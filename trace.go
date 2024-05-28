package go_mtr

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Tracer interface {
	BatchTrace(batch []Trace, startTTL uint8) ([]*TraceResult, error)
	DebugInfo() TraceDebugInfo
}

type tracer struct {
	maxUnReply       int
	nextHopWait      time.Duration
	ipv4             *tracerIpv4
	ipv6             *tracerIpv6
	traceResChMap    *sync.Map
	filterMap        *sync.Map
	atomId           uint32
	conf             Config
	receiveGoroutine int
	errCh            chan error
	lock             *sync.Mutex
	atomSend         uint32
	atomRcv          uint32
	batchSize        int
}

type tracerIpv4 struct {
	constructor   Constructor
	deConstructor DeConstructor
	detector      Detector
	receiver      Receiver
}

type tracerIpv6 struct {
	constructor   Constructor
	deConstructor DeConstructor
	detector      Detector
	receiver      Receiver
}

type TraceResult struct {
	Id  uint16
	Key string
	Trace
	StartAt    time.Time
	Done       bool
	AvgPktLoss float32
	Res        []TraceRes
	resCh      chan *ICMPRcv
}

type TraceDebugInfo struct {
	PacketSend uint32 `json:"packet_send"`
	PacketRcv  uint32 `json:"packet_rcv"`
}

func (t TraceResult) Marshal() string {
	var line []string
	for _, r := range t.Res {
		line = append(line, fmt.Sprintf("ttl:%-4d| hop:%-16s| src:%-16s| dst:%-16s|  latency:%13v| packet_loss:%7.2f%%|  reached:%-5v",
			r.TTL,
			r.SrcTTL,
			t.SrcAddr,
			t.DstAddr,
			r.Latency.String(),
			r.PacketLoss*100,
			r.Reached,
		))
	}
	line = append(line, fmt.Sprintf("debug id:%-5d key:%-35v", t.Id, t.Key))
	line = append(line, fmt.Sprintf("pkg_loss:%.2f%%", t.AvgPktLoss*100))
	line = append(line, fmt.Sprintf("%v", time.Now()))
	if t.Done {
		line = append(line, "trace successed!")
	} else {
		line = append(line, "trace failed!")
	}
	return strings.Join(line, "\n")
}

func (t TraceResult) Aggregate() TraceResult {
	var agg []TraceRes
	var latency time.Duration
	var successed int
	var total int
	var hop string
	var reached bool
	for idx, r := range t.Res {
		latency += t.Res[idx].Latency
		total++
		if r.Latency != 0 {
			successed++
		}
		// hop = r.SrcTTL
		if r.SrcTTL != "" && hop == "" {
			hop = r.SrcTTL
		}
		if r.Reached {
			reached = true
		}
		if (idx+1 < len(t.Res) && t.Res[idx+1].TTL != r.TTL) ||
			// (idx+1 < len(t.Res) && t.Res[idx+1].SrcTTL != hop) ||
			idx == len(t.Res)-1 {
			if successed > 0 {
				t.Res[idx].Latency = latency / time.Duration(successed)
			}
			t.Res[idx].PacketLoss = float32(total-successed) / float32(total)
			t.Res[idx].SrcTTL = hop
			t.Res[idx].Reached = reached
			hop = ""
			agg = append(agg, t.Res[idx])
			successed = 0
			total = 0
			latency = 0
		}
	}
	t.Res = agg
	return t
}

func (t TraceResult) MarshalAggregate() string {
	t = t.Aggregate()
	return t.Marshal()
}

func NewTrace(conf Config) (Tracer, error) {
	ipv4, err := tracerI4(conf)
	if err != nil {
		return nil, err
	}
	ipv6, err := tracerI6(conf)
	if err != nil {
		return nil, err
	}
	tc := &tracer{
		nextHopWait:      conf.NextHopWait,
		maxUnReply:       conf.MaxUnReply,
		ipv4:             ipv4,
		ipv6:             ipv6,
		traceResChMap:    &sync.Map{},
		filterMap:        &sync.Map{},
		conf:             conf,
		receiveGoroutine: conf.RcvGoroutineNum,
		errCh:            conf.ErrCh,
		lock:             &sync.Mutex{},
		batchSize:        conf.BatchSize,
	}
	if tc.receiveGoroutine == 0 {
		tc.receiveGoroutine = 5
	}
	if tc.batchSize == 0 {
		tc.batchSize = 5000
	}
	return tc, nil
}

func tracerI4(conf Config) (*tracerIpv4, error) {
	con := newConstructIpv4(conf)
	deCon := newDeconstructIpv4(conf)
	detector := newProbeIpv4(conf)
	rcv, err := newRcvIpv4(conf)
	if err != nil {
		return nil, err
	}
	// rcv, err := newRcvIpv4(conf)
	// if err != nil {
	// 	rcv, err = newRcvIpv4(conf)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	return &tracerIpv4{
		constructor:   con,
		deConstructor: deCon,
		detector:      detector,
		receiver:      rcv,
	}, nil
}

func tracerI6(conf Config) (*tracerIpv6, error) {
	con := newConstructIpv6(conf)
	deCon := newDeconstructIpv6()
	detector := newProbeIpv6()
	rcv, err := newRcvIpv6()
	if err != nil {
		return nil, err
	}
	return &tracerIpv6{
		constructor:   con,
		deConstructor: deCon,
		detector:      detector,
		receiver:      rcv,
	}, nil
}

func (t *tracer) getAtomId() uint16 {
	n := atomic.AddUint32(&t.atomId, 1)
	return uint16(n % 65535)
}

func (t *tracer) tracerKey(id uint16, src string, srcPort uint16, dst string, dstPort uint16) string {
	if t.conf.UDP {
		key := fmt.Sprintf("%v:%v:%v-%v:%v", id, src, srcPort, dst, dstPort)
		return key
	}
	if t.conf.ICMP {
		key := fmt.Sprintf("%v:%v-%v", id, src, dst)
		return key
	}
	return fmt.Sprintf("%v:%v-%v", id, src, dst)
}

func (t *tracer) handleRcv(rcv *ICMPRcv) {
	key := t.tracerKey(rcv.Id, rcv.Src, rcv.SrcPort, rcv.Dst, rcv.DstPort)
	chI, ok := t.traceResChMap.Load(key)
	if !ok {
		Error(t.errCh, fmt.Errorf("error: drop(%v)(%v)", key, time.Now()))
		return
	}
	ch := chI.(chan *ICMPRcv)
	ch <- rcv
}

func (t *tracer) Listen() error {
	t.lock.Lock()
	chIpv4, err := t.ipv4.receiver.Receive()
	if err != nil {
		return err
	}
	chIpv6, err := t.ipv6.receiver.Receive()
	if err != nil {
		return err
	}
	for i := 0; i < t.receiveGoroutine; i++ {
		go func() {
			for {
				select {
				case msg := <-chIpv4:
					if msg == nil {
						// chan has been closed by receiver goroutine should exit
						return
					}
					if !t.ipv4Filter(msg) {
						continue
					}
					t.atomRcvAdd()
					t.handleRcv(msg)
				case msg := <-chIpv6:
					if msg == nil {
						// chan has been closed by receiver goroutine should exit
						return
					}
					t.atomRcvAdd()
					t.handleRcv(msg)
				}
			}
		}()
	}
	return nil
}

func (t *tracer) Close() {
	t.lock.Unlock()
	t.ipv4.detector.Close()
	t.ipv4.receiver.Close()
	t.ipv6.detector.Close()
	t.ipv6.receiver.Close()
}

func (t *tracer) BatchTrace(data []Trace, startTTL uint8) ([]*TraceResult, error) {
	if len(data) == 0 {
		return nil, nil
	}
	probeChV4 := make(chan *SendProbe, 1024*1024)
	probeChV6 := make(chan *SendProbe, 1024*1024)
	go t.ipv4.detector.SteamProbe(probeChV4)
	go t.ipv6.detector.SteamProbe(probeChV6)
	defer func() {
		close(probeChV4)
		close(probeChV6)
	}()
	traceResults := t.setFilterMap(data)
	err := t.Listen()
	if err != nil {
		return nil, err
	}
	defer func() {
		t.clearFilterMap()
		t.Close()
	}()
	var batch []int
	ch := make(chan int, len(batch))
	for idx, _ := range traceResults {
		batch = append(batch, idx)
		if len(batch) < t.batchSize && idx != len(data)-1 {
			continue
		}
		if len(batch) == 0 {
			continue
		}
		for _, i := range batch {
			go t.trace(startTTL, traceResults[i], ch, probeChV4, probeChV6)
		}
		count := 0
	For:
		for {
			select {
			case r := <-ch:
				if r == 0 {
					break For
				}
				// result = append(result, *r)
				count++
				if count == len(batch) {
					// close(ch)
					break For
				}
			}
		}
		batch = []int{}
	}
	close(ch)
	return traceResults, nil
}

func (t *tracer) filterKey(srcIp, dstIp string) string {
	return fmt.Sprintf("%v-%v", srcIp, dstIp)
}

func (t *tracer) setFilterMap(data []Trace) []*TraceResult {
	var results []*TraceResult
	for idx, d := range data {
		atomId := t.getAtomId()
		resCh := make(chan *ICMPRcv, 100)
		t.filterMap.Store(t.filterKey(d.SrcAddr, d.DstAddr), struct{}{})
		t.traceResChMap.Store(t.tracerKey(atomId, d.SrcAddr, d.SrcPort, d.DstAddr, d.DstPort), resCh)

		key := t.tracerKey(atomId, d.SrcAddr, d.SrcPort, d.DstAddr, d.DstPort)
		tr := TraceResult{
			Id:      atomId,
			Key:     key,
			Trace:   data[idx],
			StartAt: time.Time{},
			Done:    false,
			Res:     []TraceRes{},
			resCh:   resCh,
		}
		results = append(results, &tr)
	}

	return results
}

func (t *tracer) clearFilterMap() {
	t.filterMap = &sync.Map{}
	t.traceResChMap = &sync.Map{}
}

func (t *tracer) trace(startTTL uint8, tc *TraceResult, done chan int, probeChV4, probeChV6 chan *SendProbe) {
	var err error
	var reached bool
	ch := tc.resCh
	unReply := 0
	total := 0
	loss := 0
	for ttl := startTTL; ttl <= tc.MaxTTL; ttl++ {
		ttlWithReply := false
		for r := 0; r < tc.Retry; r++ {
			var pkg []byte
			total++
			start := time.Now()
			if tc.IsIpv4 {
				pkg, err = t.ipv4.constructor.Packet(ConstructPacket{
					Trace:   tc.Trace,
					TTL:     uint8(ttl),
					Id:      tc.Id,
					Seq:     uint16(ttl),
					SrcPort: tc.SrcPort,
					DstPort: tc.DstPort,
				})
				if err != nil {
					continue
				}
				p := SendProbe{
					Trace:        tc.Trace,
					WriteTimeout: time.Duration(1) * time.Second,
					Msg:          pkg,
				}
				probeChV4 <- &p
				t.atomSendAdd()
			} else {
				pkg, err = t.ipv6.constructor.Packet(ConstructPacket{
					Trace:   tc.Trace,
					TTL:     uint8(ttl),
					Id:      tc.Id,
					Seq:     uint16(ttl),
					SrcPort: tc.SrcPort,
					DstPort: tc.DstPort,
				})
				if err != nil {
					continue
				}
				p := SendProbe{
					Trace:        tc.Trace,
					WriteTimeout: time.Duration(1) * time.Second,
					Msg:          pkg,
				}
				probeChV6 <- &p
				t.atomSendAdd()
			}
			to := time.NewTimer(t.nextHopWait)
		For:
			for {
				select {
				case <-to.C:
					if len(ch) > 0 {
						//to = time.NewTimer(t.nextHopWait)
						Error(t.errCh, fmt.Errorf("timeout but ch len(%v)", len(ch)))
						//continue
					}
					loss++
					tc.Res = append(tc.Res, TraceRes{
						Latency:    0,
						TTL:        ttl,
						PacketLoss: 1,
					})
					break For
				case rcv := <-ch:
					ttlWithReply = true
					r := TraceRes{
						SrcTTL:  rcv.TTLSrc,
						Latency: time.Since(start),
						TTL:     ttl,
						Reached: false,
					}
					if rcv.RcvType == ICMPEcho || rcv.RcvType == ICMPUnreachable {
						r.Reached = true
						tc.Done = true
						tc.Res = append(tc.Res, r)
						tc.AvgPktLoss = float32(loss) / float32(total)
						reached = true
						break For
					}
					if r.Reached {
						tc.Done = true
						tc.Res = append(tc.Res, r)
						tc.AvgPktLoss = float32(loss) / float32(total)
						reached = true
						break For
					}
					tc.Res = append(tc.Res, r)
					break For
				}
			}
		}
		if !ttlWithReply {
			unReply++
			if unReply >= t.maxUnReply {
				tc.AvgPktLoss = float32(loss) / float32(total)
				// resCh <- tc
				done <- 1
				return
			}
		} else {
			unReply = 0
		}
		if reached {
			break
		}
	}
	if total > 0 {
		tc.AvgPktLoss = float32(loss) / float32(total)
	}
	// resCh <- tc
	done <- 1
}

func (t *tracer) atomSendAdd() {
	atomic.AddUint32(&t.atomSend, 1)
}

func (t *tracer) atomRcvAdd() {
	atomic.AddUint32(&t.atomRcv, 1)
}

func (t *tracer) pkgRcvCount() uint32 {
	return t.atomRcv
}

func (t *tracer) pkgSendCount() uint32 {
	return t.atomSend
}

func (t *tracer) DebugInfo() TraceDebugInfo {
	db := TraceDebugInfo{
		PacketSend: t.pkgSendCount(),
		PacketRcv:  t.pkgRcvCount(),
	}
	return db
}
