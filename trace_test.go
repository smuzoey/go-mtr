package go_mtr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"testing"
	"time"
)

func mockTrace() []Trace {
	var data []Trace
	var dataT = []Trace{
		{
			SrcAddr: GetOutbondIP(),
			DstAddr: "8.8.8.8",
			SrcPort: 65523,
			DstPort: 65535,
			MaxTTL:  60,
			Retry:   2,
		},
	}
	for idx := range dataT {
		d, err := GetTrace(&dataT[idx])
		if err != nil {
			continue
		}
		data = append(data, *d)
	}
	return data
}

func TestTrace(t *testing.T) {
	tr, err := NewTrace(Config{
		// UDP: true,
		ICMP:        true,
		MaxUnReply:  16,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	tc, err := GetTrace(&Trace{
		SrcAddr: GetOutbondIP(),
		DstAddr: "8.8.8.8",
		SrcPort: 65523,
		DstPort: 65535,
		MaxTTL:  60,
		Retry:   2,
	})
	if err != nil {
		panic(err)
	}
	// err = tr.Listen()
	// if err != nil {
	// 	panic(err)
	// }
	// defer tr.Close()
	res, _ := tr.BatchTrace([]Trace{
		*tc,
	}, 1)
	for _, r := range res {
		fmt.Println(r.Marshal())
		fmt.Println("===================================================")
		fmt.Println(r.MarshalAggregate())
	}
}

func TestTraceBatch(t *testing.T) {
	tr, err := NewTrace(Config{
		//UDP: true,
		ICMP:        true,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 100,
	})
	if err != nil {
		panic(err)
	}
	// err = tr.Listen()
	// if err != nil {
	// 	panic(err)
	// }
	// defer tr.Close()
	wg := sync.WaitGroup{}
	batch := mockTrace()
	for i := 0; i < 1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				res, _ := tr.BatchTrace(batch, 60)
				for _, r := range res {
					fmt.Println(r.Marshal())
				}
				time.Sleep(time.Second * 2)
			}
		}()
	}
	wg.Wait()
}

type node struct {
	Ip string `json:"ip"`
}

func TestHuge(t *testing.T) {
	defer func() {
		e := recover()
		fmt.Println(">>>>>>>>>>>", e)
	}()
	var data []Trace
	errCh := make(chan error, 2048)
	go func() {
		for e := range errCh {
			fmt.Println(e)
		}
	}()
	bts, err := ioutil.ReadFile("./mock/nodes.json")
	if err != nil {
		t.Error(err)
		return
	}
	var nodes []node
	err = json.Unmarshal(bts, &nodes)
	if err != nil {
		t.Error(err)
		return
	}
	// sig := make(chan int, 2)
	// go rcv(nodes, sig)
	tr, err := NewTrace(Config{
		//UDP: true,
		ICMP:        true,
		MaxUnReply:  2,
		NextHopWait: time.Millisecond * 300,
		ErrCh:       errCh,
		BatchSize:   4000,
	})
	if err != nil {
		panic(err)
	}
	for _, n := range nodes {
		d, err := GetTrace(&Trace{
			SrcAddr: GetOutbondIP(),
			DstAddr: n.Ip,
			SrcPort: 65523,
			DstPort: 65535,
			MaxTTL:  30,
			Retry:   1,
		})
		if err != nil {
			panic(err)
		}
		data = append(data, *d)
	}
	fmt.Println("total echo:", len(data))
	result, err := tr.BatchTrace(data, 30)
	if err != nil {
		t.Error(err)
		return
	}
	var success, failed []*TraceResult
	for idx, r := range result {
		if r.Done {
			success = append(success, result[idx])
		} else {
			failed = append(failed, result[idx])
		}
	}
	fmt.Println("success:", len(success))
	fmt.Println("failed:", len(failed))
	debug := tr.DebugInfo()
	// sig <- 1
	// F:
	// for {
	// 	select {
	// 	case s := <-sig:
	// 		if s == 2{
	// 			break F
	// 		}
	// 	}
	// }
	fmt.Println("pkg send:", debug.PacketSend)
	fmt.Println("pkg rcv:", debug.PacketRcv)
	fmt.Println("pkg loss:", debug.PacketSend-debug.PacketRcv)
}
