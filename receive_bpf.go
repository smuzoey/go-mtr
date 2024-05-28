//go:build bpf
// +build bpf

package go_mtr

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	icmpV4TypeCodeMap = map[layers.ICMPv4TypeCode]string{
		layers.ICMPv4TypeDestinationUnreachable: ICMPUnreachable,
		layers.ICMPv4TypeTimeExceeded:           ICMPTimeExceed,
		layers.ICMPv4TypeEchoReply:              ICMPEcho,
		2816:                                    ICMPTimeExceed,
	}
)

type Receiver interface {
	Receive() (chan *ICMPRcv, error)
	Close()
}

type rcvMock struct{}

func (r *rcvMock) Receive() (chan *ICMPRcv, error) {
	return nil, nil
}

func (r *rcvMock) Close() {}

type rcvIpv6 struct {
	rcvMock
}

func newRcvIpv6() (Receiver, error) {
	return &rcvIpv6{}, nil
}

type rcvIpv4 struct {
	Config
	ctx       context.Context
	handle    *pcap.Handle
	pktSource *gopacket.PacketSource
	cancel    func()
}

func newRcvIpv4(conf Config) (Receiver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &rcvIpv4{
		ctx:    ctx,
		cancel: cancel,
		Config: conf,
	}
	handle, err := pcap.OpenLive("any", 128, false, pcap.BlockForever)
	if err != nil {
		return r, err
	}
	err = handle.SetBPFFilter("icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-unreach or icmp[icmptype] == icmp-timxceed")
	// err = handle.SetBPFFilter("less 48 and (icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-unreach or icmp[icmptype] == icmp-timxceed)")

	if err != nil {
		return r, err
	}
	r.handle = handle
	pktSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	pktSource.Lazy = true
	pktSource.NoCopy = true
	r.pktSource = pktSource
	return r, nil
}

func (r *rcvIpv4) Receive() (chan *ICMPRcv, error) {
	ch := make(chan *ICMPRcv, 1024)
	pktCh := r.pktSource.Packets()
	for i := 0; i < 5; i++ {
		go r.receive(pktCh, ch)
	}
	return ch, nil
}

func (r *rcvIpv4) Close() {
	// r.handle.Close()
	// r.cancel()
}

func (r *rcvIpv4) receive(chPkt chan gopacket.Packet, chRcv chan *ICMPRcv) {
	for {
		select {
		case <-r.ctx.Done():
			r.Close()
			return
		case pkt := <-chPkt:
			icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			icmpPkg := icmpLayer.(*layers.ICMPv4)

			ipv4Layer := pkt.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ipv4Pkg := ipv4Layer.(*layers.IPv4)

			rcv := &ICMPRcv{
				Id:        icmpPkg.Id,
				Seq:       icmpPkg.Seq,
				TTL:       ipv4Pkg.TTL,
				TTLSrc:    ipv4Pkg.SrcIP.String(),
				Src:       ipv4Pkg.DstIP.String(),
				Dst:       ipv4Pkg.SrcIP.String(),
				SrcPort:   0,
				DstPort:   0,
				RcvType:   icmpV4TypeCodeMap[icmpPkg.TypeCode],
				RcvAt:     time.Now(),
				Reachable: false,
			}
			if rcv.RcvType == ICMPTimeExceed {
				// src := icmpPkg.Payload[12:16]
				dst := icmpPkg.Payload[16:20]
				rcv.Dst = fmt.Sprintf("%v.%v.%v.%v", dst[0], dst[1], dst[2], dst[3])
				rcv.Id = binary.BigEndian.Uint16(icmpPkg.Payload[4:6])
				rcv.Seq = binary.BigEndian.Uint16(icmpPkg.Payload[6:8])
				proto := icmpPkg.Payload[9]
				if proto == 17 {
					rcv.SrcPort = binary.BigEndian.Uint16(icmpPkg.Payload[20:22])
					rcv.DstPort = binary.BigEndian.Uint16(icmpPkg.Payload[22:24])
				}
			}
			if rcv.RcvType == ICMPEcho || rcv.RcvType == ICMPUnreachable {
				rcv.Reachable = true
			}
			chRcv <- rcv
		}
	}
}
