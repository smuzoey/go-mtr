package go_mtr

import (
	"fmt"
	"testing"
	"time"
)

func TestConstructICMP(t *testing.T) {
	cf := Config{
		ICMP: false,
		TCP:  false,
		UDP:  true,
	}
	ct := newConstructIpv4(cf)
	tc, err := GetTrace(&Trace{
		SrcAddr: "10.23.228.78",
		//SrcAddr: "172.16.57.12",
		DstAddr: "172.16.57.12",
		SrcPort: 65535,
		DstPort: 65535,
		MaxTTL:  100,
		Retry:   0,
	})
	fmt.Println("dst:", tc.DstSockAddr)
	if err != nil {
		panic(err)
	}
	detector := newProbeIpv4(cf)
	for i := 0; i < 30; i++ {
		tc.MaxTTL = uint8(i + 1)
		bts, err := ct.Packet(ConstructPacket{
			Trace:   *tc,
			Id:      uint16(i + 1),
			Seq:     uint16(i + 2),
			SrcPort: 65232,
			DstPort: 65535,
		})
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Println(bts)

		time.Sleep(time.Millisecond * 300)
		for j := 0; j < 1; j++ {
			err = detector.Probe(SendProbe{
				Trace:        *tc,
				WriteTimeout: time.Second,
				Msg:          bts,
			})
			if err != nil {
				panic(err)
			}
		}
	}
}
