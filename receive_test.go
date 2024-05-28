package go_mtr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func fmtICMPRcv(r *ICMPRcv) {
	fmt.Printf("%v %v %v %v %v %v %v\n", r.RcvType, r.TTLSrc, r.Src, r.Dst, r.Id, r.Seq, r.Reachable)
}

func TestReceive(t *testing.T) {
	cf := Config{}
	rcv, err := newRcvIpv4(cf)
	if err != nil {
		panic(err)
	}
	// deCon := newDeconstructIpv4(cf)
	ch, err := rcv.Receive()
	if err != nil {
		t.Error(err)
		return
	}
	for {
		select {
		case icmp := <-ch:
			// icmp, err := deCon.DeConstruct(bts)
			// if err != nil {
			// 	continue
			// }
			fmtICMPRcv(icmp)
		}
	}
}

func TestRcv(t *testing.T) {
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
	sourceIp := GetOutbondIP()
	mp := map[string]struct{}{}
	for _, n := range nodes {
		mp[fmt.Sprintf("%v-%v", sourceIp, n.Ip)] = struct{}{}
	}

	cf := Config{}
	rcv, err := newRcvIpv4(cf)
	// rcv, err := newRcvIpv4Bpf(cf)
	if err != nil {
		panic(err)
	}
	ch, err := rcv.Receive()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("total:", len(mp))
	count := 0
	for {
		select {
		case bts := <-ch:
			key := filter(bts)
			_, ok := mp[key]
			if ok {
				count++
				fmt.Println("count:", count)
			}
		}
	}
}

func filter(pkg *ICMPRcv) string {
	// if len(pkg) < 28 {
	// 	return ""
	// }
	// var src, dst string
	// controlMsgProto := pkg[20]
	// switch controlMsgProto {
	// case 11:
	// 	src = fmt.Sprintf("%v.%v.%v.%v", pkg[20+20], pkg[20+21], pkg[20+22], pkg[20+23])
	// 	dst = fmt.Sprintf("%v.%v.%v.%v", pkg[20+24], pkg[20+25], pkg[20+26], pkg[20+27])
	// case 3:
	// 	dst = fmt.Sprintf("%v.%v.%v.%v", pkg[12], pkg[13], pkg[14], pkg[15])
	// 	src = fmt.Sprintf("%v.%v.%v.%v", pkg[16], pkg[17], pkg[18], pkg[19])
	// case 0:
	// 	dst = fmt.Sprintf("%v.%v.%v.%v", pkg[12], pkg[13], pkg[14], pkg[15])
	// 	src = fmt.Sprintf("%v.%v.%v.%v", pkg[16], pkg[17], pkg[18], pkg[19])
	// default:
	// 	return ""
	// }
	return fmt.Sprintf("%v-%v", pkg.Src, pkg.Dst)
}
