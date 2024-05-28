package go_mtr

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	ICMPEcho        = "ICMPEcho"
	ICMPTimeExceed  = "ICMPTimeExceed"
	ICMPUnreachable = "ICMPUnreachable"
)

type DeConstructor interface {
	DeConstruct(pkg []byte) (*ICMPRcv, error)
}

type deConstructMock struct{}

func (d *deConstructMock) DeConstruct(pkg []byte) (*ICMPRcv, error) {
	return nil, nil
}

type deConstructIpv6 struct {
	deConstructMock
}

func newDeconstructIpv6() DeConstructor {
	return &deConstructIpv6{}
}

type ICMPRcv struct {
	RcvType   string
	RcvAt     time.Time
	Src       string
	Dst       string
	TTLSrc    string
	Id        uint16
	TTL       uint8
	Seq       uint16
	Proto     uint8
	SrcPort   uint16
	DstPort   uint16
	Reachable bool
}

type deConstructIpv4 struct {
	deConstructMock
	Config
}

func newDeconstructIpv4(conf Config) DeConstructor {
	dc := &deConstructIpv4{Config: conf}
	return dc
}

func (dc *deConstructIpv4) DeConstruct(pkg []byte) (*ICMPRcv, error) {
	rcv := &ICMPRcv{}
	if len(pkg) < 28 {
		return nil, fmt.Errorf("uncomplete ICMP msg (%v)", pkg)
	}
	//ipHeader := &headerIpv4{
	//	vhl:      pkg[0],
	//	tos:      pkg[1],
	//	length:   binary.BigEndian.Uint16(pkg[2:4]),
	//	id:       binary.BigEndian.Uint16(pkg[4:6]),
	//	off:      binary.BigEndian.Uint16(pkg[6:8]),
	//	ttl:      pkg[8],
	//	proto:    pkg[9],
	//	checkSum: binary.BigEndian.Uint16(pkg[10:12]),
	//	src:      [4]byte{},
	//	dst:      [4]byte{},
	//}
	//_ = ipHeader
	rcv.RcvAt = time.Now()
	controlMsgProto := pkg[20]
	switch controlMsgProto {
	case 11:
		dc.rcvTtlICMP(rcv, pkg)
	case 3:
		dc.rcvUnreachableICMP(rcv, pkg)
	case 0:
		dc.rcvReplyICMP(rcv, pkg)
	default:
		return nil, fmt.Errorf("unknown icmp control msg proto (%v)", controlMsgProto)
	}
	return rcv, nil
}

func (dc *deConstructIpv4) rcvTtlICMP(rcv *ICMPRcv, bts []byte) {
	offset := 20
	rcv.RcvType = ICMPTimeExceed
	rcv.Id = binary.BigEndian.Uint16(bts[32:34])
	rcv.TTL = bts[36]
	rcv.TTLSrc = fmt.Sprintf("%v.%v.%v.%v", bts[12], bts[13], bts[14], bts[15])
	rcv.Src = fmt.Sprintf("%v.%v.%v.%v", bts[offset+20], bts[offset+21], bts[offset+22], bts[offset+23])
	rcv.Dst = fmt.Sprintf("%v.%v.%v.%v", bts[offset+24], bts[offset+25], bts[offset+26], bts[offset+27])
	proto := bts[37]
	switch proto {
	case 1:
		// icmp
		rcv.Id = binary.BigEndian.Uint16(bts[52:54])
		rcv.Seq = binary.BigEndian.Uint16(bts[54:57])
	case 17:
		// udp
		rcv.Id = binary.BigEndian.Uint16(bts[32:34])
		rcv.SrcPort = binary.BigEndian.Uint16(bts[48:50])
		rcv.DstPort = binary.BigEndian.Uint16(bts[50:52])
	}
}

func (dc *deConstructIpv4) rcvReplyICMP(rcv *ICMPRcv, bts []byte) {
	offset := 20
	rcv.RcvType = ICMPEcho
	rcv.Id = binary.BigEndian.Uint16(bts[offset+4 : offset+6])
	rcv.Seq = binary.BigEndian.Uint16(bts[offset+6 : offset+8])
	rcv.TTL = bts[offset+8]
	rcv.Dst = fmt.Sprintf("%v.%v.%v.%v", bts[12], bts[13], bts[14], bts[15])
	rcv.Src = fmt.Sprintf("%v.%v.%v.%v", bts[16], bts[17], bts[18], bts[19])
	rcv.TTLSrc = fmt.Sprintf("%v.%v.%v.%v", bts[12], bts[13], bts[14], bts[15])
	rcv.Reachable = true
}

func (dc *deConstructIpv4) rcvUnreachableICMP(rcv *ICMPRcv, bts []byte) {
	offset := 20
	rcv.RcvType = ICMPUnreachable
	rcv.TTL = bts[offset+8+8]
	rcv.Dst = fmt.Sprintf("%v.%v.%v.%v", bts[12], bts[13], bts[14], bts[15])
	rcv.Src = fmt.Sprintf("%v.%v.%v.%v", bts[16], bts[17], bts[18], bts[19])
	rcv.TTLSrc = fmt.Sprintf("%v.%v.%v.%v", bts[12], bts[13], bts[14], bts[15])
	rcv.Id = binary.BigEndian.Uint16(bts[32:34])
	rcv.SrcPort = binary.BigEndian.Uint16(bts[48:50])
	rcv.DstPort = binary.BigEndian.Uint16(bts[50:52])
	rcv.Reachable = true
}
