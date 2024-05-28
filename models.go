package go_mtr

import (
	"time"

	"golang.org/x/sys/unix"
)

type Config struct {
	ICMP            bool
	TCP             bool
	UDP             bool
	MaxUnReply      int
	NextHopWait     time.Duration
	RcvGoroutineNum int
	ErrCh           chan error
	BatchSize       int
}

type Trace struct {
	IsIpv4      bool
	SrcAddr     string
	DstAddr     string
	SrcSockAddr unix.Sockaddr
	DstSockAddr unix.Sockaddr
	SrcPort     uint16
	DstPort     uint16
	MaxTTL      uint8
	Retry       int
}

type TraceRes struct {
	SrcTTL     string
	Latency    time.Duration
	TTL        uint8
	Reached    bool
	PacketLoss float32
}
