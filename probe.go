package go_mtr

import (
	"time"

	"golang.org/x/sys/unix"
)

type Detector interface {
	Probe(req SendProbe) error
	SteamProbe(reqCh chan *SendProbe)
	Close()
}

type detectMock struct{}

func (*detectMock) Probe(probe SendProbe) error {
	return nil
}

func (*detectMock) SteamProbe(reqCh chan *SendProbe) {}

func (*detectMock) Close() {}

type probeIpv4 struct {
	detectMock
	Config
}

type probeIpv6 struct {
	detectMock
}

func newProbeIpv6() Detector {
	return &probeIpv6{}
}

type SendProbe struct {
	Trace
	WriteTimeout time.Duration
	Msg          []byte
}

func newProbeIpv4(conf Config) Detector {
	p4 := &probeIpv4{Config: conf}
	return p4
}

func (p *probeIpv4) Close() {

}

func (p *probeIpv4) Probe(req SendProbe) error {
	return p.probe(req)
}

func (p *probeIpv4) probe(req SendProbe) error {
	var fd int
	var err error
	_ = unix.AF_INET
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return err
	}
	err = unix.Bind(fd, req.SrcSockAddr)
	if err != nil {
		return err
	}
	err = unix.Sendto(fd, req.Msg, 0, req.DstSockAddr)
	return err
}

func (p *probeIpv4) SteamProbe(reqCh chan *SendProbe) {
	var err error
	socketPool := map[string]int{}
	for r := range reqCh {
		if r == nil {
			break
		}
		sock, ok := socketPool[r.SrcAddr]
		if !ok {
			sock, err = p.sock(r)
			if err != nil {
				delete(socketPool, r.SrcAddr)
				continue
			}
			socketPool[r.SrcAddr] = sock
		}
		err = unix.Sendto(sock, r.Msg, 0, r.DstSockAddr)
		if err != nil {
			delete(socketPool, r.SrcAddr)
			continue
		}
	}
	for _, fd := range socketPool {
		unix.Close(fd)
	}
}

func (p *probeIpv4) sock(req *SendProbe) (int, error) {
	var fd int
	var err error
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return fd, err
	}
	// defer unix.Close(fd)
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return fd, err
	}
	err = unix.Bind(fd, req.SrcSockAddr)
	if err != nil {
		return fd, err
	}
	return fd, nil
}
