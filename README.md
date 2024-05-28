# Go Mtr

Go implementation of mtr.
mtr combines the functionality of the 'traceroute' and 'ping' programs in a single network diagnostic tool.

As mtr starts, it investigates the network connection between the host mtr runs on and a user-specified destination host. After it determines the address of each network hop between the machines, it sends a sequence of ICMP ECHO requests to each one to determine the quality of the link to each machine. As it does this, it prints running statistics about each machine.

## Getting started

- command use case
```
cd ./cmd
go run root.go --help
```
- code use case
```
package main

import (
	"fmt"
	"github.com/smuzoey/go-mtr"
	"time"
)

func main() {
	tracer, err := go_mtr.NewTrace(go_mtr.Config{
		ICMP:        true,
		UDP:         false,
		MaxUnReply:  8,
		NextHopWait: time.Millisecond * 200,
	})
	if err != nil {
		panic(err)
	}
	t, err := go_mtr.GetTrace(&go_mtr.Trace{
		SrcAddr: go_mtr.GetOutbondIP(),
		DstAddr: "8.8.8.8",
		SrcPort: 65533,
		DstPort: 65535,
		MaxTTL:  30,
		Retry:   2,
	})
	if err != nil {
		panic(err)
	}
	res, _ := tracer.BatchTrace([]go_mtr.Trace{*t}, 1)
	for _, r := range res {
		fmt.Println(r.Marshal())
		fmt.Println(r.MarshalAggregate())
	}
}
```