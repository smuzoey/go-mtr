package main

import (
	"fmt"
	"strings"
	"time"

	go_mtr "github.com/smuzoey/go-mtr"
	"github.com/spf13/cobra"
)

var (
	root *cobra.Command
)

func init() {
	root = &cobra.Command{
		Use:   "mtr detect and route trace",
		Short: "mtr detect and route trace",
		Run:   run,
	}
	cobra.OnInitialize()
	root.PersistentFlags().StringP("source", "s", go_mtr.GetOutbondIP(), "source ip address, config which nic to send probe packet, 源IP")
	root.PersistentFlags().StringP("target", "t", "127.0.0.1", "target ip address, 目的IP")
	root.PersistentFlags().Uint16("source_port", 65533, "source port, 源端口")
	root.PersistentFlags().Uint16("target_port", 65535, "target port, 目的端口")
	root.PersistentFlags().IntP("count", "c", 1, "how many times retry on each hop, 每跳ttl重试次数")
	root.PersistentFlags().Int("max_unreply", 8, "stop detect when max unreply hop exceeded, 最大连续无回复hop次数 判断不可达")
	root.PersistentFlags().String("type", "icmp", "detect type, icmp/udp proto")
	root.PersistentFlags().Duration("timeout_per_pkt", time.Millisecond*200, "timeout per packet")
	root.PersistentFlags().Int("start_ttl", 1, "start ttl")
	root.PersistentFlags().Uint8("max_ttl", 30, "max ttl")
}

func run(cmd *cobra.Command, args []string) {
	source, _ := root.PersistentFlags().GetString("source")
	target, _ := root.PersistentFlags().GetString("target")
	sPort, _ := root.PersistentFlags().GetUint16("source_port")
	dPort, _ := root.PersistentFlags().GetUint16("target_port")
	retry, _ := root.PersistentFlags().GetInt("count")
	maxUnreply, _ := root.PersistentFlags().GetInt("max_unreply")
	tp, _ := root.PersistentFlags().GetString("type")
	to, _ := root.PersistentFlags().GetDuration("timeout_per_pkt")
	ttlStart, _ := root.PersistentFlags().GetInt("start_ttl")
	ttlMax, _ := root.PersistentFlags().GetUint8("max_ttl")
	conf := go_mtr.Config{
		MaxUnReply:  maxUnreply,
		NextHopWait: to,
	}
	tp = strings.Trim(tp, " ")
	if tp == "icmp" {
		conf.ICMP = true
	} else if tp == "udp" {
		conf.UDP = true
	} else {
		cmd.PrintErrf("invalid detect type (%v) must be udp/icmp\n", tp)
		return
	}
	tracer, err := go_mtr.NewTrace(conf)
	if err != nil {
		fmt.Printf("init trace error (%v)\n", err)
		return
	}
	go tracer.Listen()
	defer tracer.Close()
	t, err := go_mtr.GetTrace(&go_mtr.Trace{
		SrcAddr: source,
		DstAddr: target,
		SrcPort: sPort,
		DstPort: dPort,
		MaxTTL:  ttlMax,
		Retry:   retry,
	})
	fmt.Println("source:", source, "source_port:", sPort, "target:", target, "tareget_port:", dPort, "count:", retry, "max_unreply:", maxUnreply, "type:", tp, "timeout:", to, "ttl_start:", ttlStart)
	if err != nil {
		fmt.Printf("trace param error (%v)", err)
		return
	}
	res, _ := tracer.BatchTrace([]go_mtr.Trace{*t}, uint8(ttlStart))
	for _, r := range res {
		fmt.Println("================not aggregate==============")
		fmt.Println(r.Marshal())
		fmt.Println("==================aggregate================")
		fmt.Println(r.MarshalAggregate())
	}
}

func main() {
	err := root.Execute()
	if err != nil {
		panic(err)
	}
}
