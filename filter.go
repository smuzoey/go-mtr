package go_mtr

func (t *tracer) ipv4Filter(msg *ICMPRcv) bool {
	_, ok := t.filterMap.Load(t.filterKey(msg.Src, msg.Dst))
	return ok
}
