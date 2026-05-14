package proxy

// Chain wraps base with hops in OUTER-TO-INNER order: hops[0] is the proxy
// reachable from the local host, hops[len-1] is the proxy closest to the
// final target. The returned Dialer.DialContext(target) walks hops[0],
// hops[1], … hops[n-1], and finally the innermost-wrapped layer dials target.
//
// Empty hops returns base unchanged.
func Chain(base Dialer, hops []Wrapper) Dialer {
	d := base
	for _, w := range hops {
		d = w(d)
	}
	return d
}
