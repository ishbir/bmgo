/*
Manage network connectivity and exchange of data with other peers.
*/
package network

import (
	"time"

	"code.google.com/p/go.net/proxy"
)

var dialer proxy.Dialer

type Peer struct {
	host        string
	port        uint16
	lastConnect time.Time
}

// Taken from defaultKnownNodes.py
var knownPeers = []Peer{
	{"23.239.9.147", 8444, time.Now()},
	{"98.218.125.214", 8444, time.Now()},
	{"192.121.170.16", 8444, time.Now()},
	{"108.61.72.12", 28444, time.Now()},
	{"158.222.211.81", 8080, time.Now()},
	{"178.62.154.250", 8444, time.Now()},
	{"178.62.155.6", 8444, time.Now()},
	{"178.62.155.8", 8444, time.Now()},
}

/*
Initialize the dialer and start bootstrapping.
*/
func Init(proxyAddress string) {
	if proxyAddress == "" {
		dialer = proxy.Direct
	} else {
		// The err is always nil (package does it)
		dialer, _ = proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
	}

	dialer.Dial("tcp", "")
}

/*

*/
