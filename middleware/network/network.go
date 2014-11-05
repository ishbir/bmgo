/*
Manage network connectivity and exchange of data with other peers.
*/
package network

import (
	"code.google.com/p/go.net/proxy"
)

var dialer proxy.Dialer

/*
Initialize the dialer which will make connections to the network.
*/
func Init(proxyAddress string) {
	if proxyAddress == "" {
		dialer = proxy.Direct
	} else {
		// The err is always nil (package does it)
		dialer, _ = proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
	}
}
