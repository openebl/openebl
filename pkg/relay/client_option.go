package relay

import "crypto/tls"

func NostrClientWithServerURL(serverUrl string) NostrClientOption {
	return func(c *NostrClient) {
		c.serverURL = serverUrl
	}
}

func NostrClientWithEventSink(sink EventSink) NostrClientOption {
	return func(c *NostrClient) {
		c.eventSink = sink
	}
}

func NostrClientWithTLSConfig(tlsConfig *tls.Config) NostrClientOption {
	return func(c *NostrClient) {
		c.tlsConfig = tlsConfig
	}
}

func NostrClientWithConnectionStatusCallback(callback ClientConnectionStatusCallback) NostrClientOption {
	return func(c *NostrClient) {
		c.connectionStatusCallback = callback
	}
}
