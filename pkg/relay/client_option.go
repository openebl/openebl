package relay

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

func NostrClientWithConnectionStatusCallback(callback ClientConnectionStatusCallback) NostrClientOption {
	return func(c *NostrClient) {
		c.connectionStatusCallback = callback
	}
}
