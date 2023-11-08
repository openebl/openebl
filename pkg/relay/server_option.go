package relay

func NostrServerAddress(address string) NostrServerOption {
	return func(s *NostrServer) {
		s.address = address
	}
}

func NostrServerTLS(certFile, keyFile string) NostrServerOption {
	return func(s *NostrServer) {
		s.certFile = &certFile
		s.keyFile = &keyFile
	}
}

func NostrServerWithEventSource(source EventSource) NostrServerOption {
	return func(s *NostrServer) {
		s.eventSource = source
	}
}

func NostrServerWithEventSink(sink EventSink) NostrServerOption {
	return func(s *NostrServer) {
		s.eventSink = sink
	}
}
