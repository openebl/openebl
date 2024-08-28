package relay

import "crypto/tls"

func NostrServerAddress(address string) NostrServerOption {
	return func(s *NostrServer) {
		s.address = address
	}
}

func NostrServerTLS(tlsConfig *tls.Config) NostrServerOption {
	return func(s *NostrServer) {
		s.tlsConfig = tlsConfig
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

func NostrServerWithIdentity(identity string) NostrServerOption {
	return func(s *NostrServer) {
		s.identity = identity
	}
}
