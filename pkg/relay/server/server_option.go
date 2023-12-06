package server

import "github.com/openebl/openebl/pkg/relay/server/storage"

type ServerOption func(s *Server)

func WithStorage(storage storage.RelayServerDataStore) ServerOption {
	return func(s *Server) {
		s.dataStore = storage
	}
}

func WithLocalAddress(address string) ServerOption {
	return func(s *Server) {
		s.localAddress = address
	}
}

func WithPeers(peers []string) ServerOption {
	return func(s *Server) {
		s.otherPeers = make(map[string]*ClientCallback)
		for _, peer := range peers {
			s.otherPeers[peer] = nil
		}
	}
}
