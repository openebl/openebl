package relay

import (
	"context"
	"errors"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type NostrServerOption func(s *NostrServer)

type NostrServer struct {
	httpServer *http.Server
	address    string
	certFile   *string
	keyFile    *string

	wsUpgrader websocket.Upgrader
}

type nostrClientStub struct {
}

func NewNostrServer(opts ...NostrServerOption) *NostrServer {
	server := &NostrServer{}

	for _, opt := range opts {
		opt(server)
	}

	return server
}

func (s *NostrServer) ListenAndServe() error {
	if s.httpServer != nil {
		return errors.New("server already started")
	}

	serverMux := http.NewServeMux()
	serverMux.Handle("/", s)

	s.httpServer = &http.Server{
		Addr:    s.address,
		Handler: serverMux,
	}

	if s.certFile != nil && s.keyFile != nil {
		return s.httpServer.ListenAndServeTLS(*s.certFile, *s.keyFile)
	} else if !(s.certFile == nil && s.keyFile == nil) {
		return errors.New("both certFile and keyFile must be specified")
	}

	return s.httpServer.ListenAndServe()
}

func (s *NostrServer) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return errors.New("server not started")
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}
	s.httpServer = nil
	return nil
}

func (s *NostrServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Errorf("failed to upgrade websocket: %v", err)
		return
	}
	defer c.Close()

	for {
		mt, message, err := c.ReadMessage()
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			return
		} else if err != nil {
			logrus.Errorf("failed to read message: %v", err)
			break
		}
		logrus.Debugf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			logrus.Errorf("failed to write message: %v", err)
			break
		}
	}
}
