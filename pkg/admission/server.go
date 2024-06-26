package admission

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/cnrancher/rancher-flat-network-operator/pkg/admission/webhook"
	"github.com/cnrancher/rancher-flat-network-operator/pkg/controller/wrangler"
)

type Server struct {
	address  string
	port     int
	certFile string
	keyFile  string

	wctx *wrangler.Context
}

// NewAdmissionWebhookServer creates a server for admission FlatNetworkSubnets
func NewAdmissionWebhookServer(
	address string,
	port int,
	cert string,
	key string,
	wctx *wrangler.Context,
) *Server {
	return &Server{
		address:  address,
		port:     port,
		certFile: cert,
		keyFile:  key,
		wctx:     wctx,
	}
}

func (s *Server) Run(ctx context.Context) error {
	pair, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key pair [%v] [%v]: %w",
			s.certFile, s.keyFile, err)
	}

	addr := fmt.Sprintf("%v:%v", s.address, s.port)
	handler := webhook.NewWebhookHandler(s.wctx)

	var httpServer *http.Server
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/hostname", hostnameHandler)
	http.HandleFunc("/validate", handler.ValidateHandler)
	httpServer = &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				pair,
			},
		},
	}
	if err = httpServer.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("failed to start admission web server: %w", err)
	}
	logrus.Infof("start listen flat-network admission webhook server on %v", addr)
	return nil
}
