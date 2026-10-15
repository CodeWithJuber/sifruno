package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// whmIngress serves ONLY the WHM API compatibility transport (/json-api/ and
// /execute/) over TLS on its own listener — the panel UI, operator session
// endpoints and all other paths stay on the loopback listener. Everything
// not under the two API prefixes answers 404.
func whmIngressMux(whm http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/json-api/", whm)
	mux.Handle("/execute/", whm)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// listenWHMIngress binds the TLS WHM ingress listener. Cert and key are
// operator-provided; there is no silent self-signed fallback (an
// unverifiable ingress would train clients to skip verification).
func listenWHMIngress(addr, certFile, keyFile string, whm http.Handler) (net.Listener, *http.Server, error) {
	if whm == nil {
		return nil, nil, errors.New("WHM ingress requires the account broker (--accounts-socket)")
	}
	if certFile == "" || keyFile == "" {
		return nil, nil, errors.New("WHM ingress requires --whm-tls-cert and --whm-tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{Addr: addr, Handler: whmIngressMux(whm), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return listener, server, nil
}
