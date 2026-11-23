package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// IngestTLSConfig builds the TLS configuration of the Lumberjack listener from
// the [live] keys tlsCert, tlsKey and tlsClientCA. It returns nil when none of
// them is set (plain TCP).
//
// tlsCert + tlsKey (PEM files) make the listener speak TLS, which encrypts the
// log stream but still accepts any client. tlsClientCA (a PEM bundle) adds
// mutual TLS: only clients presenting a certificate signed by one of those CAs
// are served. That is the only form of authentication the port has - without
// it, whoever can reach the port can inject log events.
//
// The files are read once at startup; rotating a certificate needs a restart.
func (c *Config) IngestTLSConfig() (*tls.Config, error) {
	if c.Live == nil {
		return nil, nil
	}
	certFile, keyFile, caFile := c.Live.TLSCert, c.Live.TLSKey, c.Live.TLSClientCA
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		if caFile != "" && certFile == "" && keyFile == "" {
			return nil, errors.New("tlsClientCA needs tlsCert and tlsKey (the listener's own certificate)")
		}
		return nil, errors.New("tlsCert and tlsKey must be set together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading tlsCert/tlsKey: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading tlsClientCA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tlsClientCA %s contains no PEM certificate", quoteCapped(caFile))
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
