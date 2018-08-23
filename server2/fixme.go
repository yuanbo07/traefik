package server2

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/containous/traefik/configuration"
	"github.com/containous/traefik/log"
	traefiktls "github.com/containous/traefik/tls"
	"golang.org/x/net/http2"
)

type FixmeConfiguration struct {
	ForwardingTimeouts  *configuration.ForwardingTimeouts
	MaxIdleConnsPerHost int
	InsecureSkipVerify  bool
	RootCAs             traefiktls.RootCAs
}

type h2cTransportWrapper struct {
	*http2.Transport
}

func (t *h2cTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	return t.Transport.RoundTrip(req)
}

func createRootCACertPool(rootCAs traefiktls.RootCAs) *x509.CertPool {
	roots := x509.NewCertPool()

	for _, cert := range rootCAs {
		certContent, err := cert.Read()
		if err != nil {
			log.Error("Error while read RootCAs", err)
			continue
		}
		roots.AppendCertsFromPEM(certContent)
	}

	return roots
}

func createClientTLSConfig(entryPointName string, tlsOption *traefiktls.TLS) (*tls.Config, error) {
	if tlsOption == nil {
		return nil, errors.New("no TLS provided")
	}

	config, err := tlsOption.Certificates.CreateTLSConfig(entryPointName)
	if err != nil {
		return nil, err
	}

	if len(tlsOption.ClientCA.Files) > 0 {
		pool := x509.NewCertPool()
		for _, caFile := range tlsOption.ClientCA.Files {
			data, err := ioutil.ReadFile(caFile)
			if err != nil {
				return nil, err
			}

			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("invalid certificate(s) in %s", caFile)
			}
		}
		config.RootCAs = pool
	}

	config.BuildNameToCertificate()

	return config, nil
}

// createHTTPTransport creates an http.Transport configured with the GlobalConfiguration settings.
// For the settings that can't be configured in Traefik it uses the default http.Transport settings.
// An exception to this is the MaxIdleConns setting as we only provide the option MaxIdleConnsPerHost
// in Traefik at this point in time. Setting this value to the default of 100 could lead to confusing
// behavior and backwards compatibility issues.
func createHTTPTransport(globalConfiguration FixmeConfiguration) (*http.Transport, error) {
	dialer := &net.Dialer{
		Timeout:   configuration.DefaultDialTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	if globalConfiguration.ForwardingTimeouts != nil {
		dialer.Timeout = time.Duration(globalConfiguration.ForwardingTimeouts.DialTimeout)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConnsPerHost:   globalConfiguration.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	transport.RegisterProtocol("h2c", &h2cTransportWrapper{
		Transport: &http2.Transport{
			DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
			AllowHTTP: true,
		},
	})

	if globalConfiguration.ForwardingTimeouts != nil {
		transport.ResponseHeaderTimeout = time.Duration(globalConfiguration.ForwardingTimeouts.ResponseHeaderTimeout)
	}

	if globalConfiguration.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if len(globalConfiguration.RootCAs) > 0 {
		transport.TLSClientConfig = &tls.Config{
			RootCAs: createRootCACertPool(globalConfiguration.RootCAs),
		}
	}

	err := http2.ConfigureTransport(transport)
	if err != nil {
		return nil, err
	}

	return transport, nil
}
