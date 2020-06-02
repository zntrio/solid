package mtls

import (
	"crypto/x509"
	"crypto/tls"
)

func Server(ctx contxt.Context, caFile, name string) {
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{peerCert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: customPeerCertificateVerifier(caFile),
		ServerName: name,
	},
}

// -----------------------------------------------------------------------------
func loadCerts(caFile string) (*x509.CertPool, error) {
	// load ca cert.
	caCertPool := x509.NewCertPool()
	// load public root cert.
	publicCerts, err := ioutil.ReadFile(publicCACertsFile)
	if err != nil {
		log.Warnf("cannot load public root cert: %v", err)
	} else {
		caCertPool.AppendCertsFromPEM(publicCerts)
	}

	// load ca provided by file, such as istio CA certs.
	if caFile != "" {
		caCerts, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(caCerts)
	}
	return caCertPool, nil
}

func customPeerCertificateVerifier(serverName string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		chains := verifiedChains

		// Extract given certificate chain
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			// Parse the x.509 certificate
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return fmt.Errorf("unable to parse certificate from server: %w", err)
			}

			// Assign certificate
			certs[i] = cert
		}

		// Validation options
		opts := x509.VerifyOptions{
			Roots: rootCAs,
			CurrentTime: time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		return nil
	}
}
