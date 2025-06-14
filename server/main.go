package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	svidSocketPath     = "/var/run/secrets/spiffe.io"
	certReloadInterval = 20 * time.Minute
)

type CertificateManager struct {
	mu             sync.RWMutex
	serverCert     tls.Certificate
	trustDomainCAs *x509.CertPool
	lastLoadedTime time.Time
}

var certManager *CertificateManager

func main() {
	log.Println("Starting SPIFFE server with automatic certificate reloading...")

	var err error
	certManager, err = NewCertificateManager()
	if err != nil {
		log.Fatalf("Failed to initialize certificate manager: %v", err)
	}

	// Start the auto-reload process BEFORE starting the server
	certManager.StartAutoReload(certReloadInterval)

	// Use GetCertificate callback for dynamic certificate loading
	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      certManager.GetClientCAs(),
		MinVersion:     tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(handler),
	}

	log.Println("Server listening on https://localhost:8443")
	// Listening with ListenAndServeTLS, but since our tls.Config is already complete,
	// the paths to cert and key files can be empty.
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func NewCertificateManager() (*CertificateManager, error) {
	cm := &CertificateManager{}
	if err := cm.LoadCertificates(); err != nil {
		return nil, err
	}
	return cm, nil
}

func (cm *CertificateManager) LoadCertificates() error {
	log.Println("Loading TLS certificates...")

	serverCert, err := tls.LoadX509KeyPair(svidSocketPath+"/tls.crt", svidSocketPath+"/tls.key")
	if err != nil {
		return fmt.Errorf("unable to load server SVID: %w", err)
	}

	caBundleBytes, err := os.ReadFile(svidSocketPath + "/ca.crt")
	if err != nil {
		return fmt.Errorf("unable to load CA bundle: %w", err)
	}

	trustDomainCAs := x509.NewCertPool()
	if !trustDomainCAs.AppendCertsFromPEM(caBundleBytes) {
		return fmt.Errorf("failed to add CAs to the pool")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.serverCert = serverCert
	cm.trustDomainCAs = trustDomainCAs
	cm.lastLoadedTime = time.Now()

	log.Printf("TLS certificates successfully loaded at %s", cm.lastLoadedTime.Format(time.RFC3339))
	return nil
}

func (cm *CertificateManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return &cm.serverCert, nil
}

func (cm *CertificateManager) GetClientCAs() *x509.CertPool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.trustDomainCAs
}

func (cm *CertificateManager) StartAutoReload(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := cm.LoadCertificates(); err != nil {
				log.Printf("Error reloading certificates: %v", err)
			}
		}
	}()
	log.Printf("Certificate auto-reload started with interval of %s", interval)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}

	peerCert := r.TLS.PeerCertificates[0]
	id, err := x509svid.IDFromCert(peerCert)
	if err != nil {
		log.Printf("Error extracting client's SPIFFE ID: %v", err)
		http.Error(w, "Invalid SPIFFE identity", http.StatusUnauthorized)
		return
	}

	log.Printf("Request received from client with SPIFFE identity: %s", id.String())

	if id.String() != "spiffe://spiffe.une-tasse-de.cafe/ns/default/sa/client-spiffe" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	certManager.mu.RLock()
	lastLoaded := certManager.lastLoadedTime.Format(time.RFC3339)
	certManager.mu.RUnlock()

	fmt.Fprintf(w, "Hello %s, the server has successfully authenticated you!\n\nCertificates last loaded: %s",
		id.String(), lastLoaded)
}
