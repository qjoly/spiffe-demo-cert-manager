// client/main.go (improved web version)
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	svidSocketPath         = "/var/run/secrets/spiffe.io"
	serverAddress          = "https://spiffe-server.default.svc.cluster.local:8443"
	expectedServerSpiffeID = "spiffe://spiffe.une-tasse-de.cafe/ns/default/sa/server-spiffe"
)

func initializeSpiffeClient() (*http.Client, error) {
	log.Println("Loading TLS certificates...")
	clientSVID, err := tls.LoadX509KeyPair(svidSocketPath+"/tls.crt", svidSocketPath+"/tls.key")
	if err != nil {
		return nil, fmt.Errorf("unable to load client SVID: %w", err)
	}

	caBundleBytes, err := os.ReadFile(svidSocketPath + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("unable to load CA bundle: %w", err)
	}

	trustDomainCAs := x509.NewCertPool()
	if !trustDomainCAs.AppendCertsFromPEM(caBundleBytes) {
		return nil, errors.New("failed to add CAs to the pool")
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientSVID},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server certificate not presented")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("unable to parse server certificate: %w", err)
			}
			verifyOpts := x509.VerifyOptions{Roots: trustDomainCAs}
			if _, err := peerCert.Verify(verifyOpts); err != nil {
				return fmt.Errorf("invalid server certificate chain: %w", err)
			}
			id, err := x509svid.IDFromCert(peerCert)
			if err != nil {
				return fmt.Errorf("unable to extract SPIFFE ID: %w", err)
			}
			if id.String() != expectedServerSpiffeID {
				return fmt.Errorf("unexpected server SPIFFE ID: expected %q, got %q", expectedServerSpiffeID, id.String())
			}
			return nil
		},
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   10 * time.Second,
	}

	return client, nil
}

func main() {
	log.Println("Initializing web server...")

	log.Println("mTLS client initialized. Starting web server...")

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/ping", pingHandler)

	log.Println("Client web server listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	resultMsg := r.URL.Query().Get("result")
	errorMsg := r.URL.Query().Get("error")

	html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>SPIFFE Client</title>
			<style>
				body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; margin-top: 50px; background-color: #f4f4f9; }
				h1 { color: #333; }
				.ping-container { padding: 20px; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
				button { font-size: 1.2em; padding: 10px 20px; cursor: pointer; background-color: #007bff; color: white; border: none; border-radius: 5px; }
				button:hover { background-color: #0056b3; }
				.result-box {
					margin-top: 30px;
					padding: 20px;
					border-radius: 8px;
					min-width: 500px;
					white-space: pre-wrap; /* To preserve line breaks */
					text-align: left;
				}
				.result-box.success { border: 2px solid #28a745; background-color: #e9f7ef; }
				.result-box.error { border: 2px solid #dc3545; background-color: #f8d7da; }
			</style>
		</head>
		<body>
			<h1>SPIFFE Client Interface</h1>
			<div class="ping-container">
				<p>Click to send an mTLS request to the backend server.</p>
				<form action="/ping" method="post">
					<button type="submit">Ping backend server</button>
				</form>
			</div>
			
			{{if .Result}}
			<div class="result-box success">
				<strong>Ping successful!</strong><br><br>
				Response from backend server:<br>
				<pre>{{.Result}}</pre>
			</div>
			{{end}}

			{{if .Error}}
			<div class="result-box error">
				<strong>Ping failed!</strong><br><br>
				Error details:<br>
				<pre>{{.Error}}</pre>
			</div>
			{{end}}
		</body>
		</html>
	`

	tmpl, err := template.New("homepage").Parse(html)
	if err != nil {
		http.Error(w, "Internal template error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Result string
		Error  string
	}{
		Result: resultMsg,
		Error:  errorMsg,
	}

	tmpl.Execute(w, data)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request /ping received, reloading TLS certificates...")

	freshClient, err := initializeSpiffeClient()
	if err != nil {
		log.Printf("Failed to reload TLS certificates: %v", err)
		errorQuery := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/?error="+errorQuery, http.StatusFound)
		return
	}
	log.Printf("TLS certificates successfully reloaded, sending request to backend: %s", serverAddress)

	resp, err := freshClient.Get(serverAddress)

	// If there's an error, redirect to home with the error message
	if err != nil {
		log.Printf("Request to the backend failed: %v", err)
		errorQuery := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/?error="+errorQuery, http.StatusFound)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to read backend response: %v", err)
		errorQuery := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/?error="+errorQuery, http.StatusFound)
		return
	}

	log.Printf("Response from backend (status %d): %s", resp.StatusCode, string(body))
	resultQuery := url.QueryEscape(string(body))
	http.Redirect(w, r, "/?result="+resultQuery, http.StatusFound)
}
