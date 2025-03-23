package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/smarty/cproxy/v2"
)

// logs requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received connection from %s requesting %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		log.Printf("Full URL: %s", r.URL.String())
		log.Printf("User-Agent: %s", r.UserAgent())
		next.ServeHTTP(w, r)
		log.Println("Request has been fully processed.")
	})
}

// checks if request content or path has certain words, redirects if so
func contentFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathLower := strings.ToLower(r.URL.Path)
		if strings.Contains(pathLower, "porn") || strings.Contains(pathLower, "fuck") {
			http.Redirect(w, r, "https://www.google.com", http.StatusFound)
			return
		}

		var buf bytes.Buffer
		tee := io.TeeReader(r.Body, &buf)
		bodyBytes, _ := io.ReadAll(tee)
		r.Body = io.NopCloser(&buf)
		bodyLower := strings.ToLower(string(bodyBytes))
		if strings.Contains(bodyLower, "porn") || strings.Contains(bodyLower, "fuck") {
			http.Redirect(w, r, "https://www.google.com", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	handler := cproxy.New()
	handler = contentFilterMiddleware(loggingMiddleware(handler))

	// Load certificate and key from files
	certPEM, err := os.ReadFile("/path/to/your_ca_cert.pem")
	if err != nil {
		log.Fatal("Failed to read cert file:", err)
	}
	keyPEM, err := os.ReadFile("/path/to/your_ca_key.pem")
	if err != nil {
		log.Fatal("Failed to read key file:", err)
	}

	caKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal("Failed to parse CA keys:", err)
	}

	caCert, err := x509.ParseCertificate(caKeyPair.Certificate[0])
	if err != nil {
		log.Fatal("Failed to parse CA cert:", err)
	}

	// Enable TLS interception
	handler.EnableTLS(&cproxy.TLSConfig{
		CA: &cproxy.CA{
			Cert: caCert,
			Key:  caKeyPair.PrivateKey,
		},
	})

	// Listen HTTP
	go func() {
		log.Println("Listening on HTTP :8080")
		if err := http.ListenAndServe(":8080", handler); err != nil {
			log.Fatal(err)
		}
	}()

	// Listen HTTPS with our MITM
	log.Println("Listening on HTTPS :8443")
	listener, err := tls.Listen("tcp", ":8443", &tls.Config{
		Certificates: []tls.Certificate{caKeyPair},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	server := &http.Server{Handler: handler}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
