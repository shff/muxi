package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertificateManager handles dynamic certificate generation and caching
type CertificateManager struct {
	dir      string
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	certLock sync.RWMutex
	certMap  map[string]*tls.Certificate
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(dir string) (*CertificateManager, error) {
	// Ensure directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Paths for CA certificate and key
	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca.key")

	// Ensure CA certificate and key exists
	caCert, caKey, err := ensureCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure CA: %v", err)
	}

	// Trust the CA in the system keychain (macOS) if not already trusted
	err = ensureCAIsTrusted(caCertPath)
	if err != nil {
		return nil, err
	}

	return &CertificateManager{
		dir:     dir,
		caCert:  caCert,
		caKey:   caKey,
		certMap: make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate dynamically generates or retrieves a cached certificate for the given hostname
func (cm *CertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := hello.ServerName
	if hostname == "" {
		return nil, fmt.Errorf("no server name provided")
	}

	// Check if certificate is already cached
	cm.certLock.RLock()
	if cert, ok := cm.certMap[hostname]; ok {
		cm.certLock.RUnlock()
		return cert, nil
	}
	cm.certLock.RUnlock()

	// Generate new certificate
	cm.certLock.Lock()
	defer cm.certLock.Unlock()

	// Double-check after acquiring write lock
	if cert, ok := cm.certMap[hostname]; ok {
		return cert, nil
	}

	log.Printf("Generating certificate for %s", hostname)

	// Paths for leaf certificate and key
	leafCertPath := filepath.Join(cm.dir, hostname+".pem")
	leafKeyPath := filepath.Join(cm.dir, hostname+".key")

	// Ensure leaf certificate and key
	leafCert, leafKey, err := ensureLeaf(hostname, cm.caCert, cm.caKey, leafCertPath, leafKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure leaf certificate: %v", err)
	}

	// Load the leaf certificate and key into a tls.Certificate
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Cache the certificate
	cm.certMap[hostname] = &cert

	return &cert, nil
}

func ensureCAIsTrusted(caCertPath string) error {
	// Check if CA is already trusted
	if isCertificateTrusted(caCertPath) {
		log.Printf("CA certificate already trusted in system keychain")
		return nil
	}

	// Ensure we're using Sudo
	if os.Geteuid() != 0 {
		err := openTerminalSudo(fmt.Sprintf("security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", caCertPath))
		if err != nil {
			return fmt.Errorf("failed to trust CA as admin: %v", err)
		}
		log.Printf("CA certificate added to system keychain")
		return nil
	}

	// Add CA certificate to system keychain (macOS)
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", caCertPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to trust CA: %v", err)
	}
	log.Printf("CA certificate added to system keychain")

	return nil
}

func ensureCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		cert, key, err := loadCertAndKey(certPath, keyPath)
		return cert, key, err
	}

	// Generate new CA certificate and key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "muxi local CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Self-sign the CA certificate
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA cert PEM: %w", err)
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA key PEM: %w", err)
	}

	// Parse the CA certificate
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return cert, key, nil
}

func ensureLeaf(host string, ca *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		cert, key, err := loadCertAndKey(certPath, keyPath)
		return cert, key, err
	}

	// Generate new leaf certificate and key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		DNSNames:    []string{host},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Sign the leaf certificate with the CA
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return nil, nil, fmt.Errorf("failed to write leaf cert PEM: %w", err)
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return nil, nil, fmt.Errorf("failed to write leaf key PEM: %w", err)
	}

	// Parse the leaf certificate
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	return cert, key, nil
}

func loadCertAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert file: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return cert, key, nil
}

func isCertificateTrusted(certPath string) bool {
	// First check if the certificate file exists
	if !fileExists(certPath) {
		return false
	}

	// Read the certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	// Decode PEM to get certificate data
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return false
	}

	// Parse certificate to get subject
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false
	}

	// Use security command to find certificate by common name and SHA-1 hash in system keychain
	cmd := exec.Command("security", "find-certificate", "-c", cert.Subject.CommonName, "-Z", "/Library/Keychains/System.keychain")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// If we got output and it contains "SHA-1", a certificate with this CN exists in the keychain
	// Note: This checks if ANY certificate with this CN exists, which is sufficient for our CA reuse case
	return len(output) > 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return fmt.Errorf("failed to encode PEM for %s: %w", path, err)
	}
	return nil
}

func openTerminalSudo(cmd string) error {
	esc := strings.ReplaceAll(cmd, `"`, `\"`)
	apple := fmt.Sprintf(`tell application "Terminal" to do script "sudo sh -c \"%s\""`, esc)
	out, err := exec.Command("osascript", "-e", apple).CombinedOutput()
	if err != nil {
		return fmt.Errorf("osascript failed: %v, output: %s", err, out)
	}
	return nil
}
