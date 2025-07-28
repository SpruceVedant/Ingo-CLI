package quic

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

// generateTLSConfig creates a self-signed TLS configuration for QUIC
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Errorf("rsa.GenerateKey: %w", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Errorf("x509.CreateCertificate: %w", err))
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(fmt.Errorf("tls.X509KeyPair: %w", err))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"fastshare"},
	}
}

// SendFile listens on a random UDP port, prints share links, and streams the file via QUIC.
// It accepts one connection and exits after transfer.
func SendFile(ctx context.Context, filePath string, _addr string) error {
	// Create listener with TLS
	tlsConf := generateTLSConfig()
	listener, err := quic.ListenAddr("0.0.0.0:0", tlsConf, &quic.Config{})
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	// Print share link
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return fmt.Errorf("invalid listener address: %w", err)
	}
	fmt.Printf("Share link: fs://127.0.0.1:%s\n", port)

	// Accept session
	sess, err := listener.Accept(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept session: %w", err)
	}
	defer sess.CloseWithError(0, "")

	// Open a stream for sending
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Send header: name and size
	header := fmt.Sprintf("%s\n%d\n", filepath.Base(filePath), info.Size())
	if _, err := stream.Write([]byte(header)); err != nil {
		return fmt.Errorf("failed to send header: %w", err)
	}

	// Copy file data
	if _, err := io.Copy(stream, file); err != nil {
		return fmt.Errorf("failed to send file data: %w", err)
	}

	fmt.Println("Transfer complete.")
	return nil
}

// ReceiveFile dials the share link, receives the file, and writes it to outDir.
func ReceiveFile(ctx context.Context, link string, outDir string) error {
	if !strings.HasPrefix(link, "fs://") {
		return fmt.Errorf("invalid share link: %s", link)
	}
	addr := strings.TrimPrefix(link, "fs://")

	// Dial session
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"fastshare"}}
	sess, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{})
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer sess.CloseWithError(0, "")

	// Accept stream
	stream, err := sess.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to accept stream: %w", err)
	}
	defer stream.Close()

	// Read header
	reader := bufio.NewReader(stream)
	nameLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read filename: %w", err)
	}
	sizeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read filesize: %w", err)
	}

	fileName := strings.TrimSpace(nameLine)
	size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid filesize: %w", err)
	}

	// Prepare output directory and file
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	outPath := filepath.Join(outDir, fileName)
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	// Copy file data; ignore clean QUIC shutdown
	if _, err := io.Copy(outFile, reader); err != nil {
		if !strings.Contains(err.Error(), "Application error 0x0") {
			return fmt.Errorf("failed to receive file data: %w", err)
		}
	}

	fmt.Printf("Received '%s' (%d bytes)\n", outPath, size)
	return nil
}
