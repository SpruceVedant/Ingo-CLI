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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

const defaultPort = "4242"

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

// SendFile listens on the default port and sends the file once, then exits.
func SendFile(ctx context.Context, filePath string) error {
	// start QUIC listener on default port
	tlsConf := generateTLSConfig()
	listener, err := quic.ListenAddr(
		":"+defaultPort,
		tlsConf,
		&quic.Config{},
	)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	defer listener.Close()

	fmt.Printf("Serving '%s' on port %s...\n", filePath, defaultPort)

	// accept one session
	sess, err := listener.Accept(ctx)
	if err != nil {
		return fmt.Errorf("accept error: %w", err)
	}
	defer sess.CloseWithError(0, "")

	// open stream
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream error: %w", err)
	}
	defer stream.Close()

	// open file
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("file open error: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("file stat error: %w", err)
	}

	// send header
	header := fmt.Sprintf("%s\n%d\n", filepath.Base(filePath), info.Size())
	if _, err := stream.Write([]byte(header)); err != nil {
		return fmt.Errorf("header send error: %w", err)
	}

	// transfer data
	if _, err := io.Copy(stream, f); err != nil {
		return fmt.Errorf("transfer error: %w", err)
	}

	fmt.Println("Transfer complete.")
	return nil
}

// ReceiveFile connects to the default port, receives the file, and writes it to outDir.
func ReceiveFile(ctx context.Context, outDir string) error {
	// dial QUIC session
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"fastshare"}}
	sess, err := quic.DialAddr(
		ctx,
		"127.0.0.1:"+defaultPort,
		tlsConf,
		&quic.Config{},
	)
	if err != nil {
		return fmt.Errorf("dial error: %w", err)
	}
	defer sess.CloseWithError(0, "")

	// accept stream
	stream, err := sess.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept stream error: %w", err)
	}
	defer stream.Close()

	// read header
	reader := bufio.NewReader(stream)
	nameLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("filename read error: %w", err)
	}
	sizeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("filesize read error: %w", err)
	}

	fileName := strings.TrimSpace(nameLine)
	size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid filesize: %w", err)
	}

	// prepare output
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create directory error: %w", err)
	}
	outPath := filepath.Join(outDir, fileName)
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("file create error: %w", err)
	}
	defer outFile.Close()

	// receive data (ignore clean QUIC shutdown)
	if _, err := io.Copy(outFile, reader); err != nil {
		if !strings.Contains(err.Error(), "Application error 0x0") {
			return fmt.Errorf("receive error: %w", err)
		}
	}

	fmt.Printf("Received '%s' (%d bytes)\n", outPath, size)
	return nil
}
