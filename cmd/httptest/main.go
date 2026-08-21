// Command httptest is a self-contained real HTTPS file server used as the
// transfer endpoint for wire-level loss measurements (scripts/httptest-check.sh).
//
// It is deliberately dependency-free and "real":
//   - binds to a kernel-chosen port when -addr ends in :0 (no fixed ports),
//   - generates a real random payload file when it does not exist yet,
//   - generates a real self-signed TLS certificate at startup (and writes the
//     PEM to -dir/cert.pem so a client can pin it with curl --cacert),
//   - serves the file over Go net/http (the runtime's netpoll path),
//   - prints one machine-readable line on stdout:
//     httptest addr=<host:port> port=<n> url=<scheme://host:port/file> \
//     file=<abs path> size=<bytes> sha256=<hex> cert=<abs path> h2=<bool>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	addr     = flag.String("addr", "127.0.0.1:0", "listen address; port 0 picks a free port")
	dir      = flag.String("dir", ".", "directory for the served file and generated certificate")
	fileName = flag.String("file", "a.bin", "name of the served file")
	size     = flag.String("size", "2m", "payload size when the file is missing (512k, 2m, 1g, or bytes)")
	plain    = flag.Bool("plain", false, "serve plain HTTP instead of HTTPS")
	forceH1  = flag.Bool("h1", false, "disable HTTP/2 (serve HTTP/1.1 only)")
	certFile = flag.String("cert", "", "existing PEM certificate (else a fresh self-signed one is generated)")
	keyFile  = flag.String("key", "", "existing PEM key (else a fresh one is generated)")
	sanExtra = flag.String("san", "", "extra SANs for the generated certificate, comma-separated (IP or DNS)")
)

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	last := s[len(s)-1]
	switch last {
	case 'k', 'K':
		mult = 1 << 10
	case 'm', 'M':
		mult = 1 << 20
	case 'g', 'G':
		mult = 1 << 30
	default:
		if last < '0' || last > '9' {
			return 0, fmt.Errorf("bad size %q", s)
		}
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

// ensureFile creates path with sz random bytes only when it does not exist;
// an existing file is kept untouched (the served payload is the real file).
func ensureFile(path string, sz int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	var written int64
	for written < sz {
		n := int64(len(buf))
		if sz-written < n {
			n = sz - written
		}
		if _, err := io.ReadFull(rand.Reader, buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func genCert(certPEMPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "meshlink-httptest", Organization: []string{"meshlink"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	for _, e := range strings.Split(*sanExtra, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, e)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPEMPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

type fileServer struct {
	filePath string
	name     string
	sha      string
}

func (s *fileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		fmt.Fprintf(w, "meshlink httptest\nfile: %s\nsize: %d\nsha256: %s\n",
			s.name, fileSize(s.filePath), s.sha)
		return
	}
	if r.URL.Path != "/"+s.name {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, s.filePath)
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func main() {
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "httptest:", err)
		os.Exit(1)
	}
	filePath := filepath.Join(*dir, *fileName)
	sz, err := parseSize(*size)
	if err != nil {
		fmt.Fprintln(os.Stderr, "httptest:", err)
		os.Exit(1)
	}
	if err := ensureFile(filePath, sz); err != nil {
		fmt.Fprintln(os.Stderr, "httptest:", err)
		os.Exit(1)
	}
	sha, err := sha256File(filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "httptest:", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "httptest:", err)
		os.Exit(1)
	}

	scheme := "http"
	h2 := false
	certPath := ""
	var tlsCert tls.Certificate
	if !*plain {
		scheme = "https"
		h2 = !*forceH1
		if *certFile != "" && *keyFile != "" {
			tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "httptest:", err)
				os.Exit(1)
			}
			certPath = *certFile
		} else {
			certPath = filepath.Join(*dir, "cert.pem")
			tlsCert, err = genCert(certPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "httptest:", err)
				os.Exit(1)
			}
		}
	}

	handler := &fileServer{filePath: filePath, name: *fileName, sha: sha}
	srv := &http.Server{Handler: handler}
	if !*plain {
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		if *forceH1 {
			// Empty TLSNextProto disables automatic HTTP/2 negotiation.
			srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		_ = srv.Close()
	}()

	host := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("%s://%s/%s", scheme, host, *fileName)
	fmt.Printf("httptest addr=%s port=%d url=%s file=%s size=%d sha256=%s cert=%s h2=%v\n",
		host, port, url, filePath, fileSize(filePath), sha, certPath, h2)

	var serveErr error
	if *plain {
		serveErr = srv.Serve(ln)
	} else {
		// ServeTLS with empty file paths uses the in-memory TLSConfig
		// certificates AND triggers net/http's automatic HTTP/2 setup.
		serveErr = srv.ServeTLS(ln, "", "")
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "httptest:", serveErr)
		os.Exit(1)
	}
}
