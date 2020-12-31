package shadowsocks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/imgk/caddy-shadowsocks-tls/outline"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	Server    string   `json:"server,omitempty"`
	ShadowBox string   `json:"shadowbox,omitempty"`
	Users     []string `json:"users,omitempty"`

	logger *zap.Logger
	mu     sync.RWMutex
	users  map[string]struct{}
	last   time.Time
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.shadowsocks_tls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Handler) Provision(ctx caddy.Context) (err error) {
	m.logger = ctx.Logger(m)
	m.users = make(map[string]struct{})

	prefix := os.Getenv("SB_API_PREFIX")
	port := os.Getenv("SB_API_PORT")
	if prefix != "" && port != "" && m.ShadowBox == "" {
		m.ShadowBox = "https://127.0.0.1:" + port + "/" + prefix
		m.logger.Info(fmt.Sprintf("add shadowbox server: %v", m.ShadowBox))
	}

	server, err := outline.NewOutlineServer(m.ShadowBox)
	if err != nil {
		return
	}
	if m.Server == "" {
		m.Server = "127.0.0.1:" + strconv.Itoa(server.PortForNewAccessKeys)
	}

	m.logger.Info("add user from shadowbox server")
	for _, user := range server.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user.Password))
		sum := sha256.Sum224([]byte(user.Password))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	m.last = time.Now()

	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user))
		sum := sha256.Sum224([]byte(user))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	return
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	if r.Method != http.MethodConnect {
		return next.ServeHTTP(w, r)
	}
	if !m.authenticate(r) {
		return next.ServeHTTP(w, r)
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		err = errors.New("http hijacker error")
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n := rw.Reader.Buffered(); n > 0 {
		b := make([]byte, n)
		if _, err := io.ReadFull(rw, b); err != nil {
			panic("io.ReadFull error")
		}
		conn = &Conn{Conn: conn, Reader: bytes.NewReader(b)}
	} else {
		conn = &Conn{Conn: conn}
	}

	switch r.Host {
	case "tcp.imgk.cc":
		m.logger.Info(fmt.Sprintf("handle tcp connection from %v", conn.RemoteAddr()))
		err = HandleTCP(conn.(*Conn), m.Server)
		if err != nil {
			err = fmt.Errorf("handle tcp error: %v", err)
		}
	case "udp.imgk.cc":
		m.logger.Info(fmt.Sprintf("handle udp connection from %v", conn.RemoteAddr()))
		err = HandleUDP(conn.(*Conn), m.Server)
		if err != nil {
			err = fmt.Errorf("handle udp error: %v", err)
		}
	default:
		err = errors.New("common http CONNECT is not supported")
	}

	return
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

var AuthLen = len(fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(make([]byte, 28))))))

func (m *Handler) authenticate(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	m.mu.RLock()
	_, ok := m.users[auth]
	m.mu.RUnlock()

	if ok {
		return true
	}
	if AuthLen != len(auth) || m.ShadowBox == "" {
		return false
	}

	m.mu.Lock()
	if _, ok = m.users[auth]; ok {
		m.mu.Unlock()
		return true
	}
	if time.Now().Sub(m.last) < time.Second {
		m.mu.Unlock()
		return false
	}

	server, err := outline.NewOutlineServer(m.ShadowBox)
	if err != nil {
		m.logger.Error(fmt.Sprintf("connect shadowbox error: %v", err))
		return false
	}

	for k, _ := range m.users {
		delete(m.users, k)
	}
	for _, user := range server.Users {
		m.logger.Info(fmt.Sprintf("add new user: ", user.Password))
		sum := sha256.Sum224([]byte(user.Password))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: ", user))
		sum := sha256.Sum224([]byte(user))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	m.last = time.Now()
	m.mu.Unlock()

	m.mu.RLock()
	_, ok = m.users[auth]
	m.mu.RUnlock()
	return ok
}

var response = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

type Conn struct {
	net.Conn
	Reader io.Reader
	Writer io.Writer
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if errors.Is(err, io.EOF) {
		err = nil
		c.Reader = nil
	}
	return n, err
}

func (c *Conn) CloseRead() error {
	if closer, ok := c.Conn.(CloseReader); ok {
		return closer.CloseRead()
	}
	return c.Conn.Close()
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.Writer == nil {
		if _, err := c.Conn.Write(response); err != nil {
			return 0, err
		}
		c.Writer = c.Conn
	}
	return c.Writer.Write(b)
}

func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

func HandleTCP(conn *Conn, addr string) error {
	defer conn.Close()

	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	rc, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(chan error) {
		_, err := io.Copy(rc, conn)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			rc.CloseWrite()
			conn.CloseRead()
			errCh <- nil
			return
		}
		rc.SetReadDeadline(time.Now())
		conn.SetWriteDeadline(time.Now())
		errCh <- err
	}(errCh)

	_, err = io.Copy(conn, rc)
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		conn.CloseWrite()
		rc.CloseRead()
		return <-errCh
	}
	conn.SetReadDeadline(time.Now())
	rc.SetWriteDeadline(time.Now())
	<-errCh

	return err
}

func HandleUDP(conn *Conn, addr string) error {
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	rc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(chan error) (err error) {
		defer func() {
			if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
				errCh <- nil
				return
			}
			errCh <- err
		}()

		b := make([]byte, 16*1024)
		for {
			if _, err = io.ReadFull(conn, b[:2]); err != nil {
				break
			}
			n := int(b[0])<<8 | int(b[1])
			if _, err = io.ReadFull(conn, b[:n]); err != nil {
				break
			}
			if _, err = rc.Write(b[:n]); err != nil {
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(errCh)

	b := make([]byte, 16*1024)
	for {
		n := 0
		rc.SetReadDeadline(time.Now().Add(time.Minute))
		n, err = rc.Read(b[2:])
		if err != nil {
			break
		}
		b[0] = byte(n >> 8)
		b[1] = byte(n)
		if _, err = conn.Write(b[:2+n]); err != nil {
			break
		}
	}
	conn.SetReadDeadline(time.Now())

	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
		return <-errCh
	}
	<-errCh

	return err
}
