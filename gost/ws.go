package gost

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"net/url"

	"github.com/go-log/log"
	"gopkg.in/gorilla/websocket.v1"
)

type WSOptions struct {
	ReadBufferSize    int
	WriteBufferSize   int
	HandshakeTimeout  time.Duration
	EnableCompression bool
	TLSConfig         *tls.Config
}

type websocketConn struct {
	conn *websocket.Conn
	rb   []byte
}

func websocketClientConn(url string, conn net.Conn, options *WSOptions) (net.Conn, error) {
	if options == nil {
		options = &WSOptions{}
	}
	dialer := websocket.Dialer{
		ReadBufferSize:    options.ReadBufferSize,
		WriteBufferSize:   options.WriteBufferSize,
		TLSClientConfig:   options.TLSConfig,
		HandshakeTimeout:  options.HandshakeTimeout,
		EnableCompression: options.EnableCompression,
		NetDial: func(net, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	c, resp, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return &websocketConn{conn: c}, nil
}

func websocketServerConn(conn *websocket.Conn) net.Conn {
	// conn.EnableWriteCompression(true)
	return &websocketConn{
		conn: conn,
	}
}

func (c *websocketConn) Read(b []byte) (n int, err error) {
	if len(c.rb) == 0 {
		_, c.rb, err = c.conn.ReadMessage()
	}
	n = copy(b, c.rb)
	c.rb = c.rb[n:]
	return
}

func (c *websocketConn) Write(b []byte) (n int, err error) {
	err = c.conn.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *websocketConn) Close() error {
	return c.conn.Close()
}

func (c *websocketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *websocketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (conn *websocketConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}
func (c *websocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type wsTransporter struct {
	addr    string
	options *WSOptions
}

func WSTransporter(addr string, opts *WSOptions) Transporter {
	return &wsTransporter{
		addr:    addr,
		options: opts,
	}
}

func (tr *wsTransporter) Network() string {
	return "tcp"
}

func (tr *wsTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	url := url.URL{Scheme: "ws", Host: tr.addr, Path: "/ws"}
	return websocketClientConn(url.String(), conn, tr.options)
}

type wssTransporter struct {
	addr    string
	options *WSOptions
}

func WSSTransporter(addr string, opts *WSOptions) Transporter {
	return &wssTransporter{
		addr:    addr,
		options: opts,
	}
}

func (tr *wssTransporter) Network() string {
	return "tcp"
}

func (tr *wssTransporter) Handshake(conn net.Conn) (net.Conn, error) {
	url := url.URL{Scheme: "wss", Host: tr.addr, Path: "/ws"}
	return websocketClientConn(url.String(), conn, tr.options)
}

type wsListener struct {
	addr     net.Addr
	upgrader *websocket.Upgrader
	srv      *http.Server
	connChan chan net.Conn
	errChan  chan error
}

func WSListener(addr string, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &wsListener{
		addr: tcpAddr,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:    options.ReadBufferSize,
			WriteBufferSize:   options.WriteBufferSize,
			CheckOrigin:       func(r *http.Request) bool { return true },
			EnableCompression: options.EnableCompression,
		},
		connChan: make(chan net.Conn, 32),
		errChan:  make(chan error, 1),
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{Addr: addr, Handler: mux}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		err := l.srv.Serve(tcpKeepAliveListener{ln})
		if err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()
	select {
	case err := <-l.errChan:
		return nil, err
	default:
	}

	return l, nil
}

func (l *wsListener) upgrade(w http.ResponseWriter, r *http.Request) {
	log.Logf("[ws] %s -> %s", r.RemoteAddr, l.addr)
	if Debug {
		dump, _ := httputil.DumpRequest(r, false)
		log.Log(string(dump))
	}
	conn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Logf("[ws] %s - %s : %s", r.RemoteAddr, l.addr, err)
		return
	}
	l.connChan <- websocketServerConn(conn)
}

func (l *wsListener) Accept() (conn net.Conn, err error) {
	select {
	case conn = <-l.connChan:
	case err = <-l.errChan:
	}
	return
}

func (l *wsListener) Close() error {
	return l.srv.Close()
}

func (l *wsListener) Addr() net.Addr {
	return l.addr
}

type wssListener struct {
	*wsListener
}

func WSSListener(addr string, options *WSOptions) (Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	if options == nil {
		options = &WSOptions{}
	}
	l := &wssListener{
		wsListener: &wsListener{
			addr: tcpAddr,
			upgrader: &websocket.Upgrader{
				ReadBufferSize:    options.ReadBufferSize,
				WriteBufferSize:   options.WriteBufferSize,
				CheckOrigin:       func(r *http.Request) bool { return true },
				EnableCompression: options.EnableCompression,
			},
			connChan: make(chan net.Conn, 32),
			errChan:  make(chan error, 1),
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", http.HandlerFunc(l.upgrade))
	l.srv = &http.Server{
		Addr:      addr,
		TLSConfig: options.TLSConfig,
		Handler:   mux,
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		err := l.srv.Serve(tls.NewListener(tcpKeepAliveListener{ln}, options.TLSConfig))
		if err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()
	select {
	case err := <-l.errChan:
		return nil, err
	default:
	}

	return l, nil
}
