package gost

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-log/log"
)

var (
	// DefaultResolverTimeout is the default timeout for name resolution.
	DefaultResolverTimeout = 30 * time.Second
)

// Resolver is a name resolver for domain name.
// It contains a list of name servers.
type Resolver interface {
	// Resolve returns a slice of that host's IPv4 and IPv6 addresses.
	Resolve(host string) ([]net.IPAddr, error)
}

// NameServer is a name server.
// Currently supported protocol: TCP, UDP and TLS.
type NameServer struct {
	Addr     string
	Protocol string
	Hostname string // for TLS handshake verification
}

func (ns *NameServer) String() string {
	addr := ns.Addr
	prot := ns.Protocol
	host := ns.Hostname
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	if prot == "" {
		prot = "udp"
	}
	return fmt.Sprintf("%s/%s %s", addr, prot, host)
}

type resolver struct {
	Resolver *net.Resolver
	Servers  []NameServer
	Timeout  time.Duration
}

// NewResolver create a new Resolver with the given name servers and resolution timeout.
func NewResolver(servers []NameServer, timeout time.Duration) Resolver {
	r := &resolver{
		Servers: servers,
		Timeout: timeout,
	}
	r.init()
	return r
}

func (r *resolver) init() {
	r.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, err error) {
			for _, ns := range r.Servers {
				conn, err = r.dial(ctx, ns)
				if err == nil {
					break
				}
				log.Logf("[resolver] %s : %s", ns, err)
			}
			return
		},
	}
}

func (r *resolver) dial(ctx context.Context, ns NameServer) (net.Conn, error) {
	var d net.Dialer

	addr := ns.Addr
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	switch strings.ToLower(ns.Protocol) {
	case "tcp":
		return d.DialContext(ctx, "tcp", addr)
	case "tls":
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		return tls.Client(conn, cfg), nil
	case "udp":
		fallthrough
	default:
		return d.DialContext(ctx, "udp", addr)
	}
}

func (r *resolver) Resolve(name string) ([]net.IPAddr, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultResolverTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return r.Resolver.LookupIPAddr(ctx, name)
}

func (r *resolver) String() string {
	if r == nil {
		return ""
	}

	b := &bytes.Buffer{}
	fmt.Fprintf(b, "timeout %v\n", r.Timeout)
	for i := range r.Servers {
		fmt.Fprintln(b, r.Servers[i])
	}
	return b.String()
}
