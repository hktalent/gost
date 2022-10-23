package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/ginuerzh/gost/pkg"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-log/log"
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type route struct {
	ServeNodes stringList
	ChainNodes stringList
	Retries    int
	Mark       int
	Interface  string
}

func (r *route) parseChain() (*pkg.Chain, error) {
	chain := pkg.NewChain()
	chain.Retries = r.Retries
	chain.Mark = r.Mark
	chain.Interface = r.Interface
	gid := 1 // group ID

	for _, ns := range r.ChainNodes {
		ngroup := pkg.NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base nodes
		nodes, err := parseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // node ID
		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		ngroup.SetSelector(nil,
			pkg.WithFilter(
				&pkg.FailFilter{
					MaxFails:    nodes[0].GetInt("max_fails"),
					FailTimeout: nodes[0].GetDuration("fail_timeout"),
				},
				&pkg.InvalidFilter{},
			),
			pkg.WithStrategy(pkg.NewStrategy(nodes[0].Get("strategy"))),
		)

		if cfg := nodes[0].Get("peer"); cfg != "" {
			f, err := os.Open(cfg)
			if err != nil {
				return nil, err
			}

			peerCfg := newPeerConfig()
			peerCfg.group = ngroup
			peerCfg.baseNodes = nodes
			peerCfg.Reload(f)
			f.Close()

			go pkg.PeriodReload(peerCfg, cfg)
		}

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func parseChainNode(ns string) (nodes []pkg.Node, err error) {
	node, err := pkg.ParseNode(ns)
	if err != nil {
		return
	}

	if auth := node.Get("auth"); auth != "" && node.User == nil {
		c, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, err
		}
		cs := string(c)
		s := strings.IndexByte(cs, ':')
		if s < 0 {
			node.User = url.User(cs)
		} else {
			node.User = url.UserPassword(cs[:s], cs[s+1:])
		}
	}
	if node.User == nil {
		users, err := parseUsers(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			node.User = users[0]
		}
	}

	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default server name
	}

	rootCAs, err := loadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}

	// If the argument `ca` is given, but not open `secure`, we verify the
	// certificate manually.
	if rootCAs != nil && !node.GetBool("secure") {
		tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         rootCAs,
				CurrentTime:   time.Now(),
				DNSName:       "",
				Intermediates: x509.NewCertPool(),
			}

			certs := state.PeerCertificates
			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

			_, err = certs[0].Verify(opts)
			return err
		}
	}

	if cert, err := tls.LoadX509KeyPair(node.Get("cert"), node.Get("key")); err == nil {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	wsOpts := &pkg.WSOptions{}
	wsOpts.EnableCompression = node.GetBool("compression")
	wsOpts.ReadBufferSize = node.GetInt("rbuf")
	wsOpts.WriteBufferSize = node.GetInt("wbuf")
	wsOpts.UserAgent = node.Get("agent")
	wsOpts.Path = node.Get("path")

	timeout := node.GetDuration("timeout")

	var tr pkg.Transporter
	switch node.Transport {
	case "tls":
		tr = pkg.TLSTransporter()
	case "mtls":
		tr = pkg.MTLSTransporter()
	case "ws":
		tr = pkg.WSTransporter(wsOpts)
	case "mws":
		tr = pkg.MWSTransporter(wsOpts)
	case "wss":
		tr = pkg.WSSTransporter(wsOpts)
	case "mwss":
		tr = pkg.MWSSTransporter(wsOpts)
	case "kcp":
		config, err := parseKCPConfig(node.Get("c"))
		if err != nil {
			return nil, err
		}
		if config == nil {
			conf := pkg.DefaultKCPConfig
			if node.GetBool("tcp") {
				conf.TCP = true
			}
			config = &conf
		}
		tr = pkg.KCPTransporter(config)
	case "ssh":
		if node.Protocol == "direct" || node.Protocol == "remote" {
			tr = pkg.SSHForwardTransporter()
		} else {
			tr = pkg.SSHTunnelTransporter()
		}
	case "quic":
		config := &pkg.QUICConfig{
			TLSConfig:   tlsCfg,
			KeepAlive:   node.GetBool("keepalive"),
			Timeout:     timeout,
			IdleTimeout: node.GetDuration("idle"),
		}

		if cipher := node.Get("cipher"); cipher != "" {
			sum := sha256.Sum256([]byte(cipher))
			config.Key = sum[:]
		}

		tr = pkg.QUICTransporter(config)
	case "http2":
		tr = pkg.HTTP2Transporter(tlsCfg)
	case "h2":
		tr = pkg.H2Transporter(tlsCfg, node.Get("path"))
	case "h2c":
		tr = pkg.H2CTransporter(node.Get("path"))
	case "obfs4":
		tr = pkg.Obfs4Transporter()
	case "ohttp":
		tr = pkg.ObfsHTTPTransporter()
	case "otls":
		tr = pkg.ObfsTLSTransporter()
	case "ftcp":
		tr = pkg.FakeTCPTransporter()
	case "udp":
		tr = pkg.UDPTransporter()
	default:
		tr = pkg.TCPTransporter()
	}

	var connector pkg.Connector
	switch node.Protocol {
	case "http2":
		connector = pkg.HTTP2Connector(node.User)
	case "socks", "socks5":
		connector = pkg.SOCKS5Connector(node.User)
	case "socks4":
		connector = pkg.SOCKS4Connector()
	case "socks4a":
		connector = pkg.SOCKS4AConnector()
	case "ss":
		connector = pkg.ShadowConnector(node.User)
	case "ssu":
		connector = pkg.ShadowUDPConnector(node.User)
	case "direct":
		connector = pkg.SSHDirectForwardConnector()
	case "remote":
		connector = pkg.SSHRemoteForwardConnector()
	case "forward":
		connector = pkg.ForwardConnector()
	case "sni":
		connector = pkg.SNIConnector(node.Get("host"))
	case "http":
		connector = pkg.HTTPConnector(node.User)
	case "relay":
		connector = pkg.RelayConnector(node.User)
	default:
		connector = pkg.AutoConnector(node.User)
	}

	host := node.Get("host")
	if host == "" {
		host = node.Host
	}

	node.DialOptions = append(node.DialOptions,
		pkg.TimeoutDialOption(timeout),
		pkg.HostDialOption(host),
	)

	node.ConnectOptions = []pkg.ConnectOption{
		pkg.UserAgentConnectOption(node.Get("agent")),
		pkg.NoTLSConnectOption(node.GetBool("notls")),
		pkg.NoDelayConnectOption(node.GetBool("nodelay")),
	}

	sshConfig := &pkg.SSHConfig{}
	if s := node.Get("ssh_key"); s != "" {
		key, err := pkg.ParseSSHKeyFile(s)
		if err != nil {
			return nil, err
		}
		sshConfig.Key = key
	}
	handshakeOptions := []pkg.HandshakeOption{
		pkg.AddrHandshakeOption(node.Addr),
		pkg.HostHandshakeOption(host),
		pkg.UserHandshakeOption(node.User),
		pkg.TLSConfigHandshakeOption(tlsCfg),
		pkg.IntervalHandshakeOption(node.GetDuration("ping")),
		pkg.TimeoutHandshakeOption(timeout),
		pkg.RetryHandshakeOption(node.GetInt("retry")),
		pkg.SSHConfigHandshakeOption(sshConfig),
	}

	node.Client = &pkg.Client{
		Connector:   connector,
		Transporter: tr,
	}

	node.Bypass = parseBypass(node.Get("bypass"))

	ips := parseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		nd := node.Clone()
		nd.Addr = ip
		// override the default node address
		nd.HandshakeOptions = append(handshakeOptions, pkg.AddrHandshakeOption(ip))
		// One node per IP
		nodes = append(nodes, nd)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []pkg.Node{node}
	}

	if node.Transport == "obfs4" {
		for i := range nodes {
			if err := pkg.Obfs4Init(nodes[i], false); err != nil {
				return nil, err
			}
		}
	}

	return
}

func (r *route) GenRouters() ([]router, error) {
	chain, err := r.parseChain()
	if err != nil {
		return nil, err
	}

	var rts []router

	for _, ns := range r.ServeNodes {
		node, err := pkg.ParseNode(ns)
		if err != nil {
			return nil, err
		}

		if auth := node.Get("auth"); auth != "" && node.User == nil {
			c, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				return nil, err
			}
			cs := string(c)
			s := strings.IndexByte(cs, ':')
			if s < 0 {
				node.User = url.User(cs)
			} else {
				node.User = url.UserPassword(cs[:s], cs[s+1:])
			}
		}
		authenticator, err := parseAuthenticator(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if authenticator == nil && node.User != nil {
			kvs := make(map[string]string)
			kvs[node.User.Username()], _ = node.User.Password()
			authenticator = pkg.NewLocalAuthenticator(kvs)
		}
		if node.User == nil {
			if users, _ := parseUsers(node.Get("secrets")); len(users) > 0 {
				node.User = users[0]
			}
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := tlsConfig(certFile, keyFile, node.Get("ca"))
		if err != nil && certFile != "" && keyFile != "" {
			return nil, err
		}

		wsOpts := &pkg.WSOptions{}
		wsOpts.EnableCompression = node.GetBool("compression")
		wsOpts.ReadBufferSize = node.GetInt("rbuf")
		wsOpts.WriteBufferSize = node.GetInt("wbuf")
		wsOpts.Path = node.Get("path")

		ttl := node.GetDuration("ttl")
		timeout := node.GetDuration("timeout")

		tunRoutes := parseIPRoutes(node.Get("route"))
		gw := net.ParseIP(node.Get("gw")) // default gateway
		for i := range tunRoutes {
			if tunRoutes[i].Gateway == nil {
				tunRoutes[i].Gateway = gw
			}
		}

		var ln pkg.Listener
		switch node.Transport {
		case "tls":
			ln, err = pkg.TLSListener(node.Addr, tlsCfg)
		case "mtls":
			ln, err = pkg.MTLSListener(node.Addr, tlsCfg)
		case "ws":
			ln, err = pkg.WSListener(node.Addr, wsOpts)
		case "mws":
			ln, err = pkg.MWSListener(node.Addr, wsOpts)
		case "wss":
			ln, err = pkg.WSSListener(node.Addr, tlsCfg, wsOpts)
		case "mwss":
			ln, err = pkg.MWSSListener(node.Addr, tlsCfg, wsOpts)
		case "kcp":
			config, er := parseKCPConfig(node.Get("c"))
			if er != nil {
				return nil, er
			}
			if config == nil {
				conf := pkg.DefaultKCPConfig
				if node.GetBool("tcp") {
					conf.TCP = true
				}
				config = &conf
			}
			ln, err = pkg.KCPListener(node.Addr, config)
		case "ssh":
			config := &pkg.SSHConfig{
				Authenticator: authenticator,
				TLSConfig:     tlsCfg,
			}
			if s := node.Get("ssh_key"); s != "" {
				key, err := pkg.ParseSSHKeyFile(s)
				if err != nil {
					return nil, err
				}
				config.Key = key
			}
			if s := node.Get("ssh_authorized_keys"); s != "" {
				keys, err := pkg.ParseSSHAuthorizedKeysFile(s)
				if err != nil {
					return nil, err
				}
				config.AuthorizedKeys = keys
			}
			if node.Protocol == "forward" {
				ln, err = pkg.TCPListener(node.Addr)
			} else {
				ln, err = pkg.SSHTunnelListener(node.Addr, config)
			}
		case "quic":
			config := &pkg.QUICConfig{
				TLSConfig:   tlsCfg,
				KeepAlive:   node.GetBool("keepalive"),
				Timeout:     timeout,
				IdleTimeout: node.GetDuration("idle"),
			}
			if cipher := node.Get("cipher"); cipher != "" {
				sum := sha256.Sum256([]byte(cipher))
				config.Key = sum[:]
			}

			ln, err = pkg.QUICListener(node.Addr, config)
		case "http2":
			ln, err = pkg.HTTP2Listener(node.Addr, tlsCfg)
		case "h2":
			ln, err = pkg.H2Listener(node.Addr, tlsCfg, node.Get("path"))
		case "h2c":
			ln, err = pkg.H2CListener(node.Addr, node.Get("path"))
		case "tcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			if chain.LastNode().Protocol == "forward" && chain.LastNode().Transport == "ssh" {
				chain.Nodes()[len(chain.Nodes())-1].Client.Connector = pkg.SSHDirectForwardConnector()
				chain.Nodes()[len(chain.Nodes())-1].Client.Transporter = pkg.SSHForwardTransporter()
			}
			ln, err = pkg.TCPListener(node.Addr)
		case "udp":
			ln, err = pkg.UDPListener(node.Addr, &pkg.UDPListenConfig{
				TTL:       ttl,
				Backlog:   node.GetInt("backlog"),
				QueueSize: node.GetInt("queue"),
			})
		case "rtcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			if chain.LastNode().Protocol == "forward" && chain.LastNode().Transport == "ssh" {
				chain.Nodes()[len(chain.Nodes())-1].Client.Connector = pkg.SSHRemoteForwardConnector()
				chain.Nodes()[len(chain.Nodes())-1].Client.Transporter = pkg.SSHForwardTransporter()
			}
			ln, err = pkg.TCPRemoteForwardListener(node.Addr, chain)
		case "rudp":
			ln, err = pkg.UDPRemoteForwardListener(node.Addr,
				chain,
				&pkg.UDPListenConfig{
					TTL:       ttl,
					Backlog:   node.GetInt("backlog"),
					QueueSize: node.GetInt("queue"),
				})
		case "obfs4":
			if err = pkg.Obfs4Init(node, true); err != nil {
				return nil, err
			}
			ln, err = pkg.Obfs4Listener(node.Addr)
		case "ohttp":
			ln, err = pkg.ObfsHTTPListener(node.Addr)
		case "otls":
			ln, err = pkg.ObfsTLSListener(node.Addr)
		case "tun":
			cfg := pkg.TunConfig{
				Name:    node.Get("name"),
				Addr:    node.Get("net"),
				Peer:    node.Get("peer"),
				MTU:     node.GetInt("mtu"),
				Routes:  tunRoutes,
				Gateway: node.Get("gw"),
			}
			ln, err = pkg.TunListener(cfg)
		case "tap":
			cfg := pkg.TapConfig{
				Name:    node.Get("name"),
				Addr:    node.Get("net"),
				MTU:     node.GetInt("mtu"),
				Routes:  strings.Split(node.Get("route"), ","),
				Gateway: node.Get("gw"),
			}
			ln, err = pkg.TapListener(cfg)
		case "ftcp":
			ln, err = pkg.FakeTCPListener(
				node.Addr,
				&pkg.FakeTCPListenConfig{
					TTL:       ttl,
					Backlog:   node.GetInt("backlog"),
					QueueSize: node.GetInt("queue"),
				},
			)
		case "dns":
			ln, err = pkg.DNSListener(
				node.Addr,
				&pkg.DNSOptions{
					Mode:      node.Get("mode"),
					TLSConfig: tlsCfg,
				},
			)
		case "redu", "redirectu":
			ln, err = pkg.UDPRedirectListener(node.Addr, &pkg.UDPListenConfig{
				TTL:       ttl,
				Backlog:   node.GetInt("backlog"),
				QueueSize: node.GetInt("queue"),
			})
		default:
			ln, err = pkg.TCPListener(node.Addr)
		}
		if err != nil {
			return nil, err
		}

		var handler pkg.Handler
		switch node.Protocol {
		case "http2":
			handler = pkg.HTTP2Handler()
		case "socks", "socks5":
			handler = pkg.SOCKS5Handler()
		case "socks4", "socks4a":
			handler = pkg.SOCKS4Handler()
		case "ss":
			handler = pkg.ShadowHandler()
		case "http":
			handler = pkg.HTTPHandler()
		case "tcp":
			handler = pkg.TCPDirectForwardHandler(node.Remote)
		case "rtcp":
			handler = pkg.TCPRemoteForwardHandler(node.Remote)
		case "udp":
			handler = pkg.UDPDirectForwardHandler(node.Remote)
		case "rudp":
			handler = pkg.UDPRemoteForwardHandler(node.Remote)
		case "forward":
			handler = pkg.SSHForwardHandler()
		case "red", "redirect":
			handler = pkg.TCPRedirectHandler()
		case "redu", "redirectu":
			handler = pkg.UDPRedirectHandler()
		case "ssu":
			handler = pkg.ShadowUDPHandler()
		case "sni":
			handler = pkg.SNIHandler()
		case "tun":
			handler = pkg.TunHandler()
		case "tap":
			handler = pkg.TapHandler()
		case "dns":
			handler = pkg.DNSHandler(node.Remote)
		case "relay":
			handler = pkg.RelayHandler(node.Remote)
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = pkg.TCPDirectForwardHandler(node.Remote)
			} else {
				handler = pkg.AutoHandler()
			}
		}

		var whitelist, blacklist *pkg.Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = pkg.ParsePermissions(node.Get("whitelist")); err != nil {
				return nil, err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = pkg.ParsePermissions(node.Get("blacklist")); err != nil {
				return nil, err
			}
		}

		node.Bypass = parseBypass(node.Get("bypass"))
		hosts := parseHosts(node.Get("hosts"))
		ips := parseIP(node.Get("ip"), "")

		resolver := parseResolver(node.Get("dns"))
		if resolver != nil {
			resolver.Init(
				pkg.ChainResolverOption(chain),
				pkg.TimeoutResolverOption(timeout),
				pkg.TTLResolverOption(ttl),
				pkg.PreferResolverOption(node.Get("prefer")),
				pkg.SrcIPResolverOption(net.ParseIP(node.Get("ip"))),
			)
		}

		handler.Init(
			pkg.AddrHandlerOption(ln.Addr().String()),
			pkg.ChainHandlerOption(chain),
			pkg.UsersHandlerOption(node.User),
			pkg.AuthenticatorHandlerOption(authenticator),
			pkg.TLSConfigHandlerOption(tlsCfg),
			pkg.WhitelistHandlerOption(whitelist),
			pkg.BlacklistHandlerOption(blacklist),
			pkg.StrategyHandlerOption(pkg.NewStrategy(node.Get("strategy"))),
			pkg.MaxFailsHandlerOption(node.GetInt("max_fails")),
			pkg.FailTimeoutHandlerOption(node.GetDuration("fail_timeout")),
			pkg.BypassHandlerOption(node.Bypass),
			pkg.ResolverHandlerOption(resolver),
			pkg.HostsHandlerOption(hosts),
			pkg.RetryHandlerOption(node.GetInt("retry")), // override the global retry option.
			pkg.TimeoutHandlerOption(timeout),
			pkg.ProbeResistHandlerOption(node.Get("probe_resist")),
			pkg.KnockingHandlerOption(node.Get("knock")),
			pkg.NodeHandlerOption(node),
			pkg.IPsHandlerOption(ips),
			pkg.TCPModeHandlerOption(node.GetBool("tcp")),
			pkg.IPRoutesHandlerOption(tunRoutes...),
		)

		rt := router{
			node:     node,
			server:   &pkg.Server{Listener: ln},
			handler:  handler,
			chain:    chain,
			resolver: resolver,
			hosts:    hosts,
		}
		rts = append(rts, rt)
	}

	return rts, nil
}

type router struct {
	node     pkg.Node
	server   *pkg.Server
	handler  pkg.Handler
	chain    *pkg.Chain
	resolver pkg.Resolver
	hosts    *pkg.Hosts
}

func (r *router) Serve() error {
	log.Logf("%s on %s", r.node.String(), r.server.Addr())
	return r.server.Serve(r.handler)
}

func (r *router) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}
