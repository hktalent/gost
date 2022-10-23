package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/ginuerzh/gost/pkg"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"
)

var (
	routers []router
)

type baseConfig struct {
	route
	Routes []route
	Debug  bool
}

func parseBaseConfig(s string) (*baseConfig, error) {
	file, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(baseCfg); err != nil {
		return nil, err
	}

	return baseCfg, nil
}

var (
	defaultCertFile = "cert.pem"
	defaultKeyFile  = "key.pem"
)

// Load the certificate from cert & key files and optional client CA file,
// will use the default certificate if the provided info are invalid.
func tlsConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		certFile, keyFile = defaultCertFile, defaultKeyFile
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	if pool, _ := loadCA(caFile); pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

func loadCA(caFile string) (cp *x509.CertPool, err error) {
	if caFile == "" {
		return
	}
	cp = x509.NewCertPool()
	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !cp.AppendCertsFromPEM(data) {
		return nil, errors.New("AppendCertsFromPEM failed")
	}
	return
}

func parseKCPConfig(configFile string) (*pkg.KCPConfig, error) {
	if configFile == "" {
		return nil, nil
	}
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &pkg.KCPConfig{}
	if err = json.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

func parseUsers(authFile string) (users []*url.Userinfo, err error) {
	if authFile == "" {
		return
	}

	file, err := os.Open(authFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := strings.SplitN(line, " ", 2)
		if len(s) == 1 {
			users = append(users, url.User(strings.TrimSpace(s[0])))
		} else if len(s) == 2 {
			users = append(users, url.UserPassword(strings.TrimSpace(s[0]), strings.TrimSpace(s[1])))
		}
	}

	err = scanner.Err()
	return
}

func parseAuthenticator(s string) (pkg.Authenticator, error) {
	if s == "" {
		return nil, nil
	}
	f, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	au := pkg.NewLocalAuthenticator(nil)
	au.Reload(f)

	go pkg.PeriodReload(au, s)

	return au, nil
}

func parseIP(s string, port string) (ips []string) {
	if s == "" {
		return
	}
	if port == "" {
		port = "8080" // default port
	}

	file, err := os.Open(s)
	if err != nil {
		ss := strings.Split(s, ",")
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s != "" {
				// TODO: support IPv6
				if !strings.Contains(s, ":") {
					s = s + ":" + port
				}
				ips = append(ips, s)
			}

		}
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			line = line + ":" + port
		}
		ips = append(ips, line)
	}
	return
}

func parseBypass(s string) *pkg.Bypass {
	if s == "" {
		return nil
	}
	var matchers []pkg.Matcher
	var reversed bool
	if strings.HasPrefix(s, "~") {
		reversed = true
		s = strings.TrimLeft(s, "~")
	}

	f, err := os.Open(s)
	if err != nil {
		for _, s := range strings.Split(s, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			matchers = append(matchers, pkg.NewMatcher(s))
		}
		return pkg.NewBypass(reversed, matchers...)
	}
	defer f.Close()

	bp := pkg.NewBypass(reversed)
	bp.Reload(f)
	go pkg.PeriodReload(bp, s)

	return bp
}

func parseResolver(cfg string) pkg.Resolver {
	if cfg == "" {
		return nil
	}
	var nss []pkg.NameServer

	f, err := os.Open(cfg)
	if err != nil {
		for _, s := range strings.Split(cfg, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if strings.HasPrefix(s, "https") {
				p := "https"
				u, _ := url.Parse(s)
				if u == nil || u.Scheme == "" {
					continue
				}
				if u.Scheme == "https-chain" {
					p = u.Scheme
				}
				ns := pkg.NameServer{
					Addr:     s,
					Protocol: p,
				}
				nss = append(nss, ns)
				continue
			}

			ss := strings.Split(s, "/")
			if len(ss) == 1 {
				ns := pkg.NameServer{
					Addr: ss[0],
				}
				nss = append(nss, ns)
			}
			if len(ss) == 2 {
				ns := pkg.NameServer{
					Addr:     ss[0],
					Protocol: ss[1],
				}
				nss = append(nss, ns)
			}
		}
		return pkg.NewResolver(0, nss...)
	}
	defer f.Close()

	resolver := pkg.NewResolver(0)
	resolver.Reload(f)

	go pkg.PeriodReload(resolver, cfg)

	return resolver
}

func parseHosts(s string) *pkg.Hosts {
	f, err := os.Open(s)
	if err != nil {
		return nil
	}
	defer f.Close()

	hosts := pkg.NewHosts()
	hosts.Reload(f)

	go pkg.PeriodReload(hosts, s)

	return hosts
}

func parseIPRoutes(s string) (routes []pkg.IPRoute) {
	if s == "" {
		return
	}

	file, err := os.Open(s)
	if err != nil {
		ss := strings.Split(s, ",")
		for _, s := range ss {
			if _, inet, _ := net.ParseCIDR(strings.TrimSpace(s)); inet != nil {
				routes = append(routes, pkg.IPRoute{Dest: inet})
			}
		}
		return
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Replace(scanner.Text(), "\t", " ", -1)
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var route pkg.IPRoute
		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		if len(ss) > 0 && ss[0] != "" {
			_, route.Dest, _ = net.ParseCIDR(strings.TrimSpace(ss[0]))
			if route.Dest == nil {
				continue
			}
		}
		if len(ss) > 1 && ss[1] != "" {
			route.Gateway = net.ParseIP(ss[1])
		}
		routes = append(routes, route)
	}
	return routes
}
