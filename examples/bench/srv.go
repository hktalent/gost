package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ginuerzh/gost/pkg"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ginuerzh/gost"
	"golang.org/x/net/http2"
)

var (
	quiet bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&pkg.Debug, "d", false, "debug mode")
	flag.BoolVar(&http2.VerboseLogs, "v", false, "HTTP2 verbose logs")
	flag.Parse()

	if quiet {
		pkg.SetLogger(&pkg.NopLogger{})
	}
}

func main() {
	go httpServer()
	go socks5Server()
	go tlsServer()
	go shadowServer()
	go wsServer()
	go wssServer()
	go kcpServer()
	go tcpForwardServer()
	go tcpRemoteForwardServer()
	// go rudpForwardServer()
	// go tcpRedirectServer()
	go sshTunnelServer()
	go http2Server()
	go http2TunnelServer()
	go quicServer()
	go shadowUDPServer()
	go testServer()
	select {}
}

func httpServer() {
	ln, err := pkg.TCPListener(":18080")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func socks5Server() {
	ln, err := pkg.TCPListener(":11080")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.SOCKS5Handler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
		pkg.TLSConfigHandlerOption(tlsConfig()),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func shadowServer() {
	ln, err := pkg.TCPListener(":18338")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.ShadowHandler(
		pkg.UsersHandlerOption(url.UserPassword("chacha20", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func tlsServer() {
	ln, err := pkg.TLSListener(":11443", tlsConfig())
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func wsServer() {
	ln, err := pkg.WSListener(":18000", nil)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func wssServer() {
	ln, err := pkg.WSSListener(":18443", tlsConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func kcpServer() {
	ln, err := pkg.KCPListener(":18388", nil)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler()
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func tcpForwardServer() {
	ln, err := pkg.TCPListener(":2222")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.TCPDirectForwardHandler("localhost:22")
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func tcpRemoteForwardServer() {
	ln, err := pkg.TCPRemoteForwardListener(
		":1222",
		/*
			gost.NewChain(
				gost.Node{
					Protocol:  "socks5",
					Transport: "tcp",
					Addr:      "localhost:12345",
					User:      url.UserPassword("admin", "123456"),
					Client: &gost.Client{
						Connector:   gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
						Transporter: gost.TCPTransporter(),
					},
				},
			),
		*/
		nil,
	)
	if err != nil {
		log.Fatal()
	}
	h := pkg.TCPRemoteForwardHandler(
		":22",
		//gost.AddrHandlerOption("127.0.0.1:22"),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func rudpForwardServer() {
	ln, err := pkg.UDPRemoteForwardListener(
		":10053",
		pkg.NewChain(
			pkg.Node{
				Protocol:  "socks5",
				Transport: "tcp",
				Addr:      "localhost:12345",
				User:      url.UserPassword("admin", "123456"),
				Client: &pkg.Client{
					Connector:   pkg.SOCKS5Connector(url.UserPassword("admin", "123456")),
					Transporter: pkg.TCPTransporter(),
				},
			},
		),
		30*time.Second,
	)
	if err != nil {
		log.Fatal()
	}
	h := pkg.UDPRemoteForwardHandler("localhost:53")
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func tcpRedirectServer() {
	ln, err := pkg.TCPListener(":8008")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.TCPRedirectHandler()
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func sshTunnelServer() {
	ln, err := pkg.SSHTunnelListener(":12222", &pkg.SSHConfig{TLSConfig: tlsConfig()})
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func http2Server() {
	// http2.VerboseLogs = true

	ln, err := pkg.HTTP2Listener(":1443", tlsConfig())
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTP2Handler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func http2TunnelServer() {
	ln, err := pkg.H2Listener(":8443", tlsConfig()) // HTTP2 h2 mode
	// ln, err := gost.H2CListener(":8443") // HTTP2 h2c mode
	if err != nil {
		log.Fatal(err)
	}
	// h := gost.HTTPHandler(
	// 	gost.UsersHandlerOption(url.UserPassword("admin", "123456")),
	// )
	h := pkg.SOCKS5Handler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
		pkg.TLSConfigHandlerOption(tlsConfig()),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func quicServer() {
	ln, err := pkg.QUICListener("localhost:6121", &pkg.QUICConfig{TLSConfig: tlsConfig()})
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.HTTPHandler(
		pkg.UsersHandlerOption(url.UserPassword("admin", "123456")),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

func shadowUDPServer() {
	ln, err := gost.ShadowUDPListener(":18338", url.UserPassword("chacha20", "123456"), 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	h := gost.ShadowUDPdHandler(
	/*
		gost.ChainHandlerOption(gost.NewChain(
			gost.Node{
				Protocol:  "socks5",
				Transport: "tcp",
				Addr:      "localhost:11080",
				User:      url.UserPassword("admin", "123456"),
				Client: &gost.Client{
					Connector:   gost.SOCKS5Connector(url.UserPassword("admin", "123456")),
					Transporter: gost.TCPTransporter(),
				},
			},
		)),
	*/
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}

var (
	rawCert = []byte(`-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIRAMlREhz8Miu1FQozsxbeqyMwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNzA1MTkwNTM5MDJaFw0xODA1MTkwNTM5
MDJaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCyfqvv0kDriciEAVIW6JaWYFCL9a19jj1wmAGmVGxV3kNsr01kpa6N
0EBqnrcy7WknhCt1d43CqhKtTcXgJ/J9phZVxlizb8sUB85hm+MvP0N3HCg3f0Jw
hLuMrPijS6xjyw0fKCK/p6OUYMIfo5cdqeZid2WV4Ozts5uRd6Dmy2kyBe8Zg1F4
8YJGuTWZmL2L7uZUiPY4T3q9+1iucq3vUpxymVRi1BTXnTpx+C0GS8NNgeEmevHv
482vHM5DNflAQ+mvGZvBVduq/AfirCDnt2DIZm1DcZXLrY9F3EPrlRZexmAhCDGR
LIKnMmoGicBM11Aw1fDIfJAHynk43tjPAgMBAAGjSzBJMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAAx8Lna8DcQv0bRB3L9i2+KRN
l/UhPCoFagxk1cZore4p0w+1m7OgigOoTpg5jh78DzVDhScZlgJ0bBVYp5rojeJS
cBDC9lCDcaXQfFmT5LykCAwIgw/gs+rw5Aq0y3D0m8CcqKosyZa9wnZ2cVy/+45w
emcSdboc65ueZScv38/W7aTUoVRcjyRUv0jv0zW0EPnnDlluVkeZo9spBhiTTwoj
b3zGODs6alTNIJwZIHNxxyOmfJPpVVp8BzGbMk7YBixSlZ/vbrrYV34TcSiy7J57
lNNoVWM+OwiVk1+AEZfQDwaQfef5tsIkAZBUyITkkDKRhygtwM2110dejbEsgg==
-----END CERTIFICATE-----`)
	rawKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAsn6r79JA64nIhAFSFuiWlmBQi/WtfY49cJgBplRsVd5DbK9N
ZKWujdBAap63Mu1pJ4QrdXeNwqoSrU3F4CfyfaYWVcZYs2/LFAfOYZvjLz9Ddxwo
N39CcIS7jKz4o0usY8sNHygiv6ejlGDCH6OXHanmYndlleDs7bObkXeg5stpMgXv
GYNRePGCRrk1mZi9i+7mVIj2OE96vftYrnKt71KccplUYtQU1506cfgtBkvDTYHh
Jnrx7+PNrxzOQzX5QEPprxmbwVXbqvwH4qwg57dgyGZtQ3GVy62PRdxD65UWXsZg
IQgxkSyCpzJqBonATNdQMNXwyHyQB8p5ON7YzwIDAQABAoIBAQCG4doj3Apa8z+n
IShbT1+cOyQi34A+xOIA151Hh7xmFxN0afRd/iWt3JUQ/OcLgQRZbDM7DSD+3W5H
r+G7xfQkpwFxx/T3g58+f7ehYx+GcJQWyhxJ88zNIkBnyb4KCAE5WBOOW9IGajPe
yE9pgUGMlPsXpYoKfHIOHg+NGY1pWUGBfBNR2kGrbkpZMmyy5bGa8dyrwAFBFRru
kcmmKvate8UlbRspFtd4nR/GQLTBrcDJ1k1i1Su/4BpDuDeK6LPI8ZRePGqbdcxk
TS30lsdYozuGfjZ5Zu8lSIJ//+7RjfDg8r684dpWjpalq8Quen60ZrIs01CSbfyU
k8gOzTHhAoGBAOKhp41wXveegq+WylSXFyngm4bzF4dVdTRsSbJVk7NaOx1vCU6o
/xIHoGEQyLI6wF+EaHmY89/Qu6tSV97XyBbiKeskopv5iXS/BsWTHJ1VbCA1ZLmK
HgGllEkS0xfc9AdB7b6/K7LxAAQVKP3DtN6+6pSDZh9Sv2M1j0DbhkNbAoGBAMmg
HcMfExaaeskjHqyLudtKX+znwaIoumleOGuavohR4R+Fpk8Yv8Xhb5U7Yr4gk0vY
CFmhp1WAi6QMZ/8jePlKKXl3Ney827luoKiMczp2DoYE0t0u2Kw3LfkNKfjADZ7d
JI6xPJV9/X1erwjq+4UdKqrpOf05SY4nkBMcvr6dAoGAXzisvbDJNiFTp5Mj0Abr
pJzKvBjHegVeCXi2PkfWlzUCQYu1zWcURO8PY7k5mik1SuzHONAbJ578Oy+N3AOt
/m9oTXRHHmHqbzMUFU+KZlDN7XqBp7NwiCCZ/Vn7d7tOjP4Wdl68baL07sI1RupD
xJNS3LOY5PBPmc+XMRkLgKECgYEAgBNDlJSCrZMHeAjlDTncn53I/VXiPD2e3BvL
vx6W9UT9ueZN1GSmPO6M0MDeYmOS7VSXSUhUYQ28pkJzNTC1QbWITu4YxP7anBnX
1/kPoQ0pAJzDzVharlqGy3M/PBHTFRzogfO3xkY35ZFlokaR6uayGcr42Q+w16nt
7RYPXEkCgYEA3GQYirHnGZuQ952jMvduqnpgkJiSnr0fa+94Rwa1pAhxHLFMo5s4
fqZOtqKPj2s5X1JR0VCey1ilCcaAhWeb3tXCpbYLZSbMtjtqwA6LUeGY+Xdupsjw
cfWIcOfHsIm2kP+RCxEnZf1XwiN9wyJeiUKlE0dqmx9j7F0Bm+7YDhI=
-----END RSA PRIVATE KEY-----`)
)

func tlsConfig() *tls.Config {
	cert, err := tls.X509KeyPair(rawCert, rawKey)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		PreferServerCipherSuites: true,
	}
}

func testServer() {
	s := &http.Server{
		Addr: ":18888",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "abcdefghijklmnopqrstuvwxyz")
		}),
	}
	log.Fatal(s.ListenAndServe())
}
