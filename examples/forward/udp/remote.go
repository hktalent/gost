package main

import (
	"flag"
	"github.com/ginuerzh/gost/pkg"
	"log"
	"time"
)

var (
	laddr, faddr string
	quiet        bool
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&laddr, "L", ":18080", "listen address")
	flag.StringVar(&faddr, "F", ":8080", "forward address")
	flag.BoolVar(&quiet, "q", false, "quiet mode")
	flag.BoolVar(&pkg.Debug, "d", false, "debug mode")
	flag.Parse()

	if quiet {
		pkg.SetLogger(&pkg.NopLogger{})
	}
}
func main() {
	udpRemoteForwardServer()
}

func udpRemoteForwardServer() {
	ln, err := pkg.UDPRemoteForwardListener(
		laddr,
		/*
			gost.NewChain(gost.Node{
				Protocol:  "socks5",
				Transport: "tcp",
				Addr:      ":11080",
				User:      url.UserPassword("admin", "123456"),
				Client: &gost.Client{
					Connector: gost.SOCKS5Connector(
						url.UserPassword("admin", "123456"),
					),
					Transporter: gost.TCPTransporter(),
				},
			}),
		*/
		nil,
		time.Second*30)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.UDPRemoteForwardHandler(
		faddr,
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}
