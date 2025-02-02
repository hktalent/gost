package main

import (
	"flag"
	"github.com/ginuerzh/gost/pkg"
	"log"
	"time"

	"github.com/ginuerzh/gost"
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
	udpDirectForwardServer()
}

func udpDirectForwardServer() {
	ln, err := gost.UDPDirectForwardListener(laddr, time.Second*30)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.UDPDirectForwardHandler(
		faddr,
		/*
			gost.ChainHandlerOption(gost.NewChain(gost.Node{
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
			})),
		*/
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}
