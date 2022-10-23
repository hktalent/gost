package main

import (
	"github.com/ginuerzh/gost/pkg"
	"log"
)

func main() {
	tcpForward()
}

func tcpForward() {
	chain := pkg.NewChain(
		pkg.Node{
			Addr: "localhost:11222",
			Client: &pkg.Client{
				Connector:   pkg.SSHDirectForwardConnector(),
				Transporter: pkg.SSHForwardTransporter(),
			},
		},
	)

	ln, err := pkg.TCPListener(":11800")
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.TCPDirectForwardHandler(
		"localhost:22",
		pkg.ChainHandlerOption(chain),
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}
