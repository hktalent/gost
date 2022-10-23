package main

import (
	"github.com/ginuerzh/gost/pkg"
	"log"
)

func main() {
	sshRemoteForward()
}

func sshRemoteForward() {
	chain := pkg.NewChain(
		pkg.Node{
			Protocol:  "forward",
			Transport: "ssh",
			Addr:      "localhost:11222",
			Client: &pkg.Client{
				Connector:   pkg.SSHRemoteForwardConnector(),
				Transporter: pkg.SSHForwardTransporter(),
			},
		},
	)

	ln, err := pkg.TCPRemoteForwardListener(":11800", chain)
	if err != nil {
		log.Fatal(err)
	}
	h := pkg.TCPRemoteForwardHandler(
		"localhost:10000",
	)
	s := &pkg.Server{ln}
	log.Fatal(s.Serve(h))
}
