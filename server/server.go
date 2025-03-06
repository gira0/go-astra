package main

import (
	"crypto/tls"
	"log"

	"github.com/quic-go/quic-go"
)

func startServer() {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatal(err)
	}

	// Create a QUIC listener
	listener, err := quic.ListenAddr("localhost:4242", &tls.Config{Certificates: []tls.Certificate{cert}}, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("Server is listening on localhost:4242")

	for {
		// Accept a new session
		session, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleSession(session)
	}
}

func handleSession(session quic.Session) {
	defer session.Close()
	// Handle incoming data from the session
	// ...existing code...
}
