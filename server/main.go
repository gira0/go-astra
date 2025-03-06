package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"./control_node"
	"./server"
)

func main() {
	// Initialize server, client, and control node
	go server.Main()
	go startClient()
	go control_node.Main()

	// Wait for interrupt signal to gracefully shutdown the application
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	// Perform any necessary cleanup here
}
