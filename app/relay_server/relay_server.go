package main

import "github.com/openebl/openebl/pkg/relay/server"

func main() {
	app := server.RelayServerApp{}
	app.Run()
}
