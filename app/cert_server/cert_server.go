package main

import (
	formatter "github.com/bluexlab/logrus-formatter"
	"github.com/openebl/openebl/pkg/cert_server/cli"
)

func main() {
	formatter.InitLogger()
	cli := cli.App{}
	cli.Run()
}
