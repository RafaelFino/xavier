package main

import (
	"fmt"

	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/sirupsen/logrus"

	"github.com/RafaelFino/xavier/internal/datawriter"
	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-sniffer"
)

var logger *logrus.Logger

func main() {
	logger = logrus.New()
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logger.SetFormatter(customFormatter)

	ozymandias := datawriter.New(logger)

	s := sniffer.New(logger, ozymandias.ReceiveDNSMessage)
	w := pw.New(logger, ozymandias.ReceiveProcesses)

	fmt.Scanln()

	s.Stop()
	w.Stop()
	ozymandias.Stop()
}
