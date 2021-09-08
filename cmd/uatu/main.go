package main

import (
	"fmt"

	"github.com/sirupsen/logrus"

	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-watcher"
	"github.com/RafaelFino/xavier/internal/publisher"
)

var logger *logrus.Logger

func main() {
	logger = logrus.New()
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logger.SetFormatter(customFormatter)

	p := publisher.New(logger)
	defer p.Stop()

	s := sniffer.New(logger, p.ReceiveDNSMessage)
	defer s.Stop()

	w := pw.New(logger, p.ReceiveProcesses)
	defer w.Stop()

	fmt.Scanln()
}
