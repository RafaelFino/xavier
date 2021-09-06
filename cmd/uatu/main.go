package main

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/RafaelFino/xavier/internal/datawriter"
	"github.com/RafaelFino/xavier/internal/sniffer"
	"github.com/RafaelFino/xavier/internal/watcher"
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
	w := watcher.New(logger, ozymandias.ReceiveProcesses)

	fmt.Scanln()

	s.Stop()
	w.Stop()
	ozymandias.Stop()
}
