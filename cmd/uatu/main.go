package main

import (
	"github.com/sirupsen/logrus"

	"github.com/RafaelFino/xavier/internal/sniffer"
)

var logger *logrus.Logger

func main() {
	logger = logrus.New()
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logger.SetFormatter(customFormatter)

	s := sniffer.New(logger, receiveDnsMsg)

	s.Start()
}

func receiveDnsMsg(msg *sniffer.DnsMsg) {
	logger.Infof(" UATU [%s:%s] %s: %s", msg.Hostname, msg.Device, msg.Message, msg.Query)
}