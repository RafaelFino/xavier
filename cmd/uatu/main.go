package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"internal/sniffer"
)

var logger *logrus.Logger

func main() {
	logger = logrus.New()
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logger.SetFormatter(customFormatter)

	s := sniffer.New(logger, dnsMsg)
}

func dnsMsg(msg *sniffer.DnsSniffer) {
	logger.Infof(" UATU [%s:%s] %s: %s", msg.Hostname, msg.Device, msg.Message, msg.DnsQuery)
}