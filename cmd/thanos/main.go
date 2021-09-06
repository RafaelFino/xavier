package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger
var hostname string

func main() {
	hostname, _ = os.Hostname()
	logger = logrus.New()
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logger.Level = logrus.DebugLevel
	logger.SetFormatter(customFormatter)

	fmt.Println("Half of all life, will die...")
	fmt.Scanln()
}
