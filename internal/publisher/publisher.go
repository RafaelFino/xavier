package publisher

import (
	"time"

	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-watcher"
	"github.com/RafaelFino/xavier/internal/storage"
	"github.com/sirupsen/logrus"
)

type DataPublisher struct {
	logger       *logrus.Logger
	interval     int64
	processQueue chan []*pw.ProcessInfo
	dnsMsgsQueue chan *sniffer.DnsMsg
	endSignal    chan bool
	db           *storage.Storage
}

func New(logger *logrus.Logger) *DataPublisher {
	ret := &DataPublisher{
		logger:       logger,
		processQueue: make(chan []*pw.ProcessInfo),
		dnsMsgsQueue: make(chan *sniffer.DnsMsg),
		endSignal:    make(chan bool),
	}

	go ret.start()

	return ret
}

func (d *DataPublisher) ReceiveProcesses(processes []*pw.ProcessInfo) {
	d.processQueue <- processes
}

func (d *DataPublisher) ReceiveDNSMessage(msg *sniffer.DnsMsg) {
	d.dnsMsgsQueue <- msg
}

func (d *DataPublisher) start() {
	loggerContext := d.logger.WithField("Source", "Data-Publisher")
	d.db = storage.New(d.logger)

	for {
		select {
		case <-d.endSignal:
			loggerContext.Infof("Stop requested")
			return
		case dnsMsg := <-d.dnsMsgsQueue:
			loggerContext.WithField("Type", "DnsMSg").WithField("When", dnsMsg.Timestamp.Format("2006-01-02 15:04:05.000")).Debugf("[%s:%s] %s: %s", dnsMsg.Hostname, dnsMsg.Device, dnsMsg.Message, dnsMsg.Query)
			d.db.WriteDnsMessage(dnsMsg)
		case processes := <-d.processQueue:
			loggerContext.WithField("Type", "ProcessInfo").WithField("When", time.Now()).Debugf("Process count: %d", len(processes))
			d.db.WriteProcessEntry(processes)
		}
	}
}

func (d *DataPublisher) Stop() {
	d.endSignal <- true
}
