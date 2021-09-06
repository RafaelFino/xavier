package datawriter

import (
	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-watcher"
	"github.com/sirupsen/logrus"
)

type DataWriter struct {
	logger       *logrus.Entry
	interval     int64
	processQueue chan *pw.ProcessInfo
	dnsMsgsQueue chan *sniffer.DnsMsg
	endSignal    chan bool
}

func New(logger *logrus.Logger) *DataWriter {
	ret := &DataWriter{
		logger:       logger.WithField("Source", "Ozymandias"),
		processQueue: make(chan *pw.ProcessInfo),
		dnsMsgsQueue: make(chan *sniffer.DnsMsg),
		endSignal:    make(chan bool),
	}

	go ret.start()

	return ret
}

func (d *DataWriter) ReceiveProcesses(processes []*pw.ProcessInfo) {
	for _, p := range processes {
		d.processQueue <- p
	}
}

func (d *DataWriter) ReceiveDNSMessage(msg *sniffer.DnsMsg) {
	d.dnsMsgsQueue <- msg
}

func (d *DataWriter) start() {
	for {
		select {
		case <-d.endSignal:
			d.logger.Infof("Stop requested")
			return
		case dnsMsg := <-d.dnsMsgsQueue:
			d.logger.WithField("Type", "DnsMSg").WithField("When", dnsMsg.Timestamp.Format("2006-01-02 15:04:05.000")).Infof("[%s:%s] %s: %s", dnsMsg.Hostname, dnsMsg.Device, dnsMsg.Message, dnsMsg.Query)
		case process := <-d.processQueue:
			d.logger.WithField("Type", "ProcessInfo").WithField("When", process.Timestamp.Format("2006-01-02 15:04:05.000")).Infof("Process Pid: %d\t\tPpid: %d\t\tExecutable: %s", process.Pid, process.PPid, process.Executable)
		}
	}
}

func (d *DataWriter) Stop() {
	d.endSignal <- true
}
