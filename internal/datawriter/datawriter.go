package datawriter

import (
	"github.com/RafaelFino/xavier/internal/sniffer"
	"github.com/RafaelFino/xavier/internal/watcher"
	"github.com/sirupsen/logrus"
)

type DataWriter struct {
	logger       *logrus.Entry
	interval     int64
	processQueue chan *watcher.ProcessInfo
	dnsMsgsQueue chan *sniffer.DnsMsg
	endSignal    chan bool
}

func New(logger *logrus.Logger) *DataWriter {
	ret := &DataWriter{
		logger:       logger.WithField("Source", "Ozymandias"),
		processQueue: make(chan *watcher.ProcessInfo),
		dnsMsgsQueue: make(chan *sniffer.DnsMsg),
		endSignal:    make(chan bool),
	}

	go ret.start()

	return ret
}

func (d *DataWriter) ReceiveProcesses(processes []*watcher.ProcessInfo) {
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
			d.logger.WithField("Type", "DnsMSg").Infof("[%s] [%s:%s] %s: %s", dnsMsg.Timestamp.Format("2006-01-02 15:04:05.000"), dnsMsg.Hostname, dnsMsg.Device, dnsMsg.Message, dnsMsg.Query)
		case process := <-d.processQueue:
			d.logger.WithField("Type", "ProcessInfo").Infof("[%s] Process Pid: %d\t\tPpid: %d\t\tExecutable: %s", process.Timestamp.Format("2006-01-02 15:04:05.000"), process.Pid, process.PPid, process.Executable)
		}
	}
}

func (d *DataWriter) Stop() {
	d.endSignal <- true
}
