package watcher

import (
	"time"

	"github.com/mitchellh/go-ps"
	"github.com/sirupsen/logrus"
)

type ProcessInfo struct {
	Pid        int
	PPid       int
	Executable string
	Order      int
	Timestamp  time.Time
}

type ProcessCallback func([]*ProcessInfo)

type ProcessWatcher struct {
	Hostname  string
	logger    *logrus.Logger
	callback  ProcessCallback
	endSignal chan bool
	interval  int64
}

func New(logger *logrus.Logger, callback ProcessCallback) *ProcessWatcher {
	ret := &ProcessWatcher{
		callback:  callback,
		interval:  10,
		logger:    logger,
		endSignal: make(chan bool),
	}

	ret.start()

	return ret
}

func (p *ProcessWatcher) start() {
	p.Execute()
	for {
		select {
		case <-p.endSignal:
			p.logger.Infof("Stop requested")
			return
		case <-time.After(time.Duration(p.interval) * time.Second):
			p.Execute()
		}
	}
}

func (p *ProcessWatcher) Stop() {
	p.endSignal <- true
}

func (p *ProcessWatcher) Execute() {
	processes, err := ps.Processes()
	if err != nil {
		p.logger.Fatalf("err: %s", err)
	}

	if len(processes) <= 0 {
		p.logger.Fatal("should have processes")
	}

	ret := make([]*ProcessInfo, len(processes))
	for i, c := range processes {
		ret[i] = &ProcessInfo{
			Order:      i,
			Pid:        c.Pid(),
			PPid:       c.PPid(),
			Executable: c.Executable(),
			Timestamp:  time.Now(),
		}
	}

	p.callback(ret)
}
