package pw

import (
	"fmt"
	"strings"
	"time"

	ps "github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
)

type ProcessInfo struct {
	Pid        int32         `json:"pid"`
	Order      int           `json:"order"`
	Timestamp  time.Time     `json:"timestamp"`
	Interval   int64         `json:"interval"`
	Name       string        `json:"name"`
	Status     string        `json:"status"`
	Parent     int32         `json:"parent"`
	CreateTime time.Time     `json:"create-time"`
	LifeTime   time.Duration `json:"life-time"`
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
		ct := p.getInfoTime(c.CreateTime)
		ret[i] = &ProcessInfo{
			Order:      i,
			Pid:        c.Pid,
			Timestamp:  time.Now(),
			Interval:   p.interval,
			Name:       p.getInfo(c.Name),
			Status:     p.getInfoArr(c.Status),
			CreateTime: ct,
			LifeTime:   time.Since(ct),
		}
	}

	p.callback(ret)
}

func (p *ProcessWatcher) getInfo(f func() (string, error)) string {
	ret, err := f()

	if err != nil {
		p.logger.Errorf("Fail to try get process info: %s", err.Error())
	}

	return fmt.Sprint(ret)
}

func (p *ProcessWatcher) getInfoArr(f func() ([]string, error)) string {
	ret, err := f()

	if err != nil {
		p.logger.Errorf("Fail to try get process info: %s", err.Error())
	}

	return strings.Join(ret, ",")
}

func (p *ProcessWatcher) getInfoTime(f func() (int64, error)) time.Time {
	ret, err := f()

	if err != nil {
		p.logger.Errorf("Fail to try get process info: %s", err.Error())
	}

	return time.UnixMilli(ret)
}
