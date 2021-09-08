package storage

import (
	"database/sql"
	"fmt"
	"time"

	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-watcher"
	. "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

var dbDriver = "sqlite3_extended"

type Storage struct {
	logger        *logrus.Logger
	db            *sql.DB
	dbPath        string
	lastCheck     time.Time
	openDate      string
	checkInterval time.Duration
}

func New(logger *logrus.Logger) *Storage {
	return &Storage{
		logger:        logger,
		checkInterval: 10 * time.Second,
	}
}

func (s *Storage) start() error {
	s.dbPath = fmt.Sprint(`./data/database_%s.sqlite`, time.Now().Format("20170831"))
	s.openDate = time.Now().Format("20170831")

	var err error

	s.db, err = sql.Open(dbDriver, s.dbPath)

	if err != nil {
		s.logger.WithField("Source", "Storage").WithField("Trace", "start").Errorf("Fail to open SQLite file database: [Path: %s] error: %s", s.dbPath, err.Error())
		return err
	}

	err = s.createDatabase()

	if err != nil {
		s.logger.WithField("Source", "Storage").WithField("Trace", "start").Errorf("Fail to create tables on SQLite database: [Path: %s] error: %s", s.dbPath, err.Error())
		return err
	}

	return s.check()
}

func (s *Storage) Stop() {
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Storage) check() error {
	var err error

	if s.openDate != time.Now().Format("20170831") {
		s.Stop()
		err = s.start()
	}

	if err == nil && time.Now().After(s.lastCheck.Add(s.checkInterval)) {
		if err = s.db.Ping(); err != nil {
			s.logger.WithField("Source", "Storage").WithField("Trace", "check").Errorf("Fail to check SQLite database: %s", err.Error())
		} else {
			s.lastCheck = time.Now()
			s.logger.WithField("Source", "Storage").WithField("Trace", "check").Debug("Database ping ok!")
		}
	}

	return err
}

var createDBScript = `
CREATE TABLE IF NOT EXISTS DNS_MSGS 
(	
	Id INTEGER PRIMARY KEY AUTOINCREMENT,
	CreatedAt		TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	Device          TEXT DEFAULT NULL,
	Message         TEXT DEFAULT NULL,
	SourceIP        TEXT DEFAULT NULL,
	DestinationIP   TEXT DEFAULT NULL,
	Query           TEXT DEFAULT NULL,
	Answer          TEXT DEFAULT NULL,
	AnswerTTL       TEXT DEFAULT NULL,
	NumberOfAnswers TEXT DEFAULT NULL,
	DnsResponseCode TEXT DEFAULT NULL,
	DnsOpCode       TEXT DEFAULT NULL,
	Hostname        TEXT DEFAULT NULL,
	Timestamp		TIMESTAMP
);

CREATE TABLE IF NOT EXISTS PROCESSES
(	
	Id INTEGER PRIMARY KEY AUTOINCREMENT,
	CreatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	Executable	TEXT NOT NULL,
	Pid			INTEGER NOT NULL,
	PPid		INTEGER NOT NULL,	
	Order		INTEGER DEFAULT NULL,	
	Timestamp   TIMESTAMP DEFAULT NULL,
	Interval 	INTEGER DEFAULT 10
);
`

func (s *Storage) createDatabase() error {
	err := s.check()

	if err == nil {
		if _, err = s.db.Exec(createDBScript); err == nil {
			s.logger.WithField("Source", "Storage").WithField("Trace", "createDatabase").Debug("Database created!")
		} else {
			s.logger.WithField("Source", "Storage").WithField("Trace", "createDatabase").Debugf("Fail to execute create tables script on database: %s, script:\n%s", err.Error(), createDBScript)
		}
	}

	return err
}

func (s *Storage) WriteProcessEntry(processes []*pw.ProcessInfo) error {
	err := s.check()

	if err == nil {

	}

	return err
}

func (s *Storage) WriteDnsMessage(msg *sniffer.DnsMsg) error {
	err := s.check()

	if err == nil {

	}

	return err
}
