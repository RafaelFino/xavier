package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	sniffer "github.com/RafaelFino/xavier/internal/dns-sniffer"
	pw "github.com/RafaelFino/xavier/internal/process-watcher"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

var dbDriver = "sqlite3"

type Storage struct {
	logger        *logrus.Logger
	db            *sql.DB
	dbPath        string
	lastCheck     time.Time
	openDate      string
	checkInterval time.Duration
}

func New(logger *logrus.Logger) *Storage {
	ret := &Storage{
		logger:        logger,
		checkInterval: 10 * time.Second,
	}

	ret.start()

	return ret
}

func (s *Storage) start() error {
	s.dbPath = fmt.Sprintf(`data/database_%s.sqlite`, time.Now().Format("2006-01-02"))
	s.openDate = time.Now().Format("2006-01-02")

	var err error

	s.db, err = sql.Open(dbDriver, s.dbPath)

	if err != nil {
		s.logger.WithField("Source", "Storage").WithField("Trace", "start").Errorf("Fail to open SQLite file database: [Path: %s] error: %s", s.dbPath, err.Error())
		return err
	}

	s.logger.WithField("Source", "Storage").WithField("Trace", "start").Infof("SQLite file database created on %s", s.dbPath)

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

	if s.openDate != time.Now().Format("2006-01-02") {
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
	ReportedAt		NUMERIC DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS PROCESS_EVENTS
(	
	Id INTEGER PRIMARY KEY AUTOINCREMENT,
	CreatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	Executable	TEXT NOT NULL,
	Interval 	INTEGER DEFAULT 10,
	ReportedAt	NUMERIC DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS PROCESS_SUM
(	
	Executable	TEXT PRIMARY KEY,
	CreatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	UpdatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	Count	 	INTEGER DEFAULT 0,
	ReportedAt	NUMERIC DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS DNS_SUM
(	
	Query		TEXT PRIMARY KEY,
	CreatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	UpdatedAt 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP,	
	Count	 	INTEGER DEFAULT 0,
	ReportedAt	NUMERIC DEFAULT NULL
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

var insertProcesses = `
INSERT INTO PROCESS_EVENTS (
	Executable,
	Interval,
	ReportedAt
) 
VALUES 
(
	?,
	?,
	? 
);
`
var updateProcessSum = `
INSERT INTO PROCESS_SUM 
(
	Executable,
	Count,
	ReportedAt
)
VALUES
(
	?,
	?,
	?
)
ON CONFLICT(Executable) DO UPDATE SET 
	UpdatedAt=CURRENT_TIMESTAMP, 
	Count = Count + ?,
	ReportedAt = ?;
`

type processHashItem struct {
	Timestamp time.Time
	Interval  int64
}

func (s *Storage) WriteProcessEntry(processes []*pw.ProcessInfo) error {
	if len(processes) == 0 {
		return nil
	}

	err := s.check()
	var rows int64

	if err == nil {
		hash := make(map[string]*processHashItem)
		for _, p := range processes {
			if v, found := hash[p.Executable]; found {
				if p.Timestamp.Before(v.Timestamp) {
					v.Timestamp = p.Timestamp
					v.Interval = p.Interval
				}
			} else {
				hash[p.Executable] = &processHashItem{
					Timestamp: p.Timestamp,
					Interval:  p.Interval,
				}
			}
		}

		for k, v := range hash {
			if rows, err = s.execute(insertProcesses, k, v.Interval, v.Timestamp.Local().UnixMicro()); err == nil {
				s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Debugf("Process event data stored, %d rows inserted", rows)
			} else {
				s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Errorf("Fail to try insert event process into SQL: %s\nSQL: %s", err.Error(), insertProcesses)
			}

			if rows, err = s.execute(updateProcessSum, k, v.Interval, v.Timestamp.Local().UnixMicro(), v.Interval, v.Timestamp.Local().UnixMicro()); err == nil {
				s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Debugf("Process sumarry is updatedd, %d rows inserted", rows)
			} else {
				s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Errorf("Fail to try update process sumary into SQL: %s\nSQL: %s", err.Error(), updateProcessSum)
			}
		}

		s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Infof("Processes affected on database: %d", len(hash))
	}

	return err
}

var insertDnsMsg = `
INSERT INTO DNS_MSGS
(
	Device,
	Message,
	SourceIP,
	DestinationIP,
	Query,
	Answer,
	AnswerTTL,
	NumberOfAnswers,
	DnsResponseCode,
	DnsOpCode,
	Hostname,
	ReportedAt
) 
VALUES 
(
	?, --Device,
	?, --Message,
	?, --SourceIP,
	?, --DestinationIP,
	?, --Query,
	?, --Answer,
	?, --AnswerTTL,
	?, --NumberOfAnswers,
	?, --DnsResponseCode,
	?, --DnsOpCode,
	?, --Hostname,
	? --ReportedAt	
);
`

var updateDnsMsgSum = `
INSERT INTO DNS_SUM 
(
	Query,
	Count,
	ReportedAt
)
VALUES
(
	?,
	1,
	?
)
ON CONFLICT(Query) DO UPDATE SET 
	UpdatedAt=CURRENT_TIMESTAMP, 
	Count = Count + 1,
	ReportedAt = ?;
`

func (s *Storage) WriteDnsMessage(msg *sniffer.DnsMsg) error {
	err := s.check()

	if err == nil {
		var rows int64

		if rows, err = s.execute(insertDnsMsg,
			msg.Device,
			msg.Message,
			msg.SourceIP,
			msg.DestinationIP,
			msg.Query,
			strings.Join(msg.Answer, ","),
			strings.Join(msg.AnswerTTL, ","),
			msg.NumberOfAnswers,
			msg.DnsResponseCode,
			msg.DnsOpCode,
			msg.Hostname,
			msg.Timestamp.Local().UnixMicro(),
		); err == nil {
			s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Debugf("Data stored, %d rows inserted", rows)
		} else {
			s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Errorf("Fail to try insert processes into SQL: %s\nSQL: %s", err.Error(), insertDnsMsg)
		}

		if rows, err = s.execute(updateDnsMsgSum, msg.Query, msg.Timestamp.Local().UnixMicro(), msg.Timestamp.Local().UnixMicro()); err == nil {
			s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Debugf("Dns msgs sumarry is updatedd, %d rows inserted", rows)
		} else {
			s.logger.WithField("Source", "Storage").WithField("Trace", "WriteProcessEntry").Errorf("Fail to try update dns sumary into SQL: %s\nSQL: %s", err.Error(), updateProcessSum)
		}
	}

	return err
}

func (s *Storage) execute(statment string, args ...interface{}) (int64, error) {
	rows := int64(-1)
	var err error

	if len(statment) == 0 {
		return rows, nil
	}

	if err = s.check(); err == nil {
		var result sql.Result

		if result, err = s.db.Exec(statment, args...); err == nil {
			rows, err = result.RowsAffected()

			if err != nil {
				s.logger.WithField("Source", "Storage").WithField("Trace", "execute").Errorf("Fail to get SQL insert result: %s", err.Error())
			} else {
				s.logger.WithField("Source", "Storage").WithField("Trace", "execute").Debugf("SQL statment executed, %d rows affected", rows)
			}
		} else {
			s.logger.WithField("Source", "Storage").WithField("Trace", "execute").Errorf("Fail to try execute SQL statment: %s\nSQL: %s", err.Error(), statment)
		}
	}

	return rows, err
}
