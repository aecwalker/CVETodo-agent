package logger

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// New creates a new logger instance with specified level and format
func New(level, format string) *Logger {
	log := logrus.New()
	
	// Set log level
	logLevel, err := logrus.ParseLevel(strings.ToLower(level))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	log.SetLevel(logLevel)
	
	// Set log format
	switch strings.ToLower(format) {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
		})
	default:
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05Z07:00",
		})
	}
	
	// Set output to stdout
	log.SetOutput(os.Stdout)
	
	return &Logger{Logger: log}
}

// WithComponent adds a component field to log entries
func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.WithField("component", component)
}

// WithFields adds multiple fields to log entries
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// WithError adds an error field to log entries
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// Audit logs audit events with structured data
func (l *Logger) Audit(action string, fields map[string]interface{}) {
	entry := l.WithField("audit", true).WithField("action", action)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Info("audit event")
}

// Performance logs performance metrics
func (l *Logger) Performance(operation string, duration float64, fields map[string]interface{}) {
	entry := l.WithField("performance", true).
		WithField("operation", operation).
		WithField("duration_ms", duration)
	
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Info("performance metric")
}

// Security logs security-related events
func (l *Logger) Security(event string, fields map[string]interface{}) {
	entry := l.WithField("security", true).WithField("event", event)
	if fields != nil {
		entry = entry.WithFields(logrus.Fields(fields))
	}
	entry.Warn("security event")
} 