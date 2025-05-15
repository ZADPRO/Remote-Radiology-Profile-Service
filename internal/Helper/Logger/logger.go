package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// CustomFormatter formats log entries like Winston
type CustomFormatter struct{}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := time.Now()
	hour := timestamp.Hour() % 12
	if hour == 0 {
		hour = 12
	}
	min := fmt.Sprintf("%02d", timestamp.Minute())
	sec := fmt.Sprintf("%02d", timestamp.Second())
	ampm := "AM"
	if timestamp.Hour() >= 12 {
		ampm = "PM"
	}
	date := timestamp.Format("01/02/2006") // MM/DD/YYYY

	timeString := fmt.Sprintf("%s %d:%s:%s %s", date, hour, min, sec, ampm)
	logLine := fmt.Sprintf("%s [%s]: %s\n", timeString, entry.Level.String(), entry.Message)
	return []byte(logLine), nil
}

// InitLogger sets up the logger
func InitLogger() *logrus.Logger {
	log := logrus.New()

	// Set custom formatter
	log.SetFormatter(new(CustomFormatter))

	// Log output to console
	log.SetOutput(os.Stdout)

	now := time.Now()
	filename := fmt.Sprintf("Logs/Log_%02d_%02d_%d.log", now.Day(), now.Month(), now.Year())

	// File rotation setup
	logFile := &lumberjack.Logger{
		Filename:   filename, // Change path as needed
		MaxSize:    10,       // Max size in MB before rotating
		MaxBackups: 0,        // Number of backups
		MaxAge:     7,        // Max age in days
		Compress:   true,     // Compress old logs
	}

	// Log to both console and file
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	log.SetLevel(logrus.InfoLevel) // Match "info" level from Winston

	return log
}
