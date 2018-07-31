package rbac

import "fmt"

// Logger is interface for logger to be used in RBAC
type Logger interface {
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// NullLogger is null logger
type NullLogger struct {
}

// NewNullLogger returns a new NullLogger
func NewNullLogger() Logger {
	return &NullLogger{}
}

// Debugf is for debug logging
func (nl *NullLogger) Debugf(format string, args ...interface{}) {

}

// Errorf is for error logging
func (nl *NullLogger) Errorf(format string, args ...interface{}) {

}

// ConsoleLogger is console logger
type ConsoleLogger struct {
}

// NewConsoleLogger returns a new ConsoleLogger
func NewConsoleLogger() Logger {
	return &ConsoleLogger{}
}

// Debugf is for debug logging
func (nl *ConsoleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

// Errorf is for error logging
func (nl *ConsoleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}
