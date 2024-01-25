package logger

type UniversalLogger interface {
	Debug(...interface{})
	Debugf(string, ...interface{})
	Info(...interface{})
	Infof(string, ...interface{})
	Warn(...interface{})
	Warnf(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
}

type NoOpLogger struct{}

func (l NoOpLogger) Debug(...interface{})          {}
func (l NoOpLogger) Debugf(string, ...interface{}) {}
func (l NoOpLogger) Info(...interface{})           {}
func (l NoOpLogger) Infof(string, ...interface{})  {}
func (l NoOpLogger) Warn(...interface{})           {}
func (l NoOpLogger) Warnf(string, ...interface{})  {}
func (l NoOpLogger) Error(...interface{})          {}
func (l NoOpLogger) Errorf(string, ...interface{}) {}
