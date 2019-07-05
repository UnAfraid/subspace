package main

import (
	"io"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type LumberjackHookConfig struct {
	Level     logrus.Level
	Formatter logrus.Formatter
}

type RotateFileHook struct {
	Config    *LumberjackHookConfig
	logWriter io.Writer
}

func NewLumberjackHook(config *LumberjackHookConfig, logWriter *lumberjack.Logger) logrus.Hook {
	return &RotateFileHook{
		Config:    config,
		logWriter: logWriter,
	}
}

func (hook *RotateFileHook) Levels() []logrus.Level {
	return logrus.AllLevels[:hook.Config.Level+1]
}

func (hook *RotateFileHook) Fire(entry *logrus.Entry) (err error) {
	bytes, err := hook.Config.Formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = hook.logWriter.Write(bytes)
	return err
}
