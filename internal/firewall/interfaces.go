package firewall

import "os/exec"

type CmdRunner interface {
	Run(cmd *exec.Cmd) (output string, err error)
}

type Logger interface {
	Debug(s string)
	Debugf(format string, args ...any)
	Info(s string)
	Warn(s string)
	Warnf(format string, args ...any)
	Error(s string)
}

type Netlinker interface {
	FlushConntrack() error
}
