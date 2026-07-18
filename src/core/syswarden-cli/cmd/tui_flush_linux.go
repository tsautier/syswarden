//go:build linux

package cmd

import (
	"os"
	"golang.org/x/sys/unix"
)

func flushStdin() {
	_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
