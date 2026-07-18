//go:build !linux

package cmd

func flushStdin() {
	// Not required or not supported
}
