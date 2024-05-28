package go_mtr

import (
	"golang.org/x/sys/unix"
	"time"
)

func setSockOptReceiveErr(fd int) error {
	return nil
}

func setSockOptRcvTimeout(fd int, timeout time.Duration) error {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return err
}

func setSockOptRcvBuff(fd int, bytes int) error {
	err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bytes)
	return err
}
