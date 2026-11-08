//go:build darwin || linux

package ingestion

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The configured parent directories are trusted. Reject a symlink at the final
// component and use NONBLOCK so a race replacing the source with a FIFO cannot
// hang the collector. fstat closes the race with the preceding lstat.
func openLog(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, nil, errUnsafeFile
		}
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, errUnsafeFile
	}
	return f, info, nil
}
func identifyFile(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("file identity unavailable")
	}
	return fileIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
