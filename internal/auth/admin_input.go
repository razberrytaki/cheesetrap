package auth

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ReadAdminInput reads locally, never through argv/environment. Noninteractive
// input is exactly username LF password [LF], bounded to 1090 bytes. Polling
// keeps pipe/terminal reads cancellable without a stranded reader goroutine.
func ReadAdminInput(ctx context.Context, file *os.File, prompt io.Writer) (string, string, error) {
	fd := int(file.Fd())
	interactive := term.IsTerminal(fd)
	if !interactive {
		data, err := readInput(ctx, fd, 1090, false, false)
		if err != nil {
			return "", "", err
		}
		parts := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		if len(parts) != 2 || !validAdminInput(parts[0], parts[1]) {
			return "", "", ErrInput
		}
		return parts[0], parts[1], nil
	}
	_, _ = io.WriteString(prompt, "Username: ")
	username, err := readInput(ctx, fd, 64, true, false)
	if err != nil {
		return "", "", err
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", "", ErrInput
	}
	defer term.Restore(fd, state)
	_, _ = io.WriteString(prompt, "Password (12–1024 bytes): ")
	password, err := readInput(ctx, fd, 1024, true, true)
	_, _ = io.WriteString(prompt, "\r\n")
	if err != nil {
		return "", "", err
	}
	if !validAdminInput(string(username), string(password)) {
		return "", "", ErrInput
	}
	return string(username), string(password), nil
}
func validAdminInput(username, password string) bool {
	return ValidUsername(username) && len(password) >= 12 && len(password) <= 1024 && utf8.ValidString(password) && !strings.ContainsAny(password, "\x00\r\n")
}
func readInput(ctx context.Context, fd, limit int, line, raw bool) ([]byte, error) {
	data := make([]byte, 0, min(limit, 128))
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, ErrInput
		}
		if n == 0 {
			continue
		}
		var b [1]byte
		n, err = unix.Read(fd, b[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			return nil, ErrInput
		}
		if n == 0 {
			return data, nil
		}
		if line && (b[0] == '\n' || b[0] == '\r') {
			return data, nil
		}
		if raw {
			if b[0] == 3 || b[0] == 4 {
				return nil, ErrInput
			}
			if b[0] == 127 || b[0] == 8 {
				if len(data) > 0 {
					data = data[:len(data)-1]
				}
				continue
			}
		}
		if len(data) == limit {
			return nil, ErrInput
		}
		data = append(data, b[0])
	}
}
