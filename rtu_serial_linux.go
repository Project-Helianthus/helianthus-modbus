//go:build linux

package modbus

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const rtuSerialPollInterval = 10 * time.Millisecond

// Linux CBAUD is not exported by every supported syscall target. The standard
// baud constants used below occupy this mask on the Linux targets supported by
// this adapter.
const rtuSerialLinuxBaudMask uint32 = 0x100f

// OpenRTUSerial opens and configures one explicitly named Linux serial endpoint.
// It creates no registry profile and does not make any operation admissible.
func OpenRTUSerial(config RTUSerialConfig) (*RTUSerialStream, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(config.Path, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := configureRTUSerialFD(fd, config); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return newRTUSerialStream(&linuxRTUSerialBackend{file: os.NewFile(uintptr(fd), config.Path)}, time.Now)
}

type linuxRTUSerialBackend struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func configureRTUSerialFD(fd int, config RTUSerialConfig) error {
	var termios syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios))); errno != 0 {
		return errno
	}
	speed, ok := rtuSerialLinuxSpeed(config.Baud)
	if !ok {
		return protocolError(ErrorInvalidRequest, 0, 0, "rtu_serial_baud", -1)
	}
	termios.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	termios.Oflag &^= syscall.OPOST
	termios.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	termios.Cflag &^= syscall.CSIZE | syscall.PARENB | syscall.PARODD | syscall.CSTOPB | rtuSerialLinuxBaudMask
	termios.Cflag |= syscall.CREAD | syscall.CLOCAL | syscall.CS8 | speed
	if config.Parity != RTUParityNone {
		termios.Cflag |= syscall.PARENB
		if config.Parity == RTUParityOdd {
			termios.Cflag |= syscall.PARODD
		}
	}
	if config.StopBits == 2 {
		termios.Cflag |= syscall.CSTOPB
	}
	termios.Cc[syscall.VMIN] = 0
	termios.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&termios))); errno != 0 {
		return errno
	}
	return nil
}

func rtuSerialLinuxSpeed(baud uint32) (uint32, bool) {
	switch baud {
	case 9600:
		return syscall.B9600, true
	case 19200:
		return syscall.B19200, true
	case 38400:
		return syscall.B38400, true
	case 57600:
		return syscall.B57600, true
	case 115200:
		return syscall.B115200, true
	case 230400:
		return syscall.B230400, true
	default:
		return 0, false
	}
}

func (backend *linuxRTUSerialBackend) ReceiveByte(ctx context.Context) (byte, error) {
	var buffer [1]byte
	for {
		if err := setRTUSerialDeadline(ctx, backend.file.SetReadDeadline); err != nil {
			return 0, err
		}
		n, err := backend.file.Read(buffer[:])
		if err == nil && n == 1 {
			return buffer[0], nil
		}
		if err == nil && n == 0 {
			return 0, io.EOF
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			continue
		}
		return 0, err
	}
}

func (backend *linuxRTUSerialBackend) Write(ctx context.Context, frame []byte) (int, error) {
	for written := 0; written < len(frame); {
		if err := setRTUSerialDeadline(ctx, backend.file.SetWriteDeadline); err != nil {
			return written, err
		}
		n, err := backend.file.Write(frame[written:])
		written += n
		if err == nil && n == 0 {
			return written, io.ErrShortWrite
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ctx.Err() != nil {
				return written, ctx.Err()
			}
			continue
		}
		if err != nil {
			return written, err
		}
	}
	return len(frame), nil
}

func (backend *linuxRTUSerialBackend) Close() error {
	backend.closeOnce.Do(func() { backend.closeErr = backend.file.Close() })
	return backend.closeErr
}

func setRTUSerialDeadline(ctx context.Context, setDeadline func(time.Time) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(rtuSerialPollInterval)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return setDeadline(deadline)
}
