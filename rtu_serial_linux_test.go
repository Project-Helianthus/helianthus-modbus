//go:build linux

package modbus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func linuxTestPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open Linux PTY: %v", err)
	}
	peer := os.NewFile(uintptr(fd), "synthetic-pty")
	t.Cleanup(func() { _ = peer.Close() })
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Fatalf("unlock Linux PTY: %v", errno)
	}
	var number uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		t.Fatalf("number Linux PTY: %v", errno)
	}
	return peer, fmt.Sprintf("/dev/pts/%d", number)
}

func linuxTestSerial(t *testing.T, path string) *RTUSerialStream {
	t.Helper()
	s, err := OpenRTUSerial(RTUSerialConfig{Path: path, Baud: 115200, DataBits: 8, Parity: RTUParityNone, StopBits: 1})
	if err != nil {
		t.Fatalf("configure Linux PTY: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRTUSerialLinuxPTYIdleDeadlineAndHangup(t *testing.T) {
	peer, path := linuxTestPTY(t)
	s := linuxTestSerial(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := s.ReadRTUByte(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle read = %v, want deadline (never EOF)", err)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("idle deadline elapsed = %s", elapsed)
	}
	if _, err := peer.Write([]byte{0x5a}); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if value, _, err := s.ReadRTUByte(ctx2); err != nil || value != 0x5a {
		t.Fatalf("read after idle deadline = %#x, %v", value, err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadRTUByte(ctx2); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
		t.Fatalf("PTY hangup = %v, want EOF or EIO fault", err)
	}
}

func TestRTUSerialLinuxPTYInputSpeedFollowsOutput(t *testing.T) {
	_, path := linuxTestPTY(t)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Close(fd); err != nil {
			t.Errorf("close Linux PTY: %v", err)
		}
	})
	var termios syscall.Termios
	ioctl := func(request uintptr) {
		t.Helper()
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&termios))); errno != 0 {
			t.Fatal(errno)
		}
	}
	ioctl(syscall.TCGETS)
	// Seed a different input rate so inheriting it cannot pass accidentally.
	termios.Cflag &^= (uint32(0x100f) << 16)
	termios.Cflag |= uint32(syscall.B9600) << 16
	ioctl(syscall.TCSETS)
	ioctl(syscall.TCGETS)
	if termios.Cflag&(uint32(0x100f)<<16) != uint32(syscall.B9600)<<16 {
		t.Fatal("PTY did not retain seeded input speed")
	}
	if err := configureRTUSerialFD(fd, RTUSerialConfig{Path: path, Baud: 115200, DataBits: 8, Parity: RTUParityNone, StopBits: 1}); err != nil {
		t.Fatal(err)
	}
	ioctl(syscall.TCGETS)
	output := termios.Cflag & 0x100f
	input := (termios.Cflag >> 16) & 0x100f
	if input != 0 {
		t.Fatalf("input speed bits = %#x, want B0 (follow output)", input)
	}
	if output != syscall.B115200 {
		t.Fatalf("output speed bits = %#x", output)
	}
	if termios.Cc[syscall.VMIN] != 1 || termios.Cc[syscall.VTIME] != 0 {
		t.Fatal("incorrect poller read controls")
	}
}

func TestRTUSerialLinuxPTYChunkedReadFrames(t *testing.T) {
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, mutation := range []string{"valid", "crc", "truncated"} {
			t.Run(fmt.Sprintf("FC%02d/%s", function, mutation), func(t *testing.T) {
				peer, path := linuxTestPTY(t)
				s := linuxTestSerial(t, path)
				e := chunkedReadEndpoint(t, s, 0)
				req, err := NewReadRegistersRequest(function, 0, 125)
				if err != nil {
					t.Fatal(err)
				}
				words := make([]uint16, 125)
				for i := range words {
					words[i] = uint16(i + 1)
				}
				frame := productionReadResponse(t, 1, req, words)
				switch mutation {
				case "crc":
					frame[len(frame)-1] ^= 1
				case "truncated":
					frame = frame[:len(frame)-1]
				}
				if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				sent := make(chan error, 1)
				go func() {
					var request [8]byte
					if _, err := io.ReadFull(peer, request[:]); err != nil {
						sent <- err
						return
					}
					for start := 0; start < len(frame); start += 64 {
						end := start + 64
						if end > len(frame) {
							end = len(frame)
						}
						if start != 0 {
							time.Sleep(4 * time.Millisecond)
						}
						if n, err := peer.Write(frame[start:end]); err != nil {
							sent <- err
							return
						} else if n != end-start {
							sent <- io.ErrShortWrite
							return
						}
					}
					sent <- nil
				}()
				response, ev, err := e.Read(context.Background(), 1, req)
				select {
				case sendErr := <-sent:
					if sendErr != nil {
						t.Fatal(sendErr)
					}
				case <-time.After(time.Second):
					t.Fatal("PTY sender timed out")
				}
				if mutation == "valid" {
					if err != nil || !ev.Current || len(response.Words) != 125 || response.Words[124] != 125 {
						t.Fatalf("chunked PTY read: %v %#v", err, ev)
					}
				} else if err == nil || ev.Current || ev.IntegrityValid || !e.fenced {
					t.Fatalf("malformed PTY response accepted: %v %#v", err, ev)
				}
				if !bytes.Equal(ev.ResponseADU, frame) {
					t.Fatal("PTY raw response evidence changed")
				}
			})
		}
	}
}
