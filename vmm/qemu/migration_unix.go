//go:build darwin || linux

package qemu

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/tinyrange/trex/channel"
	"golang.org/x/sys/unix"
)

func qemuWriteQMPWithFD(transport channel.ByteChannel, request map[string]any, file *os.File) error {
	conn, ok := transport.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("QMP descriptor passing requires the native Unix transport")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	rights := unix.UnixRights(int(file.Fd()))
	n, nRights, err := conn.WriteMsgUnix(data, rights, nil)
	if err != nil {
		return err
	}
	if nRights != len(rights) {
		return io.ErrShortWrite
	}
	if n < len(data) {
		left := data[n:]
		n, err := conn.Write(left)
		if err != nil {
			return err
		}
		if n != len(left) {
			return io.ErrShortWrite
		}
	}
	return nil
}
