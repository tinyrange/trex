//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/emulator/uefi"
	"github.com/tinyrange/trex/vmm"
)

func TestResetReconstructsHardwarePreservesDisk(t *testing.T) {
	requireKVM(t)
	for _, cores := range []int{1, 4} {
		t.Run(fmt.Sprint(cores), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			data := make([]byte, 2048)
			copy(data, []byte{0xeb, 0xfe})
			binary.LittleEndian.PutUint16(data[510:], 0xaa55)
			b := &Backend{}
			m := vmm.Machine{Architecture: "x86_64", CPUs: cores, Memory: 16 << 20}
			overlay, err := blockstar.NewOverlayDevice(testBlock(t, data), 1<<20, blockstar.DefaultOverlayChunk)
			if err != nil {
				t.Fatal(err)
			}
			disk := vmm.Disk{Device: overlay}
			rebuild := func() (*pc, error) { return b.newPlatform(ctx, m, disk) }
			p, err := rebuild()
			if err != nil {
				t.Fatal(err)
			}
			d := newRestartableDriver(ctx, p, false, rebuild)
			defer d.Close(context.Background())
			// A queued firmware transition exercises both the single and SMP
			// coordinator, including cancellation/join of executing vCPUs.
			for cycle := byte(1); cycle <= 2; cycle++ {
				err = d.call(ctx, func() error {
					d.pc.ram[0x9000] = 99
					if _, err := d.pc.disk.Device.(block.Writer).WriteAt([]byte{cycle}, 1024); err != nil {
						return err
					}
					return d.firmwareTransition(&uefi.ResetRequest{Type: 1})
				})
				if err != nil {
					t.Fatal(err)
				}
				for {
					event, err := d.NextEvent(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if event.Kind == "exit" {
						t.Fatalf("reset exited: %+v", event)
					}
					if event.Kind == "reset" {
						break
					}
				}
				err = d.call(ctx, func() error {
					if d.pc.ram[0x9000] != 0 {
						return fmt.Errorf("old RAM survived reset")
					}
					var value [1]byte
					if _, err := d.pc.disk.Device.ReadAt(value[:], 1024); err != nil {
						return err
					}
					if value[0] != cycle {
						return fmt.Errorf("lost disk write: %d", value[0])
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			// Cancellation after a reset request must also publish a terminal
			// result; callers waiting for the VM must not hang indefinitely.
			err = d.call(ctx, func() error {
				if err := d.firmwareTransition(&uefi.ResetRequest{Type: 1}); err != nil {
					return err
				}
				d.cancel()
				return nil
			})
			// The owner may finish before call observes its buffered reply.
			result, waitErr := d.Wait(ctx)
			if waitErr != nil || result.Reason != "closed" || !result.Clean {
				t.Fatalf("cancel during reset: call=%v result=%+v wait=%v", err, result, waitErr)
			}
			if err := d.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
