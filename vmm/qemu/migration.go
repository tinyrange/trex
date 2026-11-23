package qemu

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/tinyrange/trex/channel"
	starvalue "github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const migrationFDName = "trex-checkpoint"

func (b *qemuBackend) checkpointDebugState() bool {
	for _, option := range b.options {
		if option.name == "-global" && len(option.properties) == 1 && option.properties[0].value == "migration.store-global-state=off" {
			return true
		}
	}
	return false
}

func (v *qemuExtensionValue) checkpointBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum, timeout := int64(512<<20), starvalue.Number(30)
	if err := starlark.UnpackArgs("checkpoint", args, kwargs, "maximum?", &maximum, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if maximum <= 0 || maximum > 2<<30 {
		return nil, fmt.Errorf("checkpoint maximum must be in 1..2 GiB")
	}
	ctx, cancel, err := operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	d := v.driver
	if !d.migrationMu.TryLock() {
		return nil, fmt.Errorf("another QEMU checkpoint operation is in progress")
	}
	defer d.migrationMu.Unlock()
	state, err := d.Status(ctx)
	if err != nil {
		return nil, err
	}
	if state.Running || (state.Name != "paused" && state.Name != "debug") {
		return nil, fmt.Errorf("checkpoint requires a paused VM, got %s", state.Name)
	}
	if state.Name == "debug" && !d.backend.checkpointDebugState() {
		return nil, fmt.Errorf("checkpoint at a GDB stop requires -global migration.store-global-state=off")
	}
	if err := d.checkpointDisks(); err != nil {
		return nil, err
	}
	stream, err := d.migrationStream(ctx, "migrate")
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	completed := false
	defer func() {
		if !completed {
			_ = stream.Close()
			cleanup, cancel := context.WithTimeout(d.ctx, time.Second)
			defer cancel()
			_, _ = d.qmp.Call(cleanup, "migrate_cancel", nil)
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(stream, maximum+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("read QEMU checkpoint: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("QEMU checkpoint exceeds %d bytes", maximum)
	}
	if err := d.waitMigration(ctx); err != nil {
		return nil, err
	}
	completed = true
	if len(data) == 0 {
		return nil, fmt.Errorf("QEMU sent an empty checkpoint")
	}
	return &starfile.Bytes{Name: "qemu.checkpoint", Data: data}, nil
}

func (v *qemuExtensionValue) restoreCheckpointBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourceValue starlark.Value
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("restore_checkpoint", args, kwargs, "source", &sourceValue, "timeout?", &timeout); err != nil {
		return nil, err
	}
	source, ok := sourceValue.(storage.Reader)
	if !ok || source.Size() <= 0 || source.Size() > 2<<30 {
		return nil, fmt.Errorf("restore_checkpoint requires a nonempty checkpoint file up to 2 GiB")
	}
	ctx, cancel, err := operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	d := v.driver
	if !d.migrationMu.TryLock() {
		return nil, fmt.Errorf("another QEMU checkpoint operation is in progress")
	}
	defer d.migrationMu.Unlock()
	state, err := d.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !d.backend.incoming || state.Name != "inmigrate" {
		return nil, fmt.Errorf("restore_checkpoint requires a fresh incoming QEMU VM")
	}
	if err := d.checkpointDisks(); err != nil {
		return nil, err
	}
	stream, err := d.migrationStream(ctx, "migrate-incoming")
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	_, err = io.CopyN(stream, io.NewSectionReader(source, 0, source.Size()), source.Size())
	_ = stream.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("send QEMU checkpoint: %w", err)
	}
	if err := d.waitMigration(ctx); err != nil {
		return nil, err
	}
	state, err = d.Status(ctx)
	if err != nil {
		return nil, err
	}
	if state.Running || state.Name != "paused" {
		return nil, fmt.Errorf("expected a paused restored VM, got %s", state.Name)
	}
	return starlark.None, nil
}

func (d *qemuDriver) migrationStream(ctx context.Context, command string) (channel.ByteChannel, error) {
	stream, fd, err := inheritedSocket("migration")
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err = d.qmp.call(ctx, "getfd", map[string]any{"fdname": migrationFDName}, fd); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("QEMU %s transport: %w", command, err)
	}
	if _, err = d.qmp.Call(ctx, command, map[string]any{"uri": "fd:" + migrationFDName}); err != nil {
		_ = stream.Close()
		cleanup, cancel := context.WithTimeout(d.ctx, time.Second)
		defer cancel()
		_, _ = d.qmp.Call(cleanup, "closefd", map[string]any{"fdname": migrationFDName})
		return nil, fmt.Errorf("QEMU %s: %w", command, err)
	}
	return stream, nil
}

func (d *qemuDriver) checkpointDisks() error {
	for _, disk := range d.machine.Disks {
		if !disk.ReadOnly || disk.Snapshot {
			return fmt.Errorf("QEMU memory checkpoints require immutable disk attachments")
		}
	}
	return nil
}

func (d *qemuDriver) waitMigration(ctx context.Context) error {
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	for {
		value, err := d.qmp.Call(ctx, "query-migrate", nil)
		if err != nil {
			return err
		}
		status, _ := value.(map[string]any)
		switch status["status"] {
		case "completed":
			return nil
		case "failed", "cancelled":
			return fmt.Errorf("QEMU migration %v: %v", status["status"], status["error-desc"])
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
		}
	}
}
