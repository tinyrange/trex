package repo

import "io"

// The terminal index is derived data, never a referenced native object. Remove
// it durably before appending so subsequent checkpoints do not accumulate.
func (r *Repository) discardCheckpoint() error {
	if r.checkpointStart == 0 {
		return nil
	}
	if err := r.flush(); err != nil {
		return err
	}
	start := r.checkpointStart
	if err := r.f.Truncate(start); err != nil {
		r.poisoned = err
		return err
	}
	if err := r.f.Sync(); err != nil {
		r.poisoned = err
		return err
	}
	if _, err := r.f.Seek(start, io.SeekStart); err != nil {
		r.poisoned = err
		return err
	}
	r.end = start
	r.checkpointStart = 0
	if r.writer != nil {
		r.writer.Reset(r.f)
	}
	return nil
}
