package uup

import (
	"fmt"
	"testing"
)

func TestCBSSnapshotIsolationAcrossCollidingLeaves(t *testing.T) {
	var base cbsSnapshotTable[uint32]
	byBucket := map[uint16][]string{}
	for i := 0; i < 7000; i++ {
		key := fmt.Sprintf("package-%d", i)
		base.add(key, uint32(i))
		bucket := cbsContextBucket(key)
		byBucket[bucket] = append(byBucket[bucket], key)
	}
	var same []string
	var bucket uint16
	for b, keys := range byBucket {
		if len(keys) >= 2 {
			bucket, same = b, keys[:2]
			break
		}
	}
	var sibling, other string
	for b, keys := range byBucket {
		if b != bucket && b>>6 == bucket>>6 {
			sibling = keys[0]
		}
		if b>>6 != bucket>>6 {
			other = keys[0]
		}
	}
	if len(same) != 2 || sibling == "" || other == "" {
		t.Fatal("fixture lacks required collisions")
	}
	changes := map[string]uint32{same[0]: 8001, same[1]: 8002, sibling: 8003, other: 8004, "new-package": 8005}
	next := base.changed(changes, nil)
	third := next.changed(map[string]uint32{same[0]: 9001}, []string{same[1], sibling, "missing", "new-package"})
	changes[same[0]] = 42
	for key, value := range next.all() {
		if wanted, ok := base.lookup(key); ok {
			if _, changed := changes[key]; !changed && value != wanted {
				t.Fatal("unrelated value changed")
			}
		}
	}
	for key := range changes {
		if old, ok := base.lookup(key); ok && old >= 8000 {
			t.Fatal("base snapshot mutated")
		}
	}
	if v, _ := next.lookup(same[0]); v != 8001 {
		t.Fatal("new snapshot aliases input or later snapshot")
	}
	if v, _ := third.lookup(same[0]); v != 9001 {
		t.Fatal("replacement lost")
	}
	if _, ok := third.lookup(same[1]); ok {
		t.Fatal("deletion lost")
	}
	if v, _ := next.lookup(same[1]); v != 8002 {
		t.Fatal("deletion mutated earlier snapshot")
	}
	if base.count != 7000 || next.count != 7001 || third.count != 6998 {
		t.Fatal("snapshot count changed incorrectly")
	}
	calls := 0
	for range next.all() {
		calls++
		break
	}
	if calls != 1 {
		t.Fatal("iteration did not stop")
	}
}
