#!/usr/bin/env bash
set -u

mkdir -p /logs/verifier
SCORE_FILE="/logs/verifier/reward.txt"
echo "0.0" > "$SCORE_FILE"

cd /workspace/lsmkv || exit 0

cat << 'TESTEOF' > /workspace/lsmkv/verifier_eval_test.go
package lsmkv

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestBasicCRUDAndScan(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(Options{
		Dir:                       dir,
		MemtableMaxBytes:          64 * 1024,
		Level0CompactionThreshold: 4,
		SyncWrites:                true,
		BloomFalsePositiveRate:    0.01,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	for i := 0; i < 200; i++ {
		k := []byte(fmt.Sprintf("key-%04d", i))
		v := []byte(fmt.Sprintf("val-%04d", i))
		if err := eng.Put(k, v); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	// Overwrite and delete
	if err := eng.Put([]byte("key-0050"), []byte("updated-0050")); err != nil {
		t.Fatalf("Overwrite failed: %v", err)
	}
	if err := eng.Delete([]byte("key-0055")); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	val, ok, err := eng.Get([]byte("key-0050"))
	if err != nil || !ok || string(val) != "updated-0050" {
		t.Fatalf("Expected updated-0050, got ok=%v val=%s err=%v", ok, string(val), err)
	}

	_, ok, err = eng.Get([]byte("key-0055"))
	if err != nil || ok {
		t.Fatalf("Expected key-0055 to be deleted, got ok=%v err=%v", ok, err)
	}

	entries, err := eng.Scan([]byte("key-0050"), []byte("key-0060"))
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(entries) != 9 {
		t.Fatalf("Expected 9 live entries in [0050, 0060), got %d", len(entries))
	}
	if string(entries[0].Key) != "key-0050" || string(entries[0].Value) != "updated-0050" {
		t.Fatalf("Scan first entry mismatch: %+v", entries[0])
	}
}

func TestWALRecoveryAndCorruptedTail(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(Options{
		Dir:                       dir,
		MemtableMaxBytes:          10 * 1024 * 1024, // Keep in WAL/Memtable
		Level0CompactionThreshold: 10,
		SyncWrites:                true,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		if err := eng.Put([]byte(fmt.Sprintf("k-%03d", i)), []byte(fmt.Sprintf("v-%03d", i))); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}
	if err := eng.Delete([]byte("k-042")); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Corrupt the WAL tail by appending garbage bytes simulating a torn write
	walPath := filepath.Join(dir, "wal.log")
	f, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatalf("Expected wal.log to exist: %v", err)
	}
	_, _ = f.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x99})
	_ = f.Close()

	eng2, err := Open(Options{
		Dir:                       dir,
		MemtableMaxBytes:          10 * 1024 * 1024,
		Level0CompactionThreshold: 10,
		SyncWrites:                true,
	})
	if err != nil {
		t.Fatalf("Reopen after torn WAL tail failed: %v", err)
	}
	defer eng2.Close()

	val, ok, err := eng2.Get([]byte("k-099"))
	if err != nil || !ok || string(val) != "v-099" {
		t.Fatalf("Recovery lost k-099: ok=%v val=%s err=%v", ok, string(val), err)
	}
	_, ok, err = eng2.Get([]byte("k-042"))
	if err != nil || ok {
		t.Fatalf("Recovery failed to replay tombstone for k-042")
	}
}

func TestFlushBloomAndCompaction(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(Options{
		Dir:                       dir,
		MemtableMaxBytes:          4096,
		Level0CompactionThreshold: 4,
		SyncWrites:                false,
		BloomFalsePositiveRate:    0.01,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	payload := bytes.Repeat([]byte("X"), 256)
	for round := 0; round < 3; round++ {
		for i := 0; i < 120; i++ {
			k := []byte(fmt.Sprintf("item-%04d", i))
			v := append([]byte(fmt.Sprintf("r%d-", round)), payload...)
			if err := eng.Put(k, v); err != nil {
				t.Fatalf("Put failed: %v", err)
			}
		}
	}

	for i := 0; i < 60; i++ {
		if err := eng.Delete([]byte(fmt.Sprintf("item-%04d", i))); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
	}

	if err := eng.Compact(); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// Probe missing keys to trigger Bloom filter misses
	for i := 5000; i < 5200; i++ {
		_, ok, err := eng.Get([]byte(fmt.Sprintf("missing-%04d", i)))
		if err != nil || ok {
			t.Fatalf("Unexpected hit on missing key")
		}
	}

	st := eng.Stats()
	if st.CompactionsCompleted == 0 {
		t.Fatalf("Expected CompactionsCompleted > 0, got 0")
	}
	if st.BloomMisses < 150 {
		t.Fatalf("Expected BloomMisses >= 150 on absent keys, got %d", st.BloomMisses)
	}

	// Verify live keys 60..119 have round 2 values and 0..59 are deleted
	for i := 0; i < 120; i++ {
		k := []byte(fmt.Sprintf("item-%04d", i))
		val, ok, err := eng.Get(k)
		if err != nil {
			t.Fatalf("Get error: %v", err)
		}
		if i < 60 && ok {
			t.Fatalf("Key %s should be deleted after compaction", string(k))
		}
		if i >= 60 && (!ok || !bytes.HasPrefix(val, []byte("r2-"))) {
			t.Fatalf("Key %s corrupted after compaction", string(k))
		}
	}
}

func TestRestartPersistenceAndTombstoneShadowing(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		Dir:                       dir,
		MemtableMaxBytes:          2048,
		Level0CompactionThreshold: 2,
		SyncWrites:                true,
		BloomFalsePositiveRate:    0.01,
	}

	eng1, err := Open(opts)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	for i := 0; i < 50; i++ {
		_ = eng1.Put([]byte(fmt.Sprintf("persist-%03d", i)), []byte(fmt.Sprintf("val-%03d", i)))
	}
	_ = eng1.Compact()

	_ = eng1.Delete([]byte("persist-010"))
	_ = eng1.Put([]byte("persist-020"), []byte("new-val-020"))

	if err := eng1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	eng2, err := Open(opts)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer eng2.Close()

	_, ok, _ := eng2.Get([]byte("persist-010"))
	if ok {
		t.Fatalf("persist-010 should be deleted across restart")
	}

	val, ok, _ := eng2.Get([]byte("persist-020"))
	if !ok || string(val) != "new-val-020" {
		t.Fatalf("persist-020 expected new-val-020, got %s", string(val))
	}

	val, ok, _ = eng2.Get([]byte("persist-005"))
	if !ok || string(val) != "val-005" {
		t.Fatalf("persist-005 expected val-005, got %s", string(val))
	}
}

func TestConcurrencyRaceSafety(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(Options{
		Dir:                       dir,
		MemtableMaxBytes:          8192,
		Level0CompactionThreshold: 3,
		SyncWrites:                false,
		BloomFalsePositiveRate:    0.01,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer eng.Close()

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				k := []byte(fmt.Sprintf("w-%02d-%04d", worker, i))
				v := []byte(fmt.Sprintf("val-%02d-%04d", worker, i))
				_ = eng.Put(k, v)
				_, _, _ = eng.Get(k)
				if i%10 == 0 {
					_, _ = eng.Scan([]byte(fmt.Sprintf("w-%02d-0000", worker)), []byte(fmt.Sprintf("w-%02d-0050", worker)))
				}
			}
		}(w)
	}
	wg.Wait()
}
TESTEOF

if go test -race -v -timeout 120s ./...; then
    echo "1.0" > "$SCORE_FILE"
else
    echo "0.0" > "$SCORE_FILE"
fi
rm -f /workspace/lsmkv/verifier_eval_test.go
