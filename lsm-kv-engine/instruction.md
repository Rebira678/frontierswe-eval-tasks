# Task: Concurrent Crash-Safe LSM-Tree Storage Engine (`lsmkv`)

## Objective
Implement a high-throughput, crash-recoverable Log-Structured Merge-tree (LSM-Tree) key-value storage engine in Go at `/workspace/lsmkv`.

Your package must expose a public Go library (`package lsmkv`) at `/workspace/lsmkv` that satisfies strict durability, concurrency, range-scan, and write-amplification guarantees.

## Functional & Architectural Requirements

1. **Public Go API (`/workspace/lsmkv/engine.go`)**
   Implement the following exact types and signatures in `package lsmkv` (module name `lsmkv`):
   - `type Options struct { Dir string; MemtableMaxBytes int64; Level0CompactionThreshold int; SyncWrites bool; BloomFalsePositiveRate float64 }`
   - `type KVEntry struct { Key []byte; Value []byte }`
   - `type Stats struct { MemtableBytes int64; NumSSTablesL0 int; NumSSTablesL1 int; BloomHits uint64; BloomMisses uint64; CompactionsCompleted uint64 }`
   - `func Open(opts Options) (*Engine, error)`
   - `func (e *Engine) Put(key, value []byte) error`
   - `func (e *Engine) Get(key []byte) ([]byte, bool, error)`
   - `func (e *Engine) Delete(key []byte) error`
   - `func (e *Engine) Scan(startKey, endKey []byte) ([]KVEntry, error)` — lexicographical range scan `[startKey, endKey)` returning live (non-deleted) keys in ascending order with point-in-time snapshot consistency.
   - `func (e *Engine) Compact() error` — forces synchronous compaction of L0 SSTables into L1, purging overwritten versions and tombstones.
   - `func (e *Engine) Stats() Stats`
   - `func (e *Engine) Close() error`

2. **Write-Ahead Log (WAL) & Crash Recovery**
   - Every `Put` and `Delete` must be appended to a binary WAL file (`wal.log`) before mutating the active in-memory skip-list/memtable.
   - Every WAL frame must include a **CRC32 (IEEE) checksum**, sequence number, record type (`Put=1`, `Delete=2`), key length, value length, and payload.
   - If the process crashes mid-write or a trailing WAL frame has a corrupted/truncated CRC or payload, `Open()` must replay all valid prefix frames and cleanly truncate the corrupted tail without failing to start or losing previously committed entries.

3. **Memtable Flush, SSTables, and Bloom Filters**
   - When the active memtable reaches `MemtableMaxBytes`, flush it into an immutable L0 SSTable file on disk with a footer index and an embedded **Bloom filter**.
   - Point lookups (`Get`) on keys not present in an SSTable must consult that SSTable's Bloom filter before reading data blocks, incrementing `Stats().BloomMisses` when the filter rules out a key.

4. **Leveled Compaction & Tombstone Reclamation**
   - When L0 SSTable count reaches `Level0CompactionThreshold` (or `Compact()` is invoked), merge-sort L0 SSTables into L1, discarding shadowed older values and deleted tombstones so disk space is reclaimed.

5. **Concurrency**
   - All engine methods must be safe for concurrent invocation across 32+ goroutines without data races (`go test -race`).

## Verification Criteria
Your implementation will be evaluated on:
- Correctness of `Put`, `Get`, `Delete` (tombstone shadowing across Memtable, L0, and L1), and lexicographical `Scan`.
- WAL crash recovery and corrupted tail truncation resilience.
- Bloom filter effectiveness and SSTable compaction space reclamation.
- Concurrent throughput and zero race detector violations under `go test -race`.
