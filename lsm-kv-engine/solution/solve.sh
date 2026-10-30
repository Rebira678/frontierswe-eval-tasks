#!/usr/bin/env bash
set -euo pipefail

cd /workspace/lsmkv

cat << 'GOEOF' > /workspace/lsmkv/engine.go
package lsmkv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
)

const (
	recPut    byte = 1
	recDelete byte = 2
	sstMagic  uint32 = 0x4C534D31
)

type Options struct {
	Dir                       string
	MemtableMaxBytes          int64
	Level0CompactionThreshold int
	SyncWrites                bool
	BloomFalsePositiveRate    float64
}

type KVEntry struct {
	Key   []byte
	Value []byte
}

type Stats struct {
	MemtableBytes        int64
	NumSSTablesL0        int
	NumSSTablesL1        int
	BloomHits            uint64
	BloomMisses          uint64
	CompactionsCompleted uint64
}

type internalRecord struct {
	key       string
	value     []byte
	tombstone bool
	seq       uint64
}

type bloomFilter struct {
	bits []byte
	k    uint8
}

func newBloomFilter(n int, fpRate float64) *bloomFilter {
	if n < 16 {
		n = 16
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}
	m := int(math.Ceil(-float64(n) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	if m < 64 {
		m = 64
	}
	bytesLen := (m + 7) / 8
	k := int(math.Max(1, math.Round(float64(bytesLen*8)/float64(n)*math.Ln2)))
	if k > 16 {
		k = 16
	}
	return &bloomFilter{
		bits: make([]byte, bytesLen),
		k:    uint8(k),
	}
}

func bloomHashes(key []byte) (uint32, uint32) {
	h1 := crc32.ChecksumIEEE(key)
	var h2 uint32 = 2166136261
	for _, b := range key {
		h2 ^= uint32(b)
		h2 *= 16777619
	}
	if h2 == 0 {
		h2 = 0x9e3779b9
	}
	return h1, h2
}

func (bf *bloomFilter) add(key []byte) {
	h1, h2 := bloomHashes(key)
	nbits := uint32(len(bf.bits) * 8)
	for i := uint8(0); i < bf.k; i++ {
		idx := (h1 + uint32(i)*h2) % nbits
		bf.bits[idx/8] |= 1 << (idx % 8)
	}
}

func (bf *bloomFilter) mayContain(key []byte) bool {
	if len(bf.bits) == 0 {
		return true
	}
	h1, h2 := bloomHashes(key)
	nbits := uint32(len(bf.bits) * 8)
	for i := uint8(0); i < bf.k; i++ {
		idx := (h1 + uint32(i)*h2) % nbits
		if (bf.bits[idx/8] & (1 << (idx % 8))) == 0 {
			return false
		}
	}
	return true
}

type sstableMeta struct {
	path    string
	level   int
	seqID   uint64
	bloom   *bloomFilter
	records []internalRecord // sorted by key ascending
}

type Engine struct {
	mu                   sync.RWMutex
	opts                 Options
	mem                  map[string]internalRecord
	memBytes             int64
	seq                  uint64
	sstSeq               uint64
	walFile              *os.File
	walPath              string
	l0                   []*sstableMeta
	l1                   []*sstableMeta
	bloomHits            atomic.Uint64
	bloomMisses          atomic.Uint64
	compactionsCompleted atomic.Uint64
	closed               bool
}

func Open(opts Options) (*Engine, error) {
	if opts.Dir == "" {
		return nil, errors.New("Dir is required")
	}
	if opts.MemtableMaxBytes <= 0 {
		opts.MemtableMaxBytes = 64 * 1024
	}
	if opts.Level0CompactionThreshold <= 0 {
		opts.Level0CompactionThreshold = 4
	}
	if opts.BloomFalsePositiveRate <= 0 {
		opts.BloomFalsePositiveRate = 0.01
	}
	if err := os.MkdirAll(opts.Dir, 0755); err != nil {
		return nil, err
	}

	e := &Engine{
		opts:    opts,
		mem:     make(map[string]internalRecord),
		walPath: filepath.Join(opts.Dir, "wal.log"),
	}

	if err := e.loadExistingSSTables(); err != nil {
		return nil, err
	}
	if err := e.replayAndSanitizeWAL(); err != nil {
		return nil, err
	}

	wf, err := os.OpenFile(e.walPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	e.walFile = wf
	return e, nil
}

func (e *Engine) replayAndSanitizeWAL() error {
	data, err := os.ReadFile(e.walPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	offset := 0
	total := len(data)
	for offset+21 <= total {
		crcExpected := binary.LittleEndian.Uint32(data[offset : offset+4])
		seq := binary.LittleEndian.Uint64(data[offset+4 : offset+12])
		rtype := data[offset+12]
		klen := int(binary.LittleEndian.Uint32(data[offset+13 : offset+17]))
		vlen := int(binary.LittleEndian.Uint32(data[offset+17 : offset+21]))

		if klen < 0 || vlen < 0 || offset+21+klen+vlen > total {
			break
		}
		frameBody := data[offset+4 : offset+21+klen+vlen]
		if crc32.ChecksumIEEE(frameBody) != crcExpected {
			break
		}
		if rtype != recPut && rtype != recDelete {
			break
		}

		key := string(data[offset+21 : offset+21+klen])
		val := make([]byte, vlen)
		copy(val, data[offset+21+klen:offset+21+klen+vlen])

		rec := internalRecord{
			key:       key,
			value:     val,
			tombstone: rtype == recDelete,
			seq:       seq,
		}
		if prev, ok := e.mem[key]; ok {
			e.memBytes -= int64(len(prev.key) + len(prev.value))
		}
		e.mem[key] = rec
		e.memBytes += int64(len(key) + len(val))
		if seq > e.seq {
			e.seq = seq
		}
		offset += 21 + klen + vlen
	}

	if offset < total {
		if err := os.Truncate(e.walPath, int64(offset)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) appendWAL(rec internalRecord) error {
	kbytes := []byte(rec.key)
	vbytes := rec.value
	bodyLen := 17 + len(kbytes) + len(vbytes)
	buf := make([]byte, 4+bodyLen)

	rtype := recPut
	if rec.tombstone {
		rtype = recDelete
	}
	binary.LittleEndian.PutUint64(buf[4:12], rec.seq)
	buf[12] = rtype
	binary.LittleEndian.PutUint32(buf[13:17], uint32(len(kbytes)))
	binary.LittleEndian.PutUint32(buf[17:21], uint32(len(vbytes)))
	copy(buf[21:21+len(kbytes)], kbytes)
	copy(buf[21+len(kbytes):], vbytes)

	crc := crc32.ChecksumIEEE(buf[4:])
	binary.LittleEndian.PutUint32(buf[0:4], crc)

	if _, err := e.walFile.Write(buf); err != nil {
		return err
	}
	if e.opts.SyncWrites {
		return e.walFile.Sync()
	}
	return nil
}

func (e *Engine) writeSSTableFile(level int, seqID uint64, records []internalRecord) (*sstableMeta, error) {
	fname := fmt.Sprintf("sst-L%d-%08d.sst", level, seqID)
	fpath := filepath.Join(e.opts.Dir, fname)
	tmpPath := fpath + ".tmp"

	bf := newBloomFilter(len(records), e.opts.BloomFalsePositiveRate)
	for _, r := range records {
		bf.add([]byte(r.key))
	}

	var buf bytes.Buffer
	header := make([]byte, 21)
	binary.LittleEndian.PutUint32(header[0:4], sstMagic)
	binary.LittleEndian.PutUint32(header[4:8], uint32(level))
	binary.LittleEndian.PutUint64(header[8:16], seqID)
	header[16] = bf.k
	binary.LittleEndian.PutUint32(header[17:21], uint32(len(bf.bits)))
	buf.Write(header)
	buf.Write(bf.bits)

	cntBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(cntBuf, uint32(len(records)))
	buf.Write(cntBuf)

	for _, r := range records {
		recHdr := make([]byte, 17)
		binary.LittleEndian.PutUint64(recHdr[0:8], r.seq)
		if r.tombstone {
			recHdr[8] = 1
		} else {
			recHdr[8] = 0
		}
		binary.LittleEndian.PutUint32(recHdr[9:13], uint32(len(r.key)))
		binary.LittleEndian.PutUint32(recHdr[13:17], uint32(len(r.value)))
		buf.Write(recHdr)
		buf.WriteString(r.key)
		buf.Write(r.value)
	}

	crc := crc32.ChecksumIEEE(buf.Bytes())
	crcBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(crcBuf, crc)
	buf.Write(crcBuf)

	if err := os.WriteFile(tmpPath, buf.Bytes(), 0644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpPath, fpath); err != nil {
		return nil, err
	}

	return &sstableMeta{
		path:    fpath,
		level:   level,
		seqID:   seqID,
		bloom:   bf,
		records: records,
	}, nil
}

func readSSTableFile(fpath string) (*sstableMeta, error) {
	data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	if len(data) < 29 {
		return nil, io.ErrUnexpectedEOF
	}
	crcExpected := binary.LittleEndian.Uint32(data[len(data)-4:])
	if crc32.ChecksumIEEE(data[:len(data)-4]) != crcExpected {
		return nil, errors.New("sstable checksum mismatch")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != sstMagic {
		return nil, errors.New("invalid sstable magic")
	}
	level := int(binary.LittleEndian.Uint32(data[4:8]))
	seqID := binary.LittleEndian.Uint64(data[8:16])
	k := data[16]
	bloomLen := int(binary.LittleEndian.Uint32(data[17:21]))
	pos := 21
	if pos+bloomLen+4 > len(data)-4 {
		return nil, io.ErrUnexpectedEOF
	}
	bits := make([]byte, bloomLen)
	copy(bits, data[pos:pos+bloomLen])
	pos += bloomLen

	numRecs := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4
	records := make([]internalRecord, 0, numRecs)
	for i := 0; i < numRecs; i++ {
		if pos+17 > len(data)-4 {
			return nil, io.ErrUnexpectedEOF
		}
		seq := binary.LittleEndian.Uint64(data[pos : pos+8])
		tomb := data[pos+8] == 1
		klen := int(binary.LittleEndian.Uint32(data[pos+9 : pos+13]))
		vlen := int(binary.LittleEndian.Uint32(data[pos+13 : pos+17]))
		pos += 17
		if pos+klen+vlen > len(data)-4 {
			return nil, io.ErrUnexpectedEOF
		}
		key := string(data[pos : pos+klen])
		pos += klen
		val := make([]byte, vlen)
		copy(val, data[pos:pos+vlen])
		pos += vlen
		records = append(records, internalRecord{
			key:       key,
			value:     val,
			tombstone: tomb,
			seq:       seq,
		})
	}

	return &sstableMeta{
		path:    fpath,
		level:   level,
		seqID:   seqID,
		bloom:   &bloomFilter{bits: bits, k: k},
		records: records,
	}, nil
}

func (e *Engine) loadExistingSSTables() error {
	entries, err := os.ReadDir(e.opts.Dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".sst" {
			continue
		}
		meta, err := readSSTableFile(filepath.Join(e.opts.Dir, ent.Name()))
		if err != nil {
			continue
		}
		if meta.seqID > e.sstSeq {
			e.sstSeq = meta.seqID
		}
		for _, r := range meta.records {
			if r.seq > e.seq {
				e.seq = r.seq
			}
		}
		if meta.level == 0 {
			e.l0 = append(e.l0, meta)
		} else {
			e.l1 = append(e.l1, meta)
		}
	}
	sort.Slice(e.l0, func(i, j int) bool { return e.l0[i].seqID < e.l0[j].seqID })
	sort.Slice(e.l1, func(i, j int) bool { return e.l1[i].seqID < e.l1[j].seqID })
	return nil
}

func (e *Engine) flushMemtableLocked() error {
	if len(e.mem) == 0 {
		return nil
	}
	records := make([]internalRecord, 0, len(e.mem))
	for _, r := range e.mem {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].key < records[j].key })

	e.sstSeq++
	meta, err := e.writeSSTableFile(0, e.sstSeq, records)
	if err != nil {
		return err
	}
	e.l0 = append(e.l0, meta)
	e.mem = make(map[string]internalRecord)
	e.memBytes = 0

	if e.walFile != nil {
		_ = e.walFile.Close()
	}
	wf, err := os.OpenFile(e.walPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	e.walFile = wf

	if len(e.l0) >= e.opts.Level0CompactionThreshold {
		return e.compactLocked()
	}
	return nil
}

func (e *Engine) compactLocked() error {
	if len(e.mem) > 0 {
		records := make([]internalRecord, 0, len(e.mem))
		for _, r := range e.mem {
			records = append(records, r)
		}
		sort.Slice(records, func(i, j int) bool { return records[i].key < records[j].key })
		e.sstSeq++
		meta, err := e.writeSSTableFile(0, e.sstSeq, records)
		if err != nil {
			return err
		}
		e.l0 = append(e.l0, meta)
		e.mem = make(map[string]internalRecord)
		e.memBytes = 0
		if e.walFile != nil {
			_ = e.walFile.Close()
		}
		wf, err := os.OpenFile(e.walPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		e.walFile = wf
	}

	if len(e.l0) == 0 && len(e.l1) <= 1 {
		return nil
	}

	merged := make(map[string]internalRecord)
	for _, sst := range e.l1 {
		for _, r := range sst.records {
			if prev, ok := merged[r.key]; !ok || r.seq >= prev.seq {
				merged[r.key] = r
			}
		}
	}
	for _, sst := range e.l0 {
		for _, r := range sst.records {
			if prev, ok := merged[r.key]; !ok || r.seq >= prev.seq {
				merged[r.key] = r
			}
		}
	}

	live := make([]internalRecord, 0, len(merged))
	for _, r := range merged {
		if !r.tombstone {
			live = append(live, r)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].key < live[j].key })

	e.sstSeq++
	newL1, err := e.writeSSTableFile(1, e.sstSeq, live)
	if err != nil {
		return err
	}

	oldFiles := make([]string, 0, len(e.l0)+len(e.l1))
	for _, s := range e.l0 {
		oldFiles = append(oldFiles, s.path)
	}
	for _, s := range e.l1 {
		oldFiles = append(oldFiles, s.path)
	}

	e.l0 = nil
	e.l1 = []*sstableMeta{newL1}
	for _, p := range oldFiles {
		_ = os.Remove(p)
	}
	e.compactionsCompleted.Add(1)
	return nil
}

func (e *Engine) Put(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("empty key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}

	e.seq++
	vcopy := make([]byte, len(value))
	copy(vcopy, value)
	kstr := string(key)
	rec := internalRecord{
		key:       kstr,
		value:     vcopy,
		tombstone: false,
		seq:       e.seq,
	}
	if err := e.appendWAL(rec); err != nil {
		return err
	}
	if prev, ok := e.mem[kstr]; ok {
		e.memBytes -= int64(len(prev.key) + len(prev.value))
	}
	e.mem[kstr] = rec
	e.memBytes += int64(len(kstr) + len(vcopy))

	if e.memBytes >= e.opts.MemtableMaxBytes {
		return e.flushMemtableLocked()
	}
	return nil
}

func (e *Engine) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("empty key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}

	e.seq++
	kstr := string(key)
	rec := internalRecord{
		key:       kstr,
		value:     nil,
		tombstone: true,
		seq:       e.seq,
	}
	if err := e.appendWAL(rec); err != nil {
		return err
	}
	if prev, ok := e.mem[kstr]; ok {
		e.memBytes -= int64(len(prev.key) + len(prev.value))
	}
	e.mem[kstr] = rec
	e.memBytes += int64(len(kstr))

	if e.memBytes >= e.opts.MemtableMaxBytes {
		return e.flushMemtableLocked()
	}
	return nil
}

func searchSSTable(sst *sstableMeta, key string) (internalRecord, bool) {
	idx := sort.Search(len(sst.records), func(i int) bool {
		return sst.records[i].key >= key
	})
	if idx < len(sst.records) && sst.records[idx].key == key {
		return sst.records[idx], true
	}
	return internalRecord{}, false
}

func (e *Engine) Get(key []byte) ([]byte, bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, false, errors.New("engine closed")
	}

	kstr := string(key)
	if rec, ok := e.mem[kstr]; ok {
		if rec.tombstone {
			return nil, false, nil
		}
		out := make([]byte, len(rec.value))
		copy(out, rec.value)
		return out, true, nil
	}

	for i := len(e.l0) - 1; i >= 0; i-- {
		sst := e.l0[i]
		if !sst.bloom.mayContain(key) {
			e.bloomMisses.Add(1)
			continue
		}
		e.bloomHits.Add(1)
		if rec, ok := searchSSTable(sst, kstr); ok {
			if rec.tombstone {
				return nil, false, nil
			}
			out := make([]byte, len(rec.value))
			copy(out, rec.value)
			return out, true, nil
		}
	}

	for i := len(e.l1) - 1; i >= 0; i-- {
		sst := e.l1[i]
		if !sst.bloom.mayContain(key) {
			e.bloomMisses.Add(1)
			continue
		}
		e.bloomHits.Add(1)
		if rec, ok := searchSSTable(sst, kstr); ok {
			if rec.tombstone {
				return nil, false, nil
			}
			out := make([]byte, len(rec.value))
			copy(out, rec.value)
			return out, true, nil
		}
	}

	return nil, false, nil
}

func (e *Engine) Scan(startKey, endKey []byte) ([]KVEntry, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, errors.New("engine closed")
	}

	start := string(startKey)
	end := string(endKey)
	latest := make(map[string]internalRecord)

	inRange := func(k string) bool {
		if start != "" && k < start {
			return false
		}
		if end != "" && k >= end {
			return false
		}
		return true
	}

	for _, sst := range e.l1 {
		for _, r := range sst.records {
			if inRange(r.key) {
				if prev, ok := latest[r.key]; !ok || r.seq >= prev.seq {
					latest[r.key] = r
				}
			}
		}
	}
	for _, sst := range e.l0 {
		for _, r := range sst.records {
			if inRange(r.key) {
				if prev, ok := latest[r.key]; !ok || r.seq >= prev.seq {
					latest[r.key] = r
				}
			}
		}
	}
	for _, r := range e.mem {
		if inRange(r.key) {
			if prev, ok := latest[r.key]; !ok || r.seq >= prev.seq {
				latest[r.key] = r
			}
		}
	}

	out := make([]KVEntry, 0, len(latest))
	for _, r := range latest {
		if !r.tombstone {
			vcopy := make([]byte, len(r.value))
			copy(vcopy, r.value)
			out = append(out, KVEntry{Key: []byte(r.key), Value: vcopy})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Key, out[j].Key) < 0
	})
	return out, nil
}

func (e *Engine) Compact() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}
	return e.compactLocked()
}

func (e *Engine) Stats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Stats{
		MemtableBytes:        e.memBytes,
		NumSSTablesL0:        len(e.l0),
		NumSSTablesL1:        len(e.l1),
		BloomHits:            e.bloomHits.Load(),
		BloomMisses:          e.bloomMisses.Load(),
		CompactionsCompleted: e.compactionsCompleted.Load(),
	}
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.walFile != nil {
		_ = e.walFile.Sync()
		return e.walFile.Close()
	}
	return nil
}
GOEOF

go test -race ./...
