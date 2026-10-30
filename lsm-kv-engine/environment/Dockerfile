FROM golang:1.22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    jq \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/lsmkv

RUN cat << 'GOMOD' > /workspace/lsmkv/go.mod
module lsmkv

go 1.22
GOMOD

RUN cat << 'STUB' > /workspace/lsmkv/engine.go
package lsmkv

import "errors"

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

type Engine struct{}

func Open(opts Options) (*Engine, error) {
	return nil, errors.New("not implemented")
}

func (e *Engine) Put(key, value []byte) error {
	return errors.New("not implemented")
}

func (e *Engine) Get(key []byte) ([]byte, bool, error) {
	return nil, false, errors.New("not implemented")
}

func (e *Engine) Delete(key []byte) error {
	return errors.New("not implemented")
}

func (e *Engine) Scan(startKey, endKey []byte) ([]KVEntry, error) {
	return nil, errors.New("not implemented")
}

func (e *Engine) Compact() error {
	return errors.New("not implemented")
}

func (e *Engine) Stats() Stats {
	return Stats{}
}

func (e *Engine) Close() error {
	return nil
}
STUB
