# FrontierSWE & Cybersecurity Evaluation Tasks

This repository contains two evaluation tasks formatted for the [Harbor](https://github.com/harbor-framework/harbor) evaluation framework and [FrontierSWE](https://www.frontierswe.com/).

## Tasks Overview

### 1. `lsm-kv-engine`
- **Domain**: Long-Horizon Software Engineering (Storage Engines & Distributed Systems)
- **Language**: Go 1.22
- **Description**: A 20-hour engineering task requiring implementation of a crash-safe, concurrent Log-Structured Merge-tree (`lsmkv`) engine. Features binary Write-Ahead Log (WAL) framing with IEEE CRC32 checksums, torn-write corruption tail recovery, immutable L0 SSTable flushing with embedded Bloom filters, leveled compaction with tombstone purging, and race detector compliance (`go test -race`).

### 2. `mcp-gateway-sandbox-hardening`
- **Domain**: Cybersecurity, Incident Response & Tool Gateway Hardening
- **Language**: Python 3.11
- **Description**: An incident response and defense challenge targeting an AI Agent Tool Gateway. The engineer analyzes `/logs/audit.jsonl` to reconstruct an intrusion chain (emitting `forensics_report.json`) and remediates four vulnerability classes in `app.py`: blind SSRF with redirect bypass, JWT `kid` header path traversal, sandbox directory breakout, and command injection.

## Verification & Execution

### 1. Static Rubric Checker (Python 3.11+, Zero Installs)
```bash
python3 frontierswe-check.py lsm-kv-engine
python3 frontierswe-check.py mcp-gateway-sandbox-hardening
```

### 2. Harbor Evaluation Benchmarks
```bash
# Reference solution evaluation (Oracle)
harbor run -p lsm-kv-engine -a oracle
harbor run -p mcp-gateway-sandbox-hardening -a oracle

# Baseline evaluation (Empty Agent)
harbor run -p lsm-kv-engine -a nop
harbor run -p mcp-gateway-sandbox-hardening -a nop
```
