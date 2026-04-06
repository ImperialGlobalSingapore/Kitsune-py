# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Kitsune** is an online, unsupervised network intrusion detection system (NIDS) based on an ensemble of autoencoders. It processes network packets one at a time, learning normal traffic patterns, then flags anomalies via RMSE reconstruction error. Based on the NDSS'18 paper by Mirsky et al.

## Running the Code

```bash
# Quick demo (uses included mirai.zip botnet capture)
python example.py

# Install dependencies manually (no requirements.txt)
pip install numpy scipy scapy matplotlib

# Optional: Install tshark (Wireshark CLI) for faster pcap parsing
sudo dnf install wireshark-cli   # Fedora
```

```python
# Minimal usage
from Kitsune import Kitsune
import numpy as np

K = Kitsune("capture.pcap", np.Inf, max_autoencoder_size=10,
            FM_grace_period=5000, AD_grace_period=50000)
while True:
    rmse = K.proc_next_packet()  # returns -1 when done
    if rmse == -1: break
```

## Building the Cython Accelerator

`AfterImage_extrapolate.pyx` is an optional ~100x faster Cython version of `AfterImage.py`:

```bash
python setup.py build_ext --inplace
```

Toggle between implementations in `FeatureExtractor.py` via `use_extrapolation=True/False` (line 5).

## Architecture

### Data Flow
```
PCAP/PCAPNG/TSV → FeatureExtractor → netStat (AfterImage) → 115-feature vector
                                                                      ↓
                                                              KitNET ensemble
                                                                      ↓
                                                            RMSE anomaly score
```

### Module Responsibilities

| File | Class | Role |
|------|-------|------|
| `Kitsune.py` | `Kitsune` | Top-level orchestrator: wires FE → KitNET |
| `FeatureExtractor.py` | `FE` | Parses pcap via tshark (preferred) or scapy; calls netStat |
| `netStat.py` | `netStat` | AfterImage component; maintains 4 hash tables tracking MAC-IP, host bandwidth, jitter, host-protocol-host flows |
| `AfterImage.py` | `incStat`, `incStat_cov`, `incStatDB` | Incremental exponentially-decayed statistics (weight, mean, std, covariance) |
| `KitNET/KitNET.py` | `KitNET` | Three-phase operation: FM (correlation clustering) → AD training → execution |
| `KitNET/corClust.py` | `corClust` | Builds correlation matrix incrementally; hierarchical clustering assigns features to autoencoders |
| `KitNET/dA.py` | `dA` | Denoising autoencoder with SGD backprop; sigmoid activations; 0-1 normalization |
| `KitNET/utils.py` | — | Sigmoid, tanh, ReLU, softmax, normal distribution utilities |

### KitNET Three-Phase Operation

1. **Feature Mapping (FM_grace_period packets)**: Builds correlation matrix; `corClust.cluster()` partitions the 115 features across ≤`max_autoencoder_size`-feature autoencoders
2. **Anomaly Detection training (AD_grace_period packets)**: Trains each `dA` autoencoder on its assigned features; final output layer `dA` trains on per-AE RMSE scores
3. **Execution**: Each `dA.execute()` returns RMSE; output layer combines into single anomaly score

### AfterImage Statistics

`netStat` uses 5 decay factors `λ ∈ [5, 3, 1, 0.1, 0.01]` to capture multi-timescale patterns. Each `incStat` maintains CF1 (sum) and CF2 (sum of squares) with exponential decay — efficient incremental updates without storing history.

### Packet Parsing

`FeatureExtractor` auto-selects parser:
- **tshark**: Invoked as subprocess, outputs TSV; fastest option
- **scapy**: Pure Python fallback; handles IPv4, IPv6, TCP, UDP, ICMP, ARP
- TSV input: Skip re-parsing if already processed

## Key Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `max_autoencoder_size` | 10 | Max features per AE; higher = fewer AEs, more capacity |
| `FM_grace_period` | 5000 | Packets for feature clustering phase |
| `AD_grace_period` | 50000 | Packets for AE training phase |
| `learning_rate` | 0.1 | SGD learning rate for all `dA` instances |
| `hidden_ratio` | 0.75 | Hidden layer size = `hidden_ratio × input_size` |

## No Test Suite

There is no automated test suite. `example.py` functions as the integration test — it should complete without errors and produce a plot showing low RMSE for benign traffic (first ~70k packets) and elevated RMSE for the Mirai botnet activity.
