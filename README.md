# Kernel Module Rootkit Detector

Defensive Linux security tool to detect suspicious or unauthorized kernel modules.

## Build

```bash
make
```

## Usage

```bash
# Create a trusted baseline
./detector --create-baseline

# Run a scan and compare against baseline
./detector --scan
```

## Phases

The project is implemented incrementally across 8 phases:

1. Environment Setup and Linux Module Study
2. Kernel Module Scanner
3. Metadata Collection
4. Trusted Baseline
5. Anomaly Detection Engine
6. Risk Scoring
7. CLI and Reporting
8. Testing and Controlled Demonstration

## Team

- Member 1: System Scanner & Baseline
- Member 2: Detection & Reporting