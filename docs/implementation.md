# Kernel Module Rootkit Detector — Implementation Plan

## Project Overview
**Course:** Operating Systems Lab  
**Team:** 2 Members  
**Primary Language:** C  
**Platform:** Linux  
**Approach:** Defensive kernel-module monitoring and anomaly detection  

The system scans loaded kernel modules, collects module information, compares against a trusted baseline, identifies suspicious changes, assigns a risk score, and produces a detection report.

---

## 1. Project Description
Kernel Module Rootkit Detector is a defensive Linux security tool designed to detect potentially suspicious or unauthorized kernel modules. Since kernel modules execute with high privileges, unexpected modules can represent an important security signal.

The system will inspect standard Linux interfaces such as `/proc/modules` and `/sys/module/` to enumerate loaded modules and collect metadata. A trusted baseline will then be used to identify modules that were not previously expected. Additional heuristics will contribute to a risk score, allowing the detector to classify findings as low, medium, high, or critical risk.

The project will be implemented incrementally so that each phase produces a working component that can be tested before moving to the next phase.

---

## 2. Final System Workflow
```
Linux System
  ↓
Module Scanner
  ↓
Metadata Collector
  ↓
Trusted Baseline Comparison
  ↓
Anomaly Detection
  ↓
Risk Scoring
  ↓
Detection Report
```

---

## 3. Team Division

| Member | Primary Responsibility | Main Tasks |
|--------|----------------------|------------|
| Member 1 | System Scanner & Baseline | Linux module enumeration, /proc and /sys parsing, metadata collection, baseline creation |
| Member 2 | Detection & Reporting | Anomaly rules, risk-scoring engine, CLI, reports, logging, testing and result visualization |

**Both:** Integration & Validation, Architecture decisions, debugging, VM testing, final integration, documentation and presentation.

---

## 4. Implementation Phases

### Phase 1 — Environment Setup and Linux Module Study
**Goal:** Prepare the development environment and understand the Linux interfaces required by the detector.

- Set up an Ubuntu/Linux virtual machine for safe development and testing.
- Install GCC, Make, Git and GDB.
- Study basic kernel-module commands such as `lsmod`, `modinfo`, `insmod`, `rmmod` and `modprobe`.
- Inspect `/proc/modules` and `/sys/module/` manually.
- Define the data fields that the detector will store for each module.

**Milestone:** Linux VM ready and project skeleton builds successfully.

**Member 1:** Explore module information and design the scanner data structure.  
**Member 2:** Set up the repository, build system, CLI structure and initial project documentation.

---

### Phase 2 — Kernel Module Scanner
**Goal:** Build a reliable scanner that identifies currently loaded kernel modules.

- Read `/proc/modules` directly from C.
- Parse module name, size, reference count and dependency information.
- Create a structured representation for each module.
- Display the list of loaded modules through the CLI.
- Handle malformed or unavailable information without crashing.

**Milestone:** The program can list all currently loaded modules.

**Member 1:** Implement `/proc/modules` parsing and module structures.  
**Member 2:** Implement CLI commands and scanner output formatting.

---

### Phase 3 — Metadata Collection
**Goal:** Extend the scanner with additional information for each module.

- Inspect `/sys/module/<module>/` for available information.
- Collect module state and other useful metadata where available.
- Normalize the collected data into a common internal structure.
- Add error handling for fields that are unavailable on a particular Linux version.
- Store scan results in memory for later analysis.

**Milestone:** A complete module record can be generated for each detected module.

**Member 1:** Implement metadata extraction.  
**Member 2:** Validate the collected fields and prepare the analysis data structures.

---

### Phase 4 — Trusted Baseline
**Goal:** Establish a trusted reference state for the system.

- Implement a `--create-baseline` command.
- Save the expected module list and relevant metadata.
- Implement baseline loading and validation.
- Implement comparison between the baseline and the current scan.
- Detect newly appearing and missing modules.

**Milestone:** The system can report modules that differ from the trusted baseline.

**Member 1:** Implement baseline creation, storage and comparison.  
**Member 2:** Design baseline output and test comparison scenarios.

---

### Phase 5 — Anomaly Detection Engine
**Goal:** Determine whether a module deserves further investigation.

- Create a rule-based detection engine.
- Flag modules absent from the trusted baseline.
- Add checks for unexpected metadata.
- Add checks for unexpected module locations where reliable information is available.
- Add checks for abnormal module state.
- Keep each rule independent so the detection system can be extended later.

**Milestone:** The detector produces a list of suspicious modules with specific reasons.

**Member 1:** Provide clean module and baseline data to the analyzer.  
**Member 2:** Implement and test anomaly rules.

---

### Phase 6 — Risk Scoring
**Goal:** Convert detection indicators into an understandable risk level.

- Assign weights to individual anomaly indicators.
- Calculate a total risk score.
- Normalize the score to a 0–100 range if necessary.
- Map scores to LOW, MEDIUM, HIGH and CRITICAL.
- Display the individual indicators contributing to the score.

**Milestone:** Every flagged module receives an explainable risk score.

**Member 2:** Implement the risk engine.  
**Member 1:** Validate scores against controlled test cases and check for false positives.

---

### Phase 7 — CLI and Reporting
**Goal:** Integrate all components into an easy-to-use command-line application.

- Implement `--list`, `--scan`, `--create-baseline`, `--compare` and `--report` commands.
- Create a readable terminal report.
- Include scan time, module count, suspicious modules, scores and reasons.
- Add optional logging for historical scan results.
- Keep output concise enough for a live project demonstration.

**Milestone:** One command can perform a complete scan and produce a final report.

**Member 2:** Lead CLI and reporting implementation.  
**Member 1:** Integrate scanner and baseline components with the CLI.

---

### Phase 8 — Testing and Controlled Demonstration
**Goal:** Verify that the complete system works reliably in a controlled environment.

- Create a clean baseline in the Linux VM.
- Run a scan with no intentional changes.
- Introduce a harmless test module or legitimate module change.
- Run the detector and verify that the change is identified.
- Remove the test change and scan again.
- Measure scan time and basic resource usage.
- Fix false positives and crashes discovered during testing.

**Milestone:** The complete detector successfully identifies the controlled module change and generates a final report.

---

## 5. Recommended Development Schedule

| Week | Phase | Main Output |
|------|-------|-------------|
| 1 | Environment + study | Linux VM, repository, project skeleton |
| 2 | Module scanner | Working `/proc/modules` scanner |
| 3 | Metadata collection | Complete module records |
| 4 | Baseline system | Create/load/compare baseline |
| 5 | Anomaly detection | Detection rules + findings |
| 6 | Risk scoring | 0–100 score + risk levels |
| 7 | CLI + reporting | Integrated detector |
| 8 | Testing + finalization | Validated demo + final documentation |

---

## 6. Core Data Flow

1. Start detector
2. Read `/proc/modules`
3. Collect `/sys/module` metadata
4. Load trusted baseline
5. Compare current state with baseline
6. Run anomaly rules
7. Calculate risk score
8. Generate report

---

## 7. Suggested Final Repository Structure

```
kernel-module-rootkit-detector/
├── src/
│   ├── main.c
│   ├── module_scanner.c
│   ├── module_scanner.h
│   ├── metadata.c
│   ├── metadata.h
│   ├── baseline.c
│   ├── baseline.h
│   ├── analyzer.c
│   ├── analyzer.h
│   ├── risk.c
│   └── risk.h
├── baseline/
│   └── modules.txt
├── tests/
├── reports/
├── Makefile
└── README.md
```

---

## 8. Final Integration Goal

At the end of implementation, the two-person team should have one working executable that follows this workflow:

```
./detector --create-baseline
./detector --scan
```

The first version should prioritize reliability and a clear demonstration over adding too many advanced features. Once the MVP works, optional extensions such as real-time monitoring, module hash verification, signed-module checks, JSON reports, or a dashboard can be added if time permits.

**Implementation Target:** Build a working MVP first: Module Scanner → Metadata → Baseline → Comparison → Anomaly Detection → Risk Score → CLI Report.