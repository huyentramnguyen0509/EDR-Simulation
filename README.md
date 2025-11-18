# EDR Simulation Tool - LockBit 3.0 Detection

## Overview
This repository hosts a Python-based EDR (Endpoint Detection and Response) Simulation tool.

It performs Static Analysis on Portable Executable (PE) files to identify indicators of compromise (IOCs) associated with LockBit 3.0 Ransomware, specifically targeting its packing and anti-analysis techniques.

## Detection Logic
The tool utilizes a heuristic scoring system based on three key vectors:

1.  High Entropy Detection:
    * Calculates Shannon Entropy of the file.
    * High values (> 6.3) indicate packed or encrypted code sections, a common behavior in modern ransomware.

2.  Opcode Pattern Matching:
    * Scans raw bytes to detect specific Assembly instruction sequences unique to the LockBit 3.0 Loader/Unpacker mechanism.
    * Signatures included: INDIRECT_PEB_ACCESS, HEX_TO_BIN_UPPER_CORE, etc.

3.  Anti-Debug API Scanning:
    * Inspects the Import Address Table (IAT) for known evasion APIs used to detect debuggers or sandboxes (e.g., IsDebuggerPresent, NtGlobalFlags).

## Prerequisites
To run this tool, you need Python 3.x and the following libraries:
* pefile (for parsing PE headers)
* psutil (for process and system monitoring utilities)

You can install the dependencies using pip:

```bash
pip install pefile psutil
