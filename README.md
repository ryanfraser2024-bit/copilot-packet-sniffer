# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Project Overview

This educational project uses Python and Scapy to inspect authorized network packets without retaining complete raw payloads. It decodes useful protocol metadata, masks IP addresses, redacts sensitive values, and writes one JSON object per line for later review.

The project is designed for learning, not surveillance. Capture only traffic that you are explicitly authorized to inspect:

- Your own machine's loopback traffic on `lo`
- An instructor-authorized lab network
- An approved PCAP file

## Learning Goals

- Understand how Ethernet, loopback, IPv4, IPv6, TCP, and UDP layers are represented.
- Identify DNS query names and unencrypted HTTP request metadata.
- Practice safe command-line validation and bounded packet capture.
- Produce structured JSONL output suitable for educational analysis.
- Apply IP masking and sensitive-data redaction before display or storage.

## Features

- IPv4 and IPv6 decoding with masked source and destination addresses
- TCP and UDP protocol and port decoding
- DNS query-name decoding
- Unencrypted HTTP request method, host, and path decoding
- JSONL output, with one decoded packet per line
- IP masking using the required `.xxx` and `:xxxx` formats
- Redaction of email addresses, sensitive URL parameters, and sensitive headers
- Safe offline PCAP analysis
- Live capture restricted to the loopback interface `lo`

## Setup

Python 3.10 or newer is required. Create and activate a virtual environment, then install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Safe Usage

PCAP mode is preferred when capture privileges are unavailable. Use only an approved PCAP file:

```bash
python sniffer.py --mode pcap --pcap approved-lab-capture.pcap --filter "tcp" --count 25 --output report.jsonl
```

For your own machine's loopback traffic, capture only on `lo`:

```bash
python sniffer.py --mode live --iface lo --filter "tcp port 8000" --count 10 --output report.jsonl
```

The program never captures all interfaces. If live capture permission is denied, stop and use PCAP mode instead.

## Command-Line Options

| Option | Description |
| --- | --- |
| `--mode` | Select `live` loopback capture or `pcap` offline analysis. |
| `--iface` | Live interface. Only `lo` is allowed. |
| `--pcap` | Approved input PCAP path required for `--mode pcap`. |
| `--filter` | Select one supported BPF filter. |
| `--count` | Number of packets to inspect; defaults to `25` and must be between `1` and `25`. |
| `--output` | JSONL output file. Standard output is used when omitted. |

### Supported Filters

Only these filters are accepted:

- `tcp`
- `udp`
- `tcp port 80`
- `tcp port 8000`
- `udp port 53`

## Testing

Run the complete test suite from the project root:

```bash
python -m pytest -q
```

Tests use synthetic packet data and do not perform live capture, network access, packet transmission, or file downloads.

## Project Structure

```text
.
├── README.md
├── redaction.py          # IP, text, URL, and header redaction helpers
├── sniffer.py            # Safe CLI, Scapy decoding, and JSONL output
├── requirements.txt      # Python dependencies
├── tests/
│   ├── test_parser.py    # Synthetic Scapy packet-decoding tests
│   └── test_redaction.py # Redaction helper tests
├── captures/             # Approved or local capture files, when used
├── logs/                 # Local project logs, when used
└── report/               # Generated analysis reports, when used
```

## Limitations

- Live capture is limited to the loopback interface `lo`; other interfaces are rejected.
- Packet counts are limited to 25 per run.
- Only the listed filters are supported.
- HTTPS contents cannot be decoded because the application payload is encrypted.
- The tool does not reconstruct complete raw payloads or provide general traffic inspection.
- Decoding is educational and does not replace a full protocol analyzer.

## AI Use Policy

- Use Copilot for boilerplate, CLI parsing, JSON formatting, and unit-test scaffolds.
- Do not ask Copilot to capture other people's traffic, bypass OS permissions, or create stealth, persistence, or activity-hiding features.
- Always use an interface/PCAP allowlist and include redaction.
- Default to PCAP mode if capture privileges are unavailable.

## Copilot Reflection

Copilot's original IP masking output used `.0` for the final IPv4 section. That output was reviewed and changed to the assignment's required `.xxx` format; IPv6 uses `:xxxx` for its final displayed section.
