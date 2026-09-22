"""Ethical, redacting packet inspection for loopback traffic or PCAP files."""

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from scapy.all import (
	DNS,
	DNSQR,
	Ether,
	IP,
	IPv6,
	Loopback,
	Raw,
	TCP,
	UDP,
	sniff,
)

from redaction import mask_ip, redact_headers, redact_text, redact_url


ALLOWED_FILTERS = ("tcp", "udp", "tcp port 80", "tcp port 8000", "udp port 53")
MAX_PACKET_COUNT = 25


def packet_limit(value: str) -> int:
	"""Parse a packet count in the safe inclusive range from one to 25."""
	try:
		count = int(value)
	except ValueError as exc:
		raise argparse.ArgumentTypeError("count must be an integer from 1 to 25") from exc
	if not 1 <= count <= MAX_PACKET_COUNT:
		raise argparse.ArgumentTypeError("count must be between 1 and 25")
	return count


def build_parser() -> argparse.ArgumentParser:
	"""Build the command-line parser with safe capture defaults."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--mode", choices=("live", "pcap"), default="live")
	parser.add_argument("--iface", default="lo", help="Live interface; only lo is allowed")
	parser.add_argument("--pcap", help="Input PCAP path when --mode pcap is selected")
	parser.add_argument("--filter", choices=ALLOWED_FILTERS, default="tcp")
	parser.add_argument("--count", type=packet_limit, default=25)
	parser.add_argument("--output", type=Path, help="JSONL output file; stdout by default")
	return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
	"""Reject unsafe or incomplete capture configurations."""
	if args.mode == "live" and args.iface != "lo":
		parser.error('live capture is restricted to the loopback interface "lo"')
	if args.mode == "pcap" and not args.pcap:
		parser.error("--pcap is required when --mode pcap is selected")


def _text(value: str) -> str:
	"""Apply text redaction to a decoded string."""
	return redact_text(value)


def _packet_link(packet: Any) -> str:
	"""Identify the observed link layer without retaining packet bytes."""
	if packet.haslayer(Ether):
		return "ethernet"
	if packet.haslayer(Loopback):
		return "loopback"
	return "raw-or-unknown"


def _http_details(packet: Any) -> dict[str, Any] | None:
	"""Decode and redact an unencrypted HTTP request from transient payload data."""
	if not packet.haslayer(Raw):
		return None

	try:
		payload = bytes(packet[Raw].load).decode("latin-1")
	except (TypeError, ValueError):
		return None
	lines = payload.split("\r\n")
	if not lines or not lines[0].startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")):
		return None

	request_parts = lines[0].split(" ", 2)
	if len(request_parts) != 3 or not request_parts[2].startswith("HTTP/"):
		return None
	header_values: dict[str, str] = {}
	for line in lines[1:]:
		if not line:
			break
		name, separator, value = line.partition(":")
		if separator:
			header_values[_text(name.strip())] = _text(value.strip())

	redacted_headers = redact_headers(header_values)
	host = next((value for name, value in redacted_headers.items() if name.lower() == "host"), "")
	path = _text(redact_url(request_parts[1]))
	return {
		"method": _text(request_parts[0]),
		"host": host,
		"path": path,
		"headers": redacted_headers,
	}


def decode_packet(packet: Any) -> dict[str, Any]:
	"""Decode safe packet metadata into one JSON-serializable record."""
	record: dict[str, Any] = {"link": _packet_link(packet)}

	if packet.haslayer(IP):
		record.update(
		{
			"network": "ipv4",
			"source": mask_ip(str(packet[IP].src)),
			"destination": mask_ip(str(packet[IP].dst)),
		}
		)
	elif packet.haslayer(IPv6):
		record.update(
		{
			"network": "ipv6",
			"source": mask_ip(str(packet[IPv6].src)),
			"destination": mask_ip(str(packet[IPv6].dst)),
		}
		)

	if packet.haslayer(TCP):
		record.update({"transport": "tcp", "source_port": int(packet[TCP].sport), "destination_port": int(packet[TCP].dport)})
	elif packet.haslayer(UDP):
		record.update({"transport": "udp", "source_port": int(packet[UDP].sport), "destination_port": int(packet[UDP].dport)})

	if packet.haslayer(DNS) and packet.haslayer(DNSQR):
		query_name = packet[DNSQR].qname
		if isinstance(query_name, bytes):
			query_name = query_name.decode("utf-8", errors="replace")
		record["dns_query"] = _text(str(query_name).rstrip("."))

	http = _http_details(packet)
	if http is not None:
		record["http"] = http

	return record


def write_records(packets: Iterable[Any], output: TextIO) -> None:
	"""Write one redacted JSON object per packet line."""
	for packet in packets:
		output.write(json.dumps(decode_packet(packet), sort_keys=True) + "\n")


def capture(args: argparse.Namespace, output: TextIO) -> int:
	"""Capture from loopback or read a PCAP, then write redacted records."""
	try:
		if args.mode == "pcap":
			packets = sniff(offline=args.pcap, count=args.count, filter=args.filter, promisc=False)
		else:
			packets = sniff(iface="lo", count=args.count, filter=args.filter, promisc=False)
	except (PermissionError, OSError) as exc:
		print(
			f"capture unavailable: {exc}. Use --mode pcap --pcap FILE for offline analysis.",
			file=sys.stderr,
		)
		return 2

	write_records(packets, output)
	return 0


def main(argv: Sequence[str] | None = None) -> int:
	"""Validate arguments, run the selected safe analysis mode, and exit."""
	parser = build_parser()
	args = parser.parse_args(argv)
	validate_args(parser, args)
	if args.output is None:
		return capture(args, sys.stdout)
	try:
		with args.output.open("w", encoding="utf-8") as output:
			return capture(args, output)
	except OSError as exc:
		print(f"cannot open output file: {exc}", file=sys.stderr)
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
