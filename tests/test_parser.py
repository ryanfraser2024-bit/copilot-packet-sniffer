import argparse

import pytest
from scapy.all import DNS, DNSQR, Ether, IP, IPv6, Raw, TCP, UDP

from sniffer import _http_details, decode_packet, packet_limit


def test_decode_ipv4_tcp_and_masked_addresses() -> None:
	packet = (
		Ether()
		/ IP(src="192.168.1.42", dst="10.20.30.40")
		/ TCP(sport=12345, dport=8000)
	)

	record = decode_packet(packet)

	assert record["link"] == "ethernet"
	assert record["network"] == "ipv4"
	assert record["transport"] == "tcp"
	assert record["source"] == "192.168.1.xxx"
	assert record["destination"] == "10.20.30.xxx"
	assert record["source_port"] == 12345
	assert record["destination_port"] == 8000


def test_decode_ipv6() -> None:
	packet = IPv6(src="2001:db8::42", dst="2001:db8::99") / TCP(sport=443, dport=5000)

	record = decode_packet(packet)

	assert record["network"] == "ipv6"
	assert record["source"] == "2001:db8::xxxx"
	assert record["destination"] == "2001:db8::xxxx"


def test_decode_udp() -> None:
	packet = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=53000, dport=53)

	record = decode_packet(packet)

	assert record["transport"] == "udp"
	assert record["source_port"] == 53000
	assert record["destination_port"] == 53


def test_decode_dns_query_name() -> None:
	packet = IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=53000, dport=53) / DNS(
		qd=DNSQR(qname="training.example.test")
	)

	record = decode_packet(packet)

	assert record["dns_query"] == "training.example.test"


def test_decode_http_get_redacts_path_query_and_headers() -> None:
	payload = (
		"GET /search?topic=training&token=fake-token HTTP/1.1\r\n"
		"Host: example.test\r\n"
		"Authorization: Bearer fake-auth\r\n"
		"Cookie: session=fake-session\r\n"
		"X-Contact: student@example.test\r\n"
		"\r\n"
	)
	packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=5000, dport=80) / Raw(load=payload)

	record = decode_packet(packet)
	http = record["http"]

	assert http["method"] == "GET"
	assert http["host"] == "example.test"
	assert http["path"] == "/search?topic=training&token=%5BREDACTED%5D"
	assert http["headers"]["Authorization"] == "[REDACTED]"
	assert http["headers"]["Cookie"] == "[REDACTED]"
	assert http["headers"]["X-Contact"] == "[REDACTED_EMAIL]"


def test_loopback_identification_without_ethernet() -> None:
	from scapy.all import Loopback

	loopback_packet = Loopback() / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=1000, dport=1001)
	assert decode_packet(loopback_packet)["link"] == "loopback"

	raw_packet = IP(src="192.0.2.10", dst="192.0.2.11") / UDP(sport=1000, dport=1001)
	assert decode_packet(raw_packet)["link"] == "raw-or-unknown"


@pytest.mark.parametrize("value", ["0", "-1", "26", "100"])
def test_packet_limit_rejects_counts_outside_safe_range(value: str) -> None:
	with pytest.raises(argparse.ArgumentTypeError):
		packet_limit(value)
