"""Small, conservative helpers for removing common sensitive values."""

import ipaddress
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_EMAIL_PATTERN = re.compile(
	r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
	r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
	re.IGNORECASE,
)
_SENSITIVE_QUERY_KEYS = {
	"password",
	"passwd",
	"token",
	"access_token",
	"api_key",
	"apikey",
	"secret",
	"session",
}
_SENSITIVE_HEADERS = {
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
}


def mask_ip(address: str) -> str:
	"""Mask the final IPv4 octet or IPv6 hextet when address is valid."""
	try:
		parsed = ipaddress.ip_address(address)
	except ValueError:
		return address

	if parsed.version == 4:
		return f"{parsed.exploded.rsplit('.', 1)[0]}.xxx"
	return f"{parsed.compressed.rsplit(':', 1)[0]}:xxxx"


def redact_text(text: str) -> str:
	"""Replace email addresses in text with a fixed redaction marker."""
	return _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)


def redact_url(url: str) -> str:
	"""Redact configured sensitive query parameter values in a URL."""
	try:
		parts = urlsplit(url)
	except ValueError:
		return url

	if not parts.query:
		return url

	query = [
		(key, "[REDACTED]")
		if key.lower() in _SENSITIVE_QUERY_KEYS
		else (key, redact_text(value))
		for key, value in parse_qsl(parts.query, keep_blank_values=True)
	]
	return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
	"""Return headers with sensitive header values replaced."""
	return {
		name: "[REDACTED]" if name.lower() in _SENSITIVE_HEADERS else value
		for name, value in headers.items()
	}
