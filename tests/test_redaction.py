from redaction import mask_ip, redact_headers, redact_text, redact_url


def test_mask_ip_masks_ipv4_final_section() -> None:
	assert mask_ip("192.168.1.42") == "192.168.1.xxx"


def test_mask_ip_masks_ipv6_final_section() -> None:
	assert mask_ip("2001:db8::42") == "2001:db8::xxxx"


def test_mask_ip_preserves_invalid_input() -> None:
	assert mask_ip("not-an-ip") == "not-an-ip"


def test_redact_text_replaces_email_addresses() -> None:
	assert redact_text("Contact learner@example.test for the exercise.") == (
		"Contact [REDACTED_EMAIL] for the exercise."
	)


def test_redact_text_preserves_ordinary_text() -> None:
	text = "Packet metadata contains no contact details."
	assert redact_text(text) == text


def test_redact_url_redacts_sensitive_query_parameters() -> None:
	url = (
		"https://example.test/resource?password=one&passwd=two&token=three&"
		"access_token=four&api_key=five&apikey=six&secret=seven&session=eight"
	)

	redacted = redact_url(url)

	assert redacted == (
		"https://example.test/resource?password=%5BREDACTED%5D&"
		"passwd=%5BREDACTED%5D&token=%5BREDACTED%5D&"
		"access_token=%5BREDACTED%5D&api_key=%5BREDACTED%5D&"
		"apikey=%5BREDACTED%5D&secret=%5BREDACTED%5D&"
		"session=%5BREDACTED%5D"
	)


def test_redact_url_matches_sensitive_parameters_case_insensitively() -> None:
	assert redact_url("https://example.test/?ToKeN=synthetic") == (
		"https://example.test/?ToKeN=%5BREDACTED%5D"
	)


def test_redact_url_preserves_nonsensitive_query_parameters() -> None:
	url = "https://example.test/?topic=training&count=2"
	assert redact_url(url) == url


def test_redact_headers_redacts_sensitive_headers() -> None:
	headers = {
		"Authorization": "synthetic-auth",
		"Proxy-Authorization": "synthetic-proxy-auth",
		"Cookie": "synthetic-cookie",
		"Set-Cookie": "synthetic-set-cookie",
	}

	assert redact_headers(headers) == {
		"Authorization": "[REDACTED]",
		"Proxy-Authorization": "[REDACTED]",
		"Cookie": "[REDACTED]",
		"Set-Cookie": "[REDACTED]",
	}


def test_redact_headers_preserves_nonsensitive_headers() -> None:
	headers = {"X-Training-Id": "synthetic-42", "Accept": "text/plain"}
	assert redact_headers(headers) == headers
