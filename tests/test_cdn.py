from src.core.cdn import ip_in_cloudflare_range, detect_cdn


def test_cloudflare_ip_detected():
    # 104.16.0.1 ada di range 104.16.0.0/13
    assert ip_in_cloudflare_range("104.16.0.1") is True


def test_non_cloudflare_ip_not_detected():
    assert ip_in_cloudflare_range("8.8.8.8") is False


def test_invalid_ip_returns_false():
    assert ip_in_cloudflare_range("bukan-ip") is False


def test_detect_cdn_by_ip():
    assert detect_cdn(ip="172.64.0.5") == "Cloudflare"


def test_detect_cdn_by_server_header():
    assert detect_cdn(ip="8.8.8.8", headers={"Server": "cloudflare"}) == "Cloudflare"


def test_detect_cdn_by_cf_ray_header():
    assert detect_cdn(ip="8.8.8.8", headers={"CF-RAY": "abc123"}) == "Cloudflare"


def test_detect_cdn_none_when_clean():
    assert detect_cdn(ip="8.8.8.8", headers={"Server": "nginx"}) is None
