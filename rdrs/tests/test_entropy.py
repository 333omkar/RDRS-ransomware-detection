import os

from app.core.entropy import shannon_entropy


def test_empty_data_is_zero_entropy():
    assert shannon_entropy(b"") == 0.0


def test_uniform_single_byte_is_zero_entropy():
    assert shannon_entropy(b"aaaaaaaaaa") == 0.0


def test_text_has_low_entropy():
    text = b"the quick brown fox jumps over the lazy dog " * 20
    entropy = shannon_entropy(text)
    assert 0.0 <= entropy <= 5.0


def test_random_bytes_have_high_entropy():
    random_data = os.urandom(20000)
    entropy = shannon_entropy(random_data)
    assert entropy >= 7.5


def test_entropy_bounds():
    random_data = os.urandom(5000)
    entropy = shannon_entropy(random_data)
    assert 0.0 <= entropy <= 8.0
