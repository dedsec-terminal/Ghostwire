"""
ghostwire.text_utils — text transformation and analysis utilities.

Operations: case conversion, reverse, frequency count, Shannon entropy.
"""

import math
from collections import Counter

from ghostwire.cipher_lab import frequency_analysis


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def text_reverse(text: str) -> str:
    return text[::-1]
