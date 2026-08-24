"""Deterministic random and smart-field mutation operators."""

from __future__ import annotations

import random
from collections.abc import Iterator

from .models import MutationResult, SensitiveField
from .pcap import detect_sensitive_fields

BOUNDARY_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)


class Mutator:
    def __init__(self, random_seed: int = 1337, smart_selection: bool = True) -> None:
        self.random = random.Random(random_seed)
        self.smart_selection = smart_selection

    def bit_flip(
        self, data: bytes, offset: int | None = None, bit: int | None = None
    ) -> MutationResult:
        if not data:
            raise ValueError("Cannot mutate an empty seed")
        offset = self.random.randrange(len(data)) if offset is None else offset
        bit = self.random.randrange(8) if bit is None else bit
        if not 0 <= offset < len(data) or not 0 <= bit < 8:
            raise ValueError("Invalid bit-flip position")
        changed = bytearray(data)
        changed[offset] ^= 1 << bit
        return MutationResult(bytes(changed), "bit-flip", (offset,), reason=f"flipped bit {bit}")

    def byte_mutation(self, data: bytes, offset: int | None = None) -> MutationResult:
        if not data:
            raise ValueError("Cannot mutate an empty seed")
        offset = self.random.randrange(len(data)) if offset is None else offset
        changed = bytearray(data)
        choices = [value for value in BOUNDARY_BYTES if value != changed[offset]]
        changed[offset] = self.random.choice(choices)
        return MutationResult(bytes(changed), "byte-boundary", (offset,), reason="boundary value")

    def length_mutation(self, data: bytes, field: SensitiveField) -> MutationResult:
        changed = bytearray(data)
        end = min(len(changed), field.offset + field.length)
        replacement = ((1 << (8 * (end - field.offset))) - 1).to_bytes(end - field.offset, "big")
        changed[field.offset : end] = replacement
        return MutationResult(
            bytes(changed),
            "smart-field",
            tuple(range(field.offset, end)),
            field.score,
            ", ".join(field.reasons),
        )

    def generate(self, seed: bytes, count: int) -> Iterator[MutationResult]:
        """Yield a balanced mix of bit, byte, and sensitive-field mutations."""
        for index in range(count):
            yield self.mutate(seed, index)

    def mutate(self, seed: bytes, index: int) -> MutationResult:
        """Create mutation number ``index`` while rotating through all operators."""
        fields = detect_sensitive_fields(seed) if self.smart_selection else []
        if fields and index % 3 == 2:
            field = fields[(index // 3) % len(fields)]
            return self.length_mutation(seed, field)
        if index % 3 == 0:
            return self.bit_flip(seed)
        return self.byte_mutation(seed)
