"""Deterministic random and smart-field mutation operators."""

from __future__ import annotations

import random
from collections.abc import Iterator, Sequence

from .models import MutationResult, SensitiveField
from .pcap import detect_sensitive_fields
from .state_machine import session_token_ranges

BOUNDARY_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)


class Mutator:
    def __init__(
        self,
        random_seed: int = 1337,
        smart_selection: bool = True,
        preserve_session: bool = False,
    ) -> None:
        self.random = random.Random(random_seed)
        self.smart_selection = smart_selection
        self.preserve_session = preserve_session

    def _allowed_offsets(self, data: bytes) -> list[int]:
        """Offsets eligible for mutation, excluding frozen session-token ranges."""
        if not self.preserve_session:
            return list(range(len(data)))
        frozen = session_token_ranges(data)
        allowed = [i for i in range(len(data)) if not any(s <= i < e for s, e in frozen)]
        return allowed or list(range(len(data)))  # never freeze the entire payload

    def bit_flip(
        self,
        data: bytes,
        offset: int | None = None,
        bit: int | None = None,
        allowed: Sequence[int] | None = None,
    ) -> MutationResult:
        if not data:
            raise ValueError("Cannot mutate an empty seed")
        if offset is None:
            pool = list(allowed) if allowed else list(range(len(data)))
            offset = self.random.choice(pool)
        bit = self.random.randrange(8) if bit is None else bit
        if not 0 <= offset < len(data) or not 0 <= bit < 8:
            raise ValueError("Invalid bit-flip position")
        changed = bytearray(data)
        changed[offset] ^= 1 << bit
        return MutationResult(bytes(changed), "bit-flip", (offset,), reason=f"flipped bit {bit}")

    def byte_mutation(
        self, data: bytes, offset: int | None = None, allowed: Sequence[int] | None = None
    ) -> MutationResult:
        if not data:
            raise ValueError("Cannot mutate an empty seed")
        if offset is None:
            pool = list(allowed) if allowed else list(range(len(data)))
            offset = self.random.choice(pool)
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
        allowed = self._allowed_offsets(seed)
        frozen = session_token_ranges(seed) if self.preserve_session else []
        fields = detect_sensitive_fields(seed) if self.smart_selection else []
        if frozen:  # keep session tokens intact: drop sensitive fields overlapping them
            fields = [
                f
                for f in fields
                if not any(s < f.offset + f.length and f.offset < e for s, e in frozen)
            ]
        if fields and index % 3 == 2:
            field = fields[(index // 3) % len(fields)]
            return self.length_mutation(seed, field)
        if index % 3 == 0:
            return self.bit_flip(seed, allowed=allowed)
        return self.byte_mutation(seed, allowed=allowed)
