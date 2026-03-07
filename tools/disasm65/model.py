from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AddressRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start > self.end:
            raise ValueError("start must be less than or equal to end")

    @property
    def size(self) -> int:
        # Inclusive end semantics: [start, end].
        return self.end - self.start + 1

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end


@dataclass(frozen=True)
class Config:
    input_path: Path
    org: int = 0
    control: Path | None = None
    symbols: Path | None = None
    sweet16_heuristic: bool = False
