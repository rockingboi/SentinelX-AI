"""
SentinelX AI — Abstract BaseParser
=====================================
Defines the interface contract that every log parser must implement.

Design Principles:
- Interface Segregation: parsers only implement what they need
- Single Responsibility: each parser handles exactly one log format
- Open/Closed: new formats are added by extending, not modifying
- Liskov Substitution: any parser can replace another in the registry

All parsers MUST:
1. Inherit from BaseParser
2. Declare a class-level LOG_TYPE (LogType enum value)
3. Implement can_parse() — returns 0.0–1.0 confidence score
4. Implement parse_line() — converts one raw line to NormalizedEvent | None
5. NOT raise exceptions for unparseable lines — return None instead
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Iterator

from backend.models.security_log import LogType
from backend.schemas.logs import NormalizedEvent

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for all SentinelX log parsers.

    The pipeline calls:
        1. parser.can_parse(raw_content)   → float confidence 0.0–1.0
        2. parser.parse(raw_content)       → Iterator[NormalizedEvent]

    Parsers must be stateless — a single instance is reused across requests.
    """

    # Every concrete parser must declare its log type
    LOG_TYPE: LogType = LogType.UNKNOWN

    # Maximum line length before truncation (defence against malformed logs)
    MAX_LINE_LENGTH: int = 32_768  # 32 KB per line

    # Lines to sample for detection heuristics
    DETECTION_SAMPLE_LINES: int = 20

    # -------------------------------------------------------------------------
    # Abstract interface — must be implemented by concrete parsers
    # -------------------------------------------------------------------------

    @abstractmethod
    def can_parse(self, raw_content: str) -> float:
        """
        Examine the raw log content and return a confidence score.

        Args:
            raw_content: The full raw text of the uploaded log file.

        Returns:
            Float in [0.0, 1.0] — 0.0 = definitely not this format,
            1.0 = definitely this format.

        The LogTypeDetector calls this on all registered parsers and picks
        the highest-scoring one. Scores above 0.5 are considered a match.
        """
        ...

    @abstractmethod
    def parse_line(
        self,
        line: str,
        line_number: int,
    ) -> NormalizedEvent | None:
        """
        Parse a single log line into a NormalizedEvent.

        Args:
            line: The raw log line (already stripped).
            line_number: 1-based line number within the file.

        Returns:
            NormalizedEvent if the line was successfully parsed,
            None if the line should be skipped (comment, blank, header, etc.)

        MUST NOT raise exceptions — catch internally and return None.
        """
        ...

    # -------------------------------------------------------------------------
    # Concrete methods — shared by all parsers
    # -------------------------------------------------------------------------

    def parse(self, raw_content: str) -> Iterator[NormalizedEvent]:
        """
        Parse all lines in the raw content and yield NormalizedEvents.

        Iterates line by line, calling parse_line() for each non-empty line.
        Skips blank lines and lines exceeding MAX_LINE_LENGTH.
        Logs warnings for parse failures but never raises.

        Args:
            raw_content: The full raw text of the log file.

        Yields:
            NormalizedEvent for each successfully parsed line.
        """
        lines = raw_content.splitlines()
        total = len(lines)
        parsed = 0
        skipped = 0
        errors = 0

        logger.debug(
            "Parser %s starting — log_type=%s lines=%d",
            self.__class__.__name__,
            self.LOG_TYPE.value,
            total,
        )

        for line_number, raw_line in enumerate(lines, start=1):
            # Skip empty lines
            if not raw_line.strip():
                skipped += 1
                continue

            # Truncate excessively long lines (defence against log injection)
            if len(raw_line) > self.MAX_LINE_LENGTH:
                logger.warning(
                    "Line %d exceeds MAX_LINE_LENGTH (%d) — truncating",
                    line_number,
                    self.MAX_LINE_LENGTH,
                )
                raw_line = raw_line[: self.MAX_LINE_LENGTH]

            try:
                event = self.parse_line(raw_line, line_number)
                if event is not None:
                    parsed += 1
                    yield event
                else:
                    skipped += 1
            except Exception as exc:
                errors += 1
                logger.warning(
                    "Parser %s failed on line %d: %s",
                    self.__class__.__name__,
                    line_number,
                    exc,
                    exc_info=False,
                )

        logger.info(
            "Parser %s complete — parsed=%d skipped=%d errors=%d",
            self.__class__.__name__,
            parsed,
            skipped,
            errors,
        )

    def _sample_lines(self, raw_content: str) -> list[str]:
        """
        Return the first N non-empty lines for detection heuristics.
        Used by can_parse() implementations.
        """
        lines = []
        for line in raw_content.splitlines():
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
            if len(lines) >= self.DETECTION_SAMPLE_LINES:
                break
        return lines

    def _count_pattern_matches(
        self,
        lines: list[str],
        pattern: "re.Pattern",  # type: ignore[name-defined]  # noqa: F821
    ) -> int:
        """Count how many lines match a compiled regex pattern."""
        return sum(1 for line in lines if pattern.search(line))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} log_type={self.LOG_TYPE.value!r}>"
