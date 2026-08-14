"""
SentinelX AI — Parser Registry
=================================
Maps LogType values to their concrete parser implementations.

Design:
- Singleton registry instantiated once at module import
- Parsers self-register via the @register_parser decorator
- Registry is immutable after all parsers are registered
- Lookup is O(1) by LogType

Usage:
    from backend.nlp.parsers.registry import parser_registry

    parser = parser_registry.get(LogType.LINUX_SYSLOG)
    events = list(parser.parse(raw_content))

Registration (in concrete parser modules):
    @register_parser
    class LinuxSyslogParser(BaseParser):
        LOG_TYPE = LogType.LINUX_SYSLOG
        ...
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from backend.models.security_log import LogType

if TYPE_CHECKING:
    from backend.nlp.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class ParserRegistry:
    """
    Singleton registry mapping LogType → BaseParser instance.

    Thread-safe for reads. All registrations happen at module
    import time (before any requests), so no locking is needed.
    """

    def __init__(self) -> None:
        self._registry: dict[LogType, "BaseParser"] = {}

    def register(self, parser_class: type["BaseParser"]) -> type["BaseParser"]:
        """
        Register a parser class and store a singleton instance.

        Called by the @register_parser decorator — never call directly.

        Args:
            parser_class: A concrete BaseParser subclass.

        Returns:
            The same class (decorator passthrough).

        Raises:
            ValueError: If a parser for the same LogType is already registered.
        """
        log_type: LogType = parser_class.LOG_TYPE

        if log_type == LogType.UNKNOWN:
            raise ValueError(
                f"Parser {parser_class.__name__} must declare a valid LOG_TYPE "
                f"(not LogType.UNKNOWN)."
            )

        if log_type in self._registry:
            existing = self._registry[log_type].__class__.__name__
            raise ValueError(
                f"LogType.{log_type.value} is already registered by "
                f"{existing}. Cannot register {parser_class.__name__} twice."
            )

        instance = parser_class()
        self._registry[log_type] = instance
        logger.debug(
            "Registered parser: %s → LogType.%s",
            parser_class.__name__,
            log_type.value,
        )
        return parser_class

    def get(self, log_type: LogType) -> "BaseParser | None":
        """
        Return the parser instance for a given LogType.

        Args:
            log_type: The detected or specified log format.

        Returns:
            BaseParser instance, or None if no parser is registered.
        """
        return self._registry.get(log_type)

    def get_or_raise(self, log_type: LogType) -> "BaseParser":
        """
        Return the parser instance for a given LogType or raise ValueError.

        Args:
            log_type: The detected or specified log format.

        Returns:
            BaseParser instance.

        Raises:
            ValueError: If no parser is registered for this LogType.
        """
        parser = self._registry.get(log_type)
        if parser is None:
            registered = [t.value for t in self._registry]
            raise ValueError(
                f"No parser registered for LogType.{log_type.value}. "
                f"Registered types: {registered}"
            )
        return parser

    def all_parsers(self) -> list["BaseParser"]:
        """Return all registered parser instances."""
        return list(self._registry.values())

    def registered_types(self) -> list[LogType]:
        """Return all registered LogType values."""
        return list(self._registry.keys())

    def __len__(self) -> int:
        return len(self._registry)

    def __repr__(self) -> str:
        types = [t.value for t in self._registry]
        return f"<ParserRegistry registered={types}>"


# =============================================================================
# Module-level singleton — import and use this directly
# =============================================================================

parser_registry = ParserRegistry()


def register_parser(cls: type["BaseParser"]) -> type["BaseParser"]:
    """
    Class decorator that registers a parser with the global registry.

    Usage:
        @register_parser
        class MyParser(BaseParser):
            LOG_TYPE = LogType.MY_FORMAT
    """
    return parser_registry.register(cls)
