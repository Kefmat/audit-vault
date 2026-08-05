"""Abstract base class for storage drivers."""

from abc import ABC, abstractmethod
from typing import List, Optional
from src.types import AuditEvent, VerificationResult


class VaultStorage(ABC):

    @abstractmethod
    def append_event(self, event: AuditEvent) -> AuditEvent:
        """Appends an event to the vault chain after populating hashes."""
        pass

    @abstractmethod
    def get_all_events(self) -> List[AuditEvent]:
        """Returns all events in append order."""
        pass

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """Retrieves a single event by ID."""
        pass

    @abstractmethod
    def verify_integrity(self) -> VerificationResult:
        """Verifies hash-chain continuity and Merkle root calculation."""
        pass
