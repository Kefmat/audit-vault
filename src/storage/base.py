"""Abstract base class for storage drivers."""

from abc import ABC, abstractmethod
from typing import List, Optional
from src.types import AuditEvent, VerificationResult, MerkleProof


GENESIS_HASH = "GENESIS_BLOCK_PREVIOUS_HASH"


class VaultStorage(ABC):

    @abstractmethod
    def append_event(self, event: AuditEvent) -> AuditEvent:
        """Appends an event to the vault chain after populating hashes."""
        pass

    @abstractmethod
    def get_all_events(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[AuditEvent]:
        """Returns events in append order, with optional filtering and pagination."""
        pass

    @abstractmethod
    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """Retrieves a single event by ID."""
        pass

    @abstractmethod
    def get_proof_for_event(self, event_id: str) -> Optional[MerkleProof]:
        """Generates a Merkle inclusion proof for a given event ID."""
        pass

    @abstractmethod
    def verify_integrity(self) -> VerificationResult:
        """Verifies hash-chain continuity and Merkle root calculation."""
        pass
