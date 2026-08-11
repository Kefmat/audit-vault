"""Data models for Audit Vault."""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    actor: str
    action: str
    target: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    previous_hash: str = ""
    hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        """Raises ValueError if required fields are blank or invalid."""
        for field_name in ("actor", "action", "target"):
            val = getattr(self, field_name, "")
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"AuditEvent field '{field_name}' must be a non-empty string.")

        if not isinstance(self.metadata, dict):
            raise ValueError("AuditEvent metadata must be a dictionary.")

        # Validate timestamp is a valid positive number and not in the far future
        if not isinstance(self.timestamp, (int, float)) or self.timestamp <= 0:
            raise ValueError("AuditEvent timestamp must be a positive number.")
        
        # Limit future timestamp to 24 hours
        import time
        if self.timestamp > time.time() + 86400:
            raise ValueError("AuditEvent timestamp cannot be more than 24 hours in the future.")

        # Validate serialization and size
        import json
        try:
            serialized_metadata = json.dumps(self.metadata)
        except (TypeError, ValueError) as e:
            raise ValueError(f"AuditEvent metadata is not JSON serializable: {e}")

        if len(serialized_metadata.encode("utf-8")) > 65536:
            raise ValueError("AuditEvent metadata size exceeds the 64KB limit.")


    def __repr__(self) -> str:
        return (
            f"AuditEvent(event_id={self.event_id!r}, actor={self.actor!r}, "
            f"action={self.action!r}, target={self.target!r})"
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        return cls(
            actor=data["actor"],
            action=data["action"],
            target=data["target"],
            metadata=data.get("metadata", {}),
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", time.time()),
            previous_hash=data.get("previous_hash", ""),
            hash=data.get("hash", "")
        )


@dataclass
class MerkleProof:
    leaf_hash: str
    root_hash: str
    proof: List[Dict[str, str]]  # list of {"position": "left"|"right", "hash": str}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    valid: bool
    total_events: int
    merkle_root: str
    message: str
    tampered_event_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
