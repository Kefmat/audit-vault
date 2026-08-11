"""HTTP REST API server for Audit Vault."""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional

from src.storage.base import VaultStorage
from src.types import AuditEvent, MerkleProof
from src.merkle import MerkleTree


class AuditVaultRequestHandler(BaseHTTPRequestHandler):
    storage: VaultStorage = None  # Injected before server start
    api_token: Optional[str] = None  # Injected bearer token requirement

    def _send_response_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _check_auth(self) -> bool:
        if not self.api_token:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            return token == self.api_token
        return False

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query_params = parse_qs(parsed_url.query)

        if path == "/health":
            self._send_response_json(200, {
                "status": "healthy",
                "service": "audit-vault",
                "version": "1.0.0"
            })
            return

        if not self._check_auth():
            self._send_response_json(401, {"error": "Unauthorized", "message": "Invalid or missing Bearer token"})
            return

        if path == "/v1/audit/export":
            format_val = query_params.get("format", ["json"])[0].lower()
            actor_filter = query_params.get("actor", [None])[0]
            action_filter = query_params.get("action", [None])[0]
            since_val = query_params.get("since", [None])[0]
            until_val = query_params.get("until", [None])[0]

            try:
                since = float(since_val) if since_val is not None else None
                until = float(until_val) if until_val is not None else None
            except ValueError:
                self._send_response_json(400, {
                    "error": "Bad Request",
                    "message": "Invalid format for numeric query parameters (since, until)."
                })
                return

            events = self.storage.get_all_events(
                actor=actor_filter,
                action=action_filter,
                since=since,
                until=until
            )

            if format_val == "csv":
                import io
                import csv
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["event_id", "actor", "action", "target", "timestamp", "previous_hash", "hash", "metadata"])
                for e in events:
                    writer.writerow([e.event_id, e.actor, e.action, e.target, e.timestamp, e.previous_hash, e.hash, json.dumps(e.metadata)])
                
                body = output.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", "attachment; filename=audit_export.csv")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                self._send_response_json(200, {
                    "format": "json",
                    "total": len(events),
                    "events": [e.to_dict() for e in events]
                })
                return

        if path == "/v1/audit/events":
            actor_filter = query_params.get("actor", [None])[0]
            action_filter = query_params.get("action", [None])[0]

            since_val = query_params.get("since", [None])[0]
            until_val = query_params.get("until", [None])[0]
            limit_val = query_params.get("limit", [None])[0]
            offset_val = query_params.get("offset", [None])[0]

            try:
                since = float(since_val) if since_val is not None else None
                until = float(until_val) if until_val is not None else None
                limit = int(limit_val) if limit_val is not None else None
                offset = int(offset_val) if offset_val is not None else 0
            except ValueError:
                self._send_response_json(400, {
                    "error": "Bad Request",
                    "message": "Invalid format for numeric query parameters (since, until, limit, offset)."
                })
                return

            matching_events = self.storage.get_all_events(
                actor=actor_filter,
                action=action_filter,
                since=since,
                until=until
            )

            paginated_events = self.storage.get_all_events(
                actor=actor_filter,
                action=action_filter,
                since=since,
                until=until,
                limit=limit,
                offset=offset
            )

            self._send_response_json(200, {
                "total": len(matching_events),
                "count": len(paginated_events),
                "offset": offset,
                "limit": limit,
                "events": [e.to_dict() for e in paginated_events]
            })
            return

        if path.startswith("/v1/audit/events/") and path.endswith("/proof"):
            event_id = path[len("/v1/audit/events/"): -len("/proof")]
            proof = self.storage.get_proof_for_event(event_id)
            if not proof:
                self._send_response_json(404, {"error": "Not Found", "message": f"Proof for event {event_id} not found"})
                return
            self._send_response_json(200, proof.to_dict())
            return

        if path.startswith("/v1/audit/events/"):
            event_id = path.replace("/v1/audit/events/", "")
            event = self.storage.get_event_by_id(event_id)
            if not event:
                self._send_response_json(404, {"error": "Not Found", "message": f"Event {event_id} not found"})
                return
            self._send_response_json(200, event.to_dict())
            return

        if path == "/v1/audit/verify":
            verification = self.storage.verify_integrity()
            self._send_response_json(200 if verification.valid else 409, verification.to_dict())
            return

        if path.startswith("/v1/audit/proof/"):
            try:
                index_str = path.replace("/v1/audit/proof/", "")
                index = int(index_str)
                events = self.storage.get_all_events()
                hashes = [e.hash for e in events]
                tree = MerkleTree(hashes)
                proof = tree.get_proof(index)
                if not proof:
                    self._send_response_json(404, {"error": "Not Found", "message": f"Proof index {index} out of bounds"})
                    return
                self._send_response_json(200, proof.to_dict())
            except ValueError:
                self._send_response_json(400, {"error": "Bad Request", "message": "Index must be an integer"})
            return

        self._send_response_json(404, {"error": "Not Found", "message": f"Endpoint {path} not recognized"})

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if not self._check_auth():
            self._send_response_json(401, {"error": "Unauthorized", "message": "Invalid or missing Bearer token"})
            return

        if path == "/v1/audit/proof/verify":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_response_json(400, {"error": "Bad Request", "message": "Empty request body"})
                return

            try:
                body_bytes = self.rfile.read(content_length)
                data = json.loads(body_bytes.decode("utf-8"))
                raw_proof = data.get("proof", data)
                proof = MerkleProof(
                    leaf_hash=raw_proof["leaf_hash"],
                    root_hash=raw_proof["root_hash"],
                    proof=raw_proof["proof"]
                )
                valid = MerkleTree.verify_proof(proof)
                self._send_response_json(200, {
                    "valid": valid,
                    "message": "Merkle proof is valid" if valid else "Merkle proof verification failed"
                })
            except Exception as err:
                self._send_response_json(400, {"error": "Bad Request", "message": str(err)})
            return

        if path == "/v1/audit/events/bulk":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_response_json(400, {"error": "Bad Request", "message": "Empty request body"})
                return

            try:
                body_bytes = self.rfile.read(content_length)
                data = json.loads(body_bytes.decode("utf-8"))

                if not isinstance(data, list):
                    self._send_response_json(400, {
                        "error": "Bad Request",
                        "message": "Request body must be a JSON array of events."
                    })
                    return

                if not data:
                    self._send_response_json(400, {
                        "error": "Bad Request",
                        "message": "Event list cannot be empty."
                    })
                    return

                stored_events = []
                # Append events under lock to preserve order cleanly if it is file-based
                for item in data:
                    if "actor" not in item or "action" not in item or "target" not in item:
                        self._send_response_json(400, {
                            "error": "Bad Request",
                            "message": "Fields 'actor', 'action', and 'target' are required for all events."
                        })
                        return
                    event = AuditEvent.from_dict(item)
                    event.validate()
                    stored_event = self.storage.append_event(event)
                    stored_events.append(stored_event)

                self._send_response_json(201, {
                    "status": "success",
                    "events": [e.to_dict() for e in stored_events]
                })
            except Exception as err:
                self._send_response_json(400, {"error": "Bad Request", "message": str(err)})
            return

        if path == "/v1/audit/events":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_response_json(400, {"error": "Bad Request", "message": "Empty request body"})
                return

            try:
                body_bytes = self.rfile.read(content_length)
                data = json.loads(body_bytes.decode("utf-8"))

                if "actor" not in data or "action" not in data or "target" not in data:
                    self._send_response_json(400, {
                        "error": "Bad Request",
                        "message": "Fields 'actor', 'action', and 'target' are required."
                    })
                    return

                event = AuditEvent.from_dict(data)
                event.validate()
                stored_event = self.storage.append_event(event)

                self._send_response_json(201, {
                    "status": "success",
                    "event": stored_event.to_dict()
                })
            except Exception as err:
                self._send_response_json(400, {"error": "Bad Request", "message": str(err)})
            return

        self._send_response_json(404, {"error": "Not Found", "message": f"Endpoint {path} not recognized"})


def create_server(host: str, port: int, storage: VaultStorage, api_token: Optional[str] = None) -> HTTPServer:
    class ConfiguredHandler(AuditVaultRequestHandler):
        pass

    ConfiguredHandler.storage = storage
    ConfiguredHandler.api_token = api_token
    server = HTTPServer((host, port), ConfiguredHandler)
    return server
