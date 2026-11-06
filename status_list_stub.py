"""
status_list_stub.py
Temporary stub for Sub-System 6 (Status List Service).

Rename to status_list.py ONLY when using this stub locally without SS6.
When Sub-System 6 is delivered, replace with the real status_list.py.

This stub writes nothing to Redis or Kafka. It allocates sequential
bit indices from a simple in-memory counter and returns mock URLs.
For development and unit testing only — not for integration tests.
"""

import uuid

_counter = 0


def allocate_status_entry(vc_id: str, issuer_did: str) -> dict:
    """
    Stub: allocates the next bit index in a mock status list.
    Real implementation in status_list.py (Sub-System 6).

    Returns:
        { "statusListUrl": str, "bitIndex": int }
    """
    global _counter
    _counter += 1
    return {
        "statusListUrl": f"https://status.example.com/lists/stub-list-1",
        "bitIndex":      _counter,
    }


def revoke_entry(vc_id: str, bit_index: int, status_list_url: str) -> None:
    """
    Stub: no-op revocation. Real implementation in Sub-System 6.
    """
    pass
