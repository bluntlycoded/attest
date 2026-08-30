"""Adapters turning real agent traffic into :class:`attest.Envelope` values.

The core library has no dependencies. Adapters do - a SAMACP envelope cannot be
checked without Ed25519, JWT and JSON-LD canonicalisation - so each adapter
imports its own requirements lazily and raises a clear message if the extra was
not installed.

Install with::

    pip install -e ".[samacp]"
"""

from .samacp import AnsClient, SamacpAdapter, VerificationOutcome

__all__ = ["AnsClient", "SamacpAdapter", "VerificationOutcome"]
