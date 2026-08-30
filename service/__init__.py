"""HTTP service wrapping the Attest engine.

Run with::

    uvicorn service.app:app --reload

Environment:
    ATTEST_DB: SQLite path. Defaults to ``attest.db``.
    ATTEST_ANS_URL: Agent Name Service base URL for the SAMACP adapter.
    ATTEST_CORS_ORIGINS: Comma-separated allowed origins for the console.
"""

from .state import ServiceState, Verifiers

__all__ = ["ServiceState", "Verifiers"]
