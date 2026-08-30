import sqlite3

import pytest

from attest.tenancy import KeyStore, Principal, Role, hash_token


@pytest.fixture
def keys():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    return KeyStore(connection, bootstrap_token="boot-secret")


# --------------------------------------------------------------------- roles


def test_roles_are_ordered_by_blast_radius():
    assert Role.ADMIN.allows(Role.APPROVER)
    assert Role.ADMIN.allows(Role.INGEST)
    assert Role.APPROVER.allows(Role.INGEST)
    assert not Role.INGEST.allows(Role.APPROVER)
    assert not Role.APPROVER.allows(Role.ADMIN)


def test_a_principal_refuses_what_it_cannot_do():
    who = Principal(key_id="k", tenant_id="t", role=Role.INGEST)
    who.require(Role.INGEST)
    with pytest.raises(PermissionError, match="cannot act as approver"):
        who.require(Role.APPROVER)


# ---------------------------------------------------------------------- keys


def test_issuing_returns_a_token_that_authenticates(keys):
    issued = keys.issue("acme", Role.APPROVER, label="on-call")
    who = keys.authenticate(issued.token)

    assert who is not None
    assert who.tenant_id == "acme"
    assert who.role is Role.APPROVER
    assert who.label == "on-call"


def test_only_a_digest_is_stored(keys):
    """A stolen database should yield nothing usable."""
    issued = keys.issue("acme", Role.INGEST)
    row = keys._conn.execute(
        "SELECT token_hash FROM api_keys WHERE key_id = ?", (issued.key_id,)
    ).fetchone()

    assert issued.token not in row["token_hash"]
    assert row["token_hash"] == hash_token(issued.token)


def test_listed_keys_never_expose_a_secret(keys):
    keys.issue("acme", Role.INGEST, label="gateway")
    for row in keys.list_keys("acme"):
        assert "token" not in row
        assert "token_hash" not in row


def test_a_tampered_token_is_refused(keys):
    issued = keys.issue("acme", Role.ADMIN)
    assert keys.authenticate(issued.token + "x") is None
    assert keys.authenticate(issued.token[:-1]) is None


@pytest.mark.parametrize(
    "token", [None, "", "garbage", "attest_only_two", "wrongprefix_a_b"]
)
def test_malformed_tokens_are_refused(keys, token):
    assert keys.authenticate(token) is None


def test_an_unknown_key_id_is_refused(keys):
    assert keys.authenticate("attest_deadbeefdeadbeef_whatever") is None


def test_revocation_takes_effect_immediately(keys):
    issued = keys.issue("acme", Role.ADMIN)
    assert keys.authenticate(issued.token) is not None
    assert keys.revoke(issued.key_id, "acme")
    assert keys.authenticate(issued.token) is None


def test_a_tenant_cannot_revoke_another_tenants_key(keys):
    issued = keys.issue("acme", Role.ADMIN)
    assert not keys.revoke(issued.key_id, "globex")
    assert keys.authenticate(issued.token) is not None


def test_keys_are_listed_per_tenant(keys):
    keys.issue("acme", Role.INGEST)
    keys.issue("globex", Role.INGEST)
    assert len(keys.list_keys("acme")) == 1
    assert len(keys.list_keys("globex")) == 1


def test_a_key_must_belong_to_a_tenant(keys):
    with pytest.raises(ValueError, match="must belong to a tenant"):
        keys.issue("", Role.ADMIN)


def test_two_keys_are_never_the_same(keys):
    tokens = {keys.issue("acme", Role.INGEST).token for _ in range(20)}
    assert len(tokens) == 20


# ----------------------------------------------------------------- bootstrap


def test_the_bootstrap_token_is_an_admin_and_is_never_stored(keys):
    who = keys.authenticate("boot-secret")
    assert who is not None and who.role is Role.ADMIN
    assert keys.list_keys(who.tenant_id) == []


def test_without_a_bootstrap_token_an_empty_store_admits_nobody():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    bare = KeyStore(connection)

    assert bare.authenticate("boot-secret") is None
    assert bare.authenticate("") is None
    assert bare.authenticate("attest_a_b") is None


def test_last_used_is_recorded(keys):
    issued = keys.issue("acme", Role.INGEST)
    assert keys.list_keys("acme")[0]["last_used"] is None
    keys.authenticate(issued.token)
    assert keys.list_keys("acme")[0]["last_used"] is not None


def test_tenants_are_discoverable(keys):
    keys.issue("acme", Role.INGEST)
    keys.issue("globex", Role.INGEST)
    found = keys.tenants()
    assert "acme" in found and "globex" in found
    # The bootstrap tenant exists even with no rows in it.
    assert "default" in found
