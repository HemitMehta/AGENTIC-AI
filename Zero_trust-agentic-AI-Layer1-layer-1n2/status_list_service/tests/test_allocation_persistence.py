import pytest
from unittest.mock import AsyncMock, MagicMock

from services import bitstring_manager as manager


def result(value):
    row = MagicMock()
    row.mappings.return_value.first.return_value = value
    row.mappings.return_value.one.return_value = value
    return row


@pytest.mark.asyncio
async def test_allocation_persists_mapping_before_commit(monkeypatch):
    session = AsyncMock()
    session.execute.side_effect = [result(None), result(None), result(None),
                                  result({"id": "list-id", "next_free_index": 7}),
                                  result(None), result(None)]
    monkeypatch.setattr(manager, "get_session", lambda: session)
    url, index = await manager.allocate_status_entry("did:issuer", "urn:uuid:credential")
    assert index == 7 and url.endswith("/list-id")
    insert = session.execute.call_args_list[-1]
    assert "INSERT INTO status_list_entries" in str(insert.args[0])
    assert insert.args[1]["vc"] == "urn:uuid:credential"
    session.commit.assert_awaited_once()
    session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_allocation_retry_reuses_original_mapping(monkeypatch):
    session = AsyncMock()
    session.execute.side_effect = [result(None), result({"issuer_did": "did:issuer",
                                                        "status_list_url": "https://status/list", "bit_index": 7})]
    monkeypatch.setattr(manager, "get_session", lambda: session)
    assert await manager.allocate_status_entry("did:issuer", "vc") == ("https://status/list", 7)
    session.commit.assert_not_awaited()
