from unittest.mock import AsyncMock

import pytest

from services import selective_disclosure as selection


@pytest.mark.asyncio
async def test_select_only_requested_job_credentials(monkeypatch):
    session = AsyncMock()
    monkeypatch.setattr(selection, "get_session", AsyncMock(return_value=session))
    rows = [(1, "role", ["RoleVC"]), (2, "job-one", ["JITVC"]), (3, "job-two", ["JITVC"])]
    monkeypatch.setattr(selection, "get_credentials_by_type", AsyncMock(return_value=rows))
    selected = await selection.get_credentials_for_presentation("did:worker", ["RoleVC", "JITVC"], ["role", "job-two"])
    assert [row[1] for row in selected] == ["role", "job-two"]
    session.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("ids", [["role", "missing"], ["role"], ["role", "role"]])
async def test_missing_wrong_type_or_duplicate_credentials_rejected(monkeypatch, ids):
    monkeypatch.setattr(selection, "get_session", AsyncMock(return_value=AsyncMock()))
    monkeypatch.setattr(selection, "get_credentials_by_type", AsyncMock(return_value=[(1, "role", ["RoleVC"])]))
    with pytest.raises(ValueError):
        await selection.get_credentials_for_presentation("did:worker", ["RoleVC", "JITVC"], ids)
