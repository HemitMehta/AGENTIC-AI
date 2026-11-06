import base64
import copy
import json
from unittest.mock import AsyncMock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from models.requests import CredentialRequest
from services import revocation_checker as checker


@pytest.mark.asyncio
async def test_fresh_status_signature_and_tampering(monkeypatch):
    key = Ed25519PrivateKey.generate()
    url = "https://status/lists/1"
    data = {"id": url, "credentialSubject": {"statusPurpose": "revocation", "encodedList": "bits"}}
    signature = key.sign(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    data["proof"] = {"proofValue": base64.b64encode(signature).decode()}
    client = AsyncMock()
    client.get_public_key.return_value = {
        "keyStatus": "active",
        "publicKey": base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}
    monkeypatch.setattr(checker, "get_kms_client", lambda: client)
    await checker._verify_status_signature(data, url)
    changed = copy.deepcopy(data)
    changed["credentialSubject"]["encodedList"] = "changed"
    with pytest.raises(InvalidSignature):
        await checker._verify_status_signature(changed, url)
    with pytest.raises(ValueError):
        await checker._verify_status_signature(data, "https://other/list")


@pytest.mark.asyncio
async def test_fresh_status_rejects_arbitrary_url():
    with pytest.raises(ValueError, match="Untrusted"):
        await checker._get_status_list_bitstring("http://127.0.0.1:8200/v1/secrets", fresh=True)


def test_single_credential_representation_required():
    assert CredentialRequest(credential={"id": "vc"}, fresh_status=True).fresh_status
    assert CredentialRequest(vc_jwt="signed").vc_jwt == "signed"
    with pytest.raises(ValidationError):
        CredentialRequest()
    with pytest.raises(ValidationError):
        CredentialRequest(vc_jwt="signed", credential={})
