import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent
IDP = BACKEND.parent / "idp"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(IDP))

# The IdP reads its database and key paths from the environment at import
# time, so point them at a throwaway directory before anything imports it.
_tmp = tempfile.mkdtemp(prefix="lab04-idp-")
os.environ["LAB_IDP_DB"] = str(Path(_tmp) / "idp.db")
os.environ["LAB_IDP_KEY"] = str(Path(_tmp) / "idp-key.pem")

from app.db import reset_db, DB_PATH  # noqa: E402

reset_db(DB_PATH)

from app import oidc_client  # noqa: E402
from app.main import app, conn  # noqa: E402
from lab_idp import main as idp_main  # noqa: E402

# The app talks to the IdP over HTTP. In tests both live in this process:
# the app's HTTP client is the IdP's own ASGI app, so no ports are needed.
_idp_http = TestClient(idp_main.app, follow_redirects=False)
oidc_client.set_http_client(_idp_http)


@pytest.fixture()
def client():
    return TestClient(app, follow_redirects=False)


@pytest.fixture()
def idp():
    return _idp_http


@pytest.fixture()
def idp_module():
    return idp_main


@pytest.fixture()
def db_conn():
    return conn


@pytest.fixture()
def new_username():
    return f"user-{uuid.uuid4().hex[:8]}"
