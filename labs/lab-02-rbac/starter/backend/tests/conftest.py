import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import reset_db, DB_PATH  # noqa: E402

reset_db(DB_PATH)

from app.main import app, conn  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def db_conn():
    return conn


@pytest.fixture()
def new_username():
    return f"user-{uuid.uuid4().hex[:8]}"
