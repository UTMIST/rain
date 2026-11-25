"""In-process OpenAPI contract tests for the portal's JSON endpoints."""

from hypothesis import settings
import pytest
import schemathesis
from schemathesis.checks import (
    content_type_conformance,
    not_a_server_error,
    response_schema_conformance,
    status_code_conformance,
)


@pytest.fixture
def api_schema(app):
    return schemathesis.openapi.from_asgi("/openapi.json", app)


@schemathesis.pytest.from_fixture("api_schema").parametrize()
@settings(max_examples=20, deadline=None)
def test_openapi(case):
    case.call_and_validate(checks=[
        not_a_server_error,
        status_code_conformance,
        content_type_conformance,
        response_schema_conformance,
    ])
