"""Tests for BOLA resource-id prefill from OpenAPI specs (api.web helpers)."""

import json

from api.web import _extract_resource_id, _resolve_resource_id


_JSON_SPEC = json.dumps({
    "openapi": "3.0.0",
    "paths": {
        "/users/{userId}": {
            "get": {
                "parameters": [
                    {"name": "userId", "in": "path", "required": True,
                     "example": "42"},
                ],
            },
        },
    },
})

_YAML_SPEC = """
openapi: 3.0.0
paths:
  /orders/{orderId}/items:
    parameters:
      - name: orderId
        in: path
        required: true
        schema:
          default: "ORD-1001"
    get:
      responses:
        '200':
          description: ok
"""

_SWAGGER2 = json.dumps({
    "swagger": "2.0",
    "paths": {
        "/accounts/{account_id}": {
            "delete": {
                "parameters": [
                    {"name": "account_id", "in": "path", "required": True,
                     "schema": {"type": "integer", "default": 7}},
                ],
            },
        },
    },
})


def test_json_operation_example_used():
    assert _extract_resource_id(_JSON_SPEC) == "42"


def test_yaml_path_level_default_used():
    assert _extract_resource_id(_YAML_SPEC) == "ORD-1001"


def test_swagger2_schema_default_coerced_to_string():
    assert _extract_resource_id(_SWAGGER2) == "7"


def test_operation_param_preferred_over_path_level():
    spec = json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/things/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "example": "path-level"},
                ],
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "example": "op-level"},
                    ],
                },
            },
        },
    })
    assert _extract_resource_id(spec) == "op-level"


def test_non_path_parameters_ignored():
    spec = json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/things": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"default": 10}},
                        {"name": "filter", "in": "header"},
                    ],
                },
            },
        },
    })
    assert _extract_resource_id(spec) is None


def test_no_path_params_returns_none():
    spec = json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"default": 10}},
                    ],
                },
            },
        },
    })
    assert _extract_resource_id(spec) is None


def test_empty_or_invalid_spec_returns_none():
    assert _extract_resource_id(None) is None
    assert _extract_resource_id("") is None
    assert _extract_resource_id("not a document") is None
    assert _extract_resource_id("[]") is None


def test_resolve_resource_id_priority():
    form = {"resource_id": "guid-abc"}
    assert _resolve_resource_id(form, _JSON_SPEC) == "guid-abc"

    assert _resolve_resource_id({}, _JSON_SPEC) == "42"
    assert _resolve_resource_id({}, None) == "1"
    assert _resolve_resource_id({"resource_id": "   "}, _JSON_SPEC) == "42"