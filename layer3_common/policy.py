"""Validated policy language shared by administration and evaluation."""
import ipaddress
import json
import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PATH = re.compile(r"^(?:\$\.)?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
OPERATORS = {"eq", "neq", "in", "contains", "gte", "lte", "exists", "equals_path", "any", "all", "ip_in_cidr"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


def validate_condition(value, depth=0):
    if depth > 8 or not isinstance(value, dict) or set(value) - {"path", "operator", "value"}:
        raise ValueError("Invalid condition structure or nesting exceeds eight levels")
    path, operator, expected = value.get("path"), value.get("operator"), value.get("value")
    if not isinstance(path, str) or len(path) > 500 or not PATH.fullmatch(path):
        raise ValueError("Conditions require a dotted attribute path")
    if not isinstance(operator, str) or operator not in OPERATORS:
        raise ValueError("Unsupported condition operator")
    if operator == "exists" and type(expected) is not bool:
        raise ValueError("exists requires a boolean")
    if operator == "equals_path" and (not isinstance(expected, str) or not PATH.fullmatch(expected)):
        raise ValueError("equals_path requires a dotted attribute path")
    if operator == "in" and (not isinstance(expected, list) or not 1 <= len(expected) <= 100):
        raise ValueError("in requires a nonempty list of at most 100 values")
    if operator in {"gte", "lte"} and (type(expected) not in (int, float)
                                     or (type(expected) is float and not math.isfinite(expected))):
        raise ValueError("Ordered comparisons require a finite number")
    if operator == "ip_in_cidr":
        if not isinstance(expected, str):
            raise ValueError("ip_in_cidr requires a CIDR string")
        ipaddress.ip_network(expected, strict=True)
    if operator in {"any", "all"}:
        if not isinstance(expected, list) or not 1 <= len(expected) <= 20:
            raise ValueError("Array predicates require 1..20 conditions")
        for child in expected:
            validate_condition(child, depth + 1)
    elif operator not in {"exists", "equals_path"} and expected is None:
        raise ValueError("Condition value cannot be null")


class Condition(StrictModel):
    path: str
    operator: Literal["eq", "neq", "in", "contains", "gte", "lte", "exists", "equals_path", "any", "all", "ip_in_cidr"]
    value: Any = None

    @model_validator(mode="after")
    def valid_expression(self):
        validate_condition(self.model_dump())
        return self


class Policy(StrictModel):
    policyId: str = Field(min_length=1, max_length=200)
    version: int = Field(ge=1, strict=True)
    description: str = Field(default="", max_length=4000)
    effect: Literal["permit", "deny"]
    priority: int = Field(default=0, strict=True)
    resourceIds: list[str] = Field(default_factory=list, max_length=100)
    resourceTypes: list[str] = Field(default_factory=list, max_length=100)
    actions: list[str] = Field(min_length=1, max_length=100)
    requiredCredentialTypes: list[str] = Field(default_factory=list, max_length=100)
    conditions: list[Condition] = Field(default_factory=list, max_length=100)
    active: bool = Field(default=True, strict=True)

    @model_validator(mode="after")
    def bounded_document(self):
        if len(json.dumps(self.model_dump(mode="json"), allow_nan=False).encode()) > 65536:
            raise ValueError("Policy exceeds 64 KiB")
        return self

    @field_validator("resourceIds", "resourceTypes", "actions", "requiredCredentialTypes")
    @classmethod
    def nonempty_selectors(cls, values):
        if any(not value.strip() or len(value) > 500 for value in values) or len(set(values)) != len(values):
            raise ValueError("Selectors must be unique nonempty strings of at most 500 characters")
        return values


def path_value(data, dotted, root=None):
    if dotted.startswith("$."):
        data, dotted = root, dotted[2:]
    for part in dotted.split("."):
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
    return data


def equal(left, right):
    # JSON booleans are not numbers, including inside arrays and objects.
    if type(left) is not type(right) and not (type(left) in (int, float) and type(right) in (int, float)):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def condition_matches(condition, attributes, root=None):
    root = attributes if root is None else root
    actual = path_value(attributes, condition["path"], root)
    operator, expected = condition["operator"], condition.get("value")
    if operator == "exists":
        return type(expected) is bool and (actual is not None) is expected
    if actual is None:
        return False
    if operator in {"any", "all"}:
        if not isinstance(actual, list) or not actual:
            return False
        results = (all(condition_matches(child, item, root) for child in expected) for item in actual)
        return any(results) if operator == "any" else all(results)
    if operator == "equals_path":
        other = path_value(attributes, expected, root)
        return other is not None and equal(actual, other)
    if operator == "eq":
        return equal(actual, expected)
    if operator == "neq":
        return type(actual) is type(expected) and not equal(actual, expected)
    if operator == "in":
        return isinstance(expected, list) and any(equal(actual, item) for item in expected)
    if operator == "contains":
        if isinstance(actual, list):
            return any(equal(item, expected) for item in actual)
        return isinstance(actual, (str, dict)) and isinstance(expected, str) and expected in actual
    if operator in {"gte", "lte"}:
        if type(actual) not in (int, float) or type(expected) not in (int, float):
            return False
        if any(type(value) is float and not math.isfinite(value) for value in (actual, expected)):
            return False
        return actual >= expected if operator == "gte" else actual <= expected
    if operator == "ip_in_cidr":
        try:
            return isinstance(actual, str) and ipaddress.ip_address(actual) in ipaddress.ip_network(expected)
        except ValueError:
            return False
    return False
