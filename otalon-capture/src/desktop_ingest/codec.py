"""Versioned JSON codec for trusted internal carry; never unpickle captured input."""

import base64
import dataclasses
from collections import Counter

from otalon_capture import aggregation, mac_aggregation, proto_aggregation

TYPES = {
    c.__name__: c
    for m in [aggregation, mac_aggregation, proto_aggregation]
    for c in vars(m).values()
    if isinstance(c, type) and dataclasses.is_dataclass(c)
}


def encode(value):
    if dataclasses.is_dataclass(value):
        return {
            "t": "object",
            "c": type(value).__name__,
            "v": {f.name: encode(getattr(value, f.name)) for f in dataclasses.fields(value)},
        }
    if isinstance(value, bytes):
        return {"t": "bytes", "v": base64.b64encode(value).decode()}
    if isinstance(value, Counter):
        return {"t": "counter", "v": [[encode(k), encode(v)] for k, v in value.items()]}
    if isinstance(value, dict):
        return {"t": "dict", "v": [[encode(k), encode(v)] for k, v in value.items()]}
    if isinstance(value, set):
        return {"t": "set", "v": [encode(v) for v in sorted(value, key=repr)]}
    if isinstance(value, tuple):
        return {"t": "tuple", "v": [encode(v) for v in value]}
    if isinstance(value, list):
        return [encode(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("unsupported state type")


def decode(value):
    if isinstance(value, list):
        return [decode(v) for v in value]
    if not isinstance(value, dict):
        return value
    t = value["t"]
    v = value["v"]
    if t == "bytes":
        return base64.b64decode(v, validate=True)
    if t == "dict":
        return {decode(k): decode(x) for k, x in v}
    if t == "counter":
        return Counter({decode(k): decode(x) for k, x in v})
    if t == "set":
        return {decode(x) for x in v}
    if t == "tuple":
        return tuple(decode(x) for x in v)
    if t == "object":
        return TYPES[value["c"]](**{k: decode(x) for k, x in v.items()})
    raise ValueError("unsupported state tag")
