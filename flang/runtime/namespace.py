"""
FLANG Namespace / Object Model
--------------------------------
Backs the `namespace.method(args)` and `variable.method(args)` syntax
(system.info(), process.list(), sample.hash()). A FlangNamespace is a
named bag of methods, each with the same (callable, min_role, effect)
shape as the flat builtin registry in interpreter.py -- so every
namespaced call gets identical RBAC enforcement and audit logging.

`analyze.file(path)` returns a FlangObject (a "Sample") -- a namespace
instance bound to one specific piece of data, so `sample.hash()` /
`sample.metadata()` work as method calls on the value `sample` holds,
not on a fixed global name.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Dict, Any


@dataclass
class MethodSpec:
    func: Callable
    min_role: str
    effect: str  # READ | DERIVE | EXPORT


class FlangNamespace:
    """A named, fixed set of methods -- e.g. the global `system` object."""

    def __init__(self, name: str, methods: Dict[str, MethodSpec]):
        self.name = name
        self.methods = methods

    def __repr__(self):
        return f"<namespace {self.name}>"


class FlangObject(FlangNamespace):
    """
    A namespace instance bound to a specific piece of data (e.g. one
    analyzed file). Distinguished from FlangNamespace only so error
    messages and repr() can say "object" instead of "namespace" --
    behaviorally identical.
    """

    def __repr__(self):
        return f"<{self.name} object>"
