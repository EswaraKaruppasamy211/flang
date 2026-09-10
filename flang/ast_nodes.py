"""
FLANG AST node definitions.
Plain dataclasses -- the interpreter pattern-matches on type.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any


@dataclass
class Program:
    statements: List[Any]


@dataclass
class Import:
    name: str
    path: str
    line: int


@dataclass
class Assign:
    target: str
    value: Any
    line: int


@dataclass
class ExprStmt:
    expr: Any
    line: int


@dataclass
class If:
    condition: Any
    then_block: List[Any]
    else_block: Optional[List[Any]]
    line: int


@dataclass
class For:
    var_name: str
    iterable: Any
    body: List[Any]
    line: int


@dataclass
class While:
    condition: Any
    body: List[Any]
    line: int


@dataclass
class Try:
    try_block: List[Any]
    err_name: str
    catch_block: List[Any]
    line: int


@dataclass
class Break:
    line: int


@dataclass
class Continue:
    line: int


@dataclass
class FunctionDef:
    name: str
    params: List[str]
    body: List[Any]
    line: int


@dataclass
class Return:
    value: Any
    line: int


@dataclass
class Identifier:
    name: str
    line: int


@dataclass
class NumberLiteral:
    value: float
    line: int


@dataclass
class StringLiteral:
    value: str
    line: int


@dataclass
class FStringLiteral:
    raw: str
    line: int


@dataclass
class BoolLiteral:
    value: bool
    line: int


@dataclass
class ListLiteral:
    elements: List[Any]
    line: int


@dataclass
class DictLiteral:
    pairs: List[Any]   # list of (key_expr, value_expr) tuples
    line: int


@dataclass
class BinaryOp:
    op: str
    left: Any
    right: Any
    line: int


@dataclass
class UnaryOp:
    op: str
    operand: Any
    line: int


@dataclass
class Ternary:
    condition: Any
    then_expr: Any
    else_expr: Any
    line: int


@dataclass
class Call:
    name: str
    args: List[Any]
    kwargs: dict
    line: int


@dataclass
class MemberCall:
    # `object_expr.method_name(args)` -- used for the namespaced stdlib
    # syntax (system.info(), process.list()) and for method calls on
    # objects returned by builtins (sample.hash() where sample came
    # from analyze.file(...)).
    object_expr: Any
    method_name: str
    args: List[Any]
    kwargs: dict
    line: int
