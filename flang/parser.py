"""
FLANG Parser
------------
Hand-written recursive-descent parser producing an AST (see ast_nodes.py)
from the token stream produced by lexer.py.

Grammar (informal EBNF) is documented in the project proposal; this parser
implements a practical subset sufficient to run real investigation scripts:

program        ::= { statement }
statement      ::= import_stmt | function_def | assignment | if_stmt
                  | for_stmt | expr_stmt
import_stmt    ::= "import" IDENT "from" STRING ";"
function_def   ::= "function" IDENT "(" params ")" block
assignment     ::= IDENT ":=" expression ";"
if_stmt        ::= "if" expression block [ "else" block ]
for_stmt       ::= "for" IDENT "in" expression block
expr_stmt      ::= expression ";"
expression     ::= additive
additive       ::= primary { ("+"|"-") primary }
primary        ::= NUMBER | STRING | FSTRING | "true" | "false"
                  | IDENT | call | list_literal | "(" expression ")"
call           ::= IDENT "(" [ arg { "," arg } ] ")"
arg            ::= [ IDENT ":" ] expression
list_literal   ::= "[" [ expression { "," expression } ] "]"
"""

from typing import List, Optional
from .lexer import Token
from . import ast_nodes as A


class ParseError(Exception):
    def __init__(self, message: str, token: Token):
        super().__init__(f"Parse error at {token.line}:{token.col}: {message} (got {token.kind} {token.value!r})")


COMPOUND_ASSIGN_OPS = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%"}
INCDEC_OPS = {"++": "+", "--": "-"}


class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    # -- token helpers -------------------------------------------------
    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if tok.kind != "EOF":
            self.pos += 1
        return tok

    def check(self, kind: str, value: Optional[str] = None) -> bool:
        tok = self.peek()
        if tok.kind != kind:
            return False
        if value is not None and tok.value != value:
            return False
        return True

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        if not self.check(kind, value):
            raise ParseError(f"expected {kind} {value or ''}".strip(), self.peek())
        return self.advance()

    # -- entry point -----------------------------------------------------
    def parse_program(self) -> A.Program:
        statements = []
        while not self.check("EOF"):
            statements.append(self.parse_statement())
        return A.Program(statements)

    # -- statements --------------------------------------------------------
    def parse_statement(self):
        tok = self.peek()

        if tok.kind == "KEYWORD" and tok.value == "import":
            return self.parse_import()
        if tok.kind == "KEYWORD" and tok.value == "function":
            return self.parse_function_def()
        if tok.kind == "KEYWORD" and tok.value == "if":
            return self.parse_if()
        if tok.kind == "KEYWORD" and tok.value == "while":
            return self.parse_while()
        if tok.kind == "KEYWORD" and tok.value == "try":
            return self.parse_try()
        if tok.kind == "KEYWORD" and tok.value == "break":
            self.advance()
            self.expect("SYMBOL", ";")
            return A.Break(tok.line)
        if tok.kind == "KEYWORD" and tok.value == "continue":
            self.advance()
            self.expect("SYMBOL", ";")
            return A.Continue(tok.line)
        if tok.kind == "KEYWORD" and tok.value == "for":
            return self.parse_for()
        if tok.kind == "KEYWORD" and tok.value == "return":
            line = tok.line
            self.advance()
            value = self.parse_expression()
            self.expect("SYMBOL", ";")
            return A.Return(value, line)

        # assignment: IDENT ":=" expression ";"
        if tok.kind == "IDENT" and self.tokens[self.pos + 1].kind == "SYMBOL" and self.tokens[self.pos + 1].value == ":=":
            name = self.advance().value
            self.expect("SYMBOL", ":=")
            value = self.parse_expression()
            self.expect("SYMBOL", ";")
            return A.Assign(name, value, tok.line)

        # compound assignment: IDENT ("+=" | "-=" | "*=" | "/=" | "%=") expression ";"
        # desugars to IDENT := IDENT <op> expression, so the interpreter
        # only ever needs to know about plain Assign nodes.
        if tok.kind == "IDENT" and self.tokens[self.pos + 1].kind == "SYMBOL" \
                and self.tokens[self.pos + 1].value in COMPOUND_ASSIGN_OPS:
            name = self.advance().value
            op_tok = self.advance()
            rhs = self.parse_expression()
            self.expect("SYMBOL", ";")
            base_op = COMPOUND_ASSIGN_OPS[op_tok.value]
            combined = A.BinaryOp(base_op, A.Identifier(name, tok.line), rhs, tok.line)
            return A.Assign(name, combined, tok.line)

        # increment / decrement: IDENT "++" ";"  |  IDENT "--" ";"
        # desugars to IDENT := IDENT + 1 / IDENT := IDENT - 1
        if tok.kind == "IDENT" and self.tokens[self.pos + 1].kind == "SYMBOL" \
                and self.tokens[self.pos + 1].value in INCDEC_OPS:
            name = self.advance().value
            op_tok = self.advance()
            self.expect("SYMBOL", ";")
            base_op = INCDEC_OPS[op_tok.value]
            combined = A.BinaryOp(base_op, A.Identifier(name, tok.line), A.NumberLiteral(1, tok.line), tok.line)
            return A.Assign(name, combined, tok.line)

        # otherwise: expression statement
        expr = self.parse_expression()
        self.expect("SYMBOL", ";")
        return A.ExprStmt(expr, tok.line)

    def parse_import(self):
        line = self.expect("KEYWORD", "import").line
        name = self.expect("IDENT").value
        self.expect("KEYWORD", "from")
        path_tok = self.expect("STRING")
        self.expect("SYMBOL", ";")
        return A.Import(name, path_tok.value, line)

    def parse_function_def(self):
        line = self.expect("KEYWORD", "function").line
        name = self.expect("IDENT").value
        self.expect("SYMBOL", "(")
        params = []
        if not self.check("SYMBOL", ")"):
            params.append(self.expect("IDENT").value)
            # optional type annotation ": type"
            if self.check("SYMBOL", ":"):
                self.advance()
                self.expect("IDENT")
            while self.check("SYMBOL", ","):
                self.advance()
                params.append(self.expect("IDENT").value)
                if self.check("SYMBOL", ":"):
                    self.advance()
                    self.expect("IDENT")
        self.expect("SYMBOL", ")")
        if self.check("SYMBOL", "->"):
            self.advance()
            self.expect("IDENT")
        body = self.parse_block()
        return A.FunctionDef(name, params, body, line)

    def parse_if(self):
        line = self.expect("KEYWORD", "if").line
        return self._parse_if_body(line)

    def _parse_if_body(self, line):
        # shared by "if" and "elif" -- an "elif" is parsed as a nested
        # If node inside the else_block, so `if / elif / elif / else`
        # chains read naturally without any special-case AST shape.
        cond = self.parse_expression()
        then_block = self.parse_block()
        else_block = None
        if self.check("KEYWORD", "elif"):
            elif_line = self.advance().line
            else_block = [self._parse_if_body(elif_line)]
        elif self.check("KEYWORD", "else"):
            self.advance()
            else_block = self.parse_block()
        return A.If(cond, then_block, else_block, line)

    def parse_while(self):
        line = self.expect("KEYWORD", "while").line
        cond = self.parse_expression()
        body = self.parse_block()
        return A.While(cond, body, line)

    def parse_try(self):
        line = self.expect("KEYWORD", "try").line
        try_block = self.parse_block()
        self.expect("KEYWORD", "catch")
        err_name = self.expect("IDENT").value
        catch_block = self.parse_block()
        return A.Try(try_block, err_name, catch_block, line)

    def parse_for(self):
        line = self.expect("KEYWORD", "for").line
        var_name = self.expect("IDENT").value
        self.expect("KEYWORD", "in")
        iterable = self.parse_expression()
        body = self.parse_block()
        return A.For(var_name, iterable, body, line)

    def parse_block(self) -> List:
        self.expect("SYMBOL", "{")
        statements = []
        while not self.check("SYMBOL", "}"):
            statements.append(self.parse_statement())
        self.expect("SYMBOL", "}")
        return statements

    # -- expressions ---------------------------------------------------
    # precedence, low to high:
    #   ternary (?:)  <  or  <  and  <  not  <  comparison (==, !=, <, >, <=, >=)
    #   <  membership (in)  <  additive (+, -)  <  multiplicative (*, /, %, //)
    #   <  power (**)  <  unary (-)  <  primary
    def parse_expression(self):
        cond = self.parse_or()
        if self.check("SYMBOL", "?"):
            self.advance()
            then_expr = self.parse_expression()
            self.expect("SYMBOL", ":")
            else_expr = self.parse_expression()
            return A.Ternary(cond, then_expr, else_expr, cond.line if hasattr(cond, "line") else 0)
        return cond

    def parse_or(self):
        left = self.parse_and()
        while self.check("KEYWORD", "or"):
            op = self.advance().value
            right = self.parse_and()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.check("KEYWORD", "and"):
            op = self.advance().value
            right = self.parse_not()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_not(self):
        if self.check("KEYWORD", "not"):
            tok = self.advance()
            operand = self.parse_not()
            return A.UnaryOp("not", operand, tok.line)
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_membership()
        while self.check("SYMBOL") and self.peek().value in ("==", "!=", "<", ">", "<=", ">="):
            op = self.advance().value
            right = self.parse_membership()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_membership(self):
        left = self.parse_additive()
        # `x in list` -- reuses the same "in" keyword the for-loop uses,
        # disambiguated by grammar position (this is never reached while
        # parsing a for-loop header, which consumes "in" itself).
        while self.check("KEYWORD", "in"):
            op = self.advance().value
            right = self.parse_additive()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_additive(self):
        left = self.parse_multiplicative()
        while self.check("SYMBOL") and self.peek().value in ("+", "-"):
            op = self.advance().value
            right = self.parse_multiplicative()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_multiplicative(self):
        left = self.parse_power()
        while self.check("SYMBOL") and self.peek().value in ("*", "/", "%", "//"):
            op = self.advance().value
            right = self.parse_power()
            left = A.BinaryOp(op, left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_power(self):
        left = self.parse_unary()
        if self.check("SYMBOL", "**"):
            self.advance()
            right = self.parse_power()  # right-associative: 2 ** 3 ** 2 == 2 ** (3 ** 2)
            return A.BinaryOp("**", left, right, left.line if hasattr(left, "line") else 0)
        return left

    def parse_unary(self):
        if self.check("SYMBOL", "-"):
            tok = self.advance()
            operand = self.parse_unary()
            return A.UnaryOp("-", operand, tok.line)
        return self.parse_postfix()

    def parse_postfix(self):
        # handles chained method calls: system.info()  or  sample.hash().foo()
        expr = self.parse_primary()
        while self.check("SYMBOL", "."):
            self.advance()
            method_name = self.expect("IDENT").value
            self.expect("SYMBOL", "(")
            args, kwargs = [], {}
            if not self.check("SYMBOL", ")"):
                self._parse_arg(args, kwargs)
                while self.check("SYMBOL", ","):
                    self.advance()
                    self._parse_arg(args, kwargs)
            self.expect("SYMBOL", ")")
            expr = A.MemberCall(expr, method_name, args, kwargs,
                                 expr.line if hasattr(expr, "line") else 0)
        return expr

    def parse_primary(self):
        tok = self.peek()

        if tok.kind == "NUMBER":
            self.advance()
            # whole numbers parse as int, decimals as float, so
            # `print(a)` shows 12 instead of 12.0 for integer-looking input
            value = float(tok.value) if "." in tok.value else int(tok.value)
            return A.NumberLiteral(value, tok.line)

        if tok.kind == "STRING":
            self.advance()
            return A.StringLiteral(tok.value, tok.line)

        if tok.kind == "FSTRING":
            self.advance()
            return A.FStringLiteral(tok.value, tok.line)

        if tok.kind == "KEYWORD" and tok.value in ("true", "false"):
            self.advance()
            return A.BoolLiteral(tok.value == "true", tok.line)

        if tok.kind == "SYMBOL" and tok.value == "[":
            return self.parse_list_literal()

        if tok.kind == "SYMBOL" and tok.value == "{":
            return self.parse_dict_literal()

        if tok.kind == "SYMBOL" and tok.value == "(":
            self.advance()
            expr = self.parse_expression()
            self.expect("SYMBOL", ")")
            return expr

        if tok.kind == "IDENT":
            name = self.advance().value
            if self.check("SYMBOL", "("):
                return self.parse_call(name, tok.line)
            return A.Identifier(name, tok.line)

        raise ParseError("unexpected token in expression", tok)

    def parse_call(self, name: str, line: int):
        self.expect("SYMBOL", "(")
        args = []
        kwargs = {}
        if not self.check("SYMBOL", ")"):
            self._parse_arg(args, kwargs)
            while self.check("SYMBOL", ","):
                self.advance()
                self._parse_arg(args, kwargs)
        self.expect("SYMBOL", ")")
        return A.Call(name, args, kwargs, line)

    def _parse_arg(self, args: list, kwargs: dict):
        # lookahead for "IDENT : expression" (keyword arg) vs plain expression
        if self.check("IDENT") and self.tokens[self.pos + 1].kind == "SYMBOL" and self.tokens[self.pos + 1].value == ":":
            key = self.advance().value
            self.advance()  # ':'
            value = self.parse_expression()
            kwargs[key] = value
        else:
            args.append(self.parse_expression())

    def parse_list_literal(self):
        line = self.expect("SYMBOL", "[").line
        elements = []
        if not self.check("SYMBOL", "]"):
            elements.append(self.parse_expression())
            while self.check("SYMBOL", ","):
                self.advance()
                elements.append(self.parse_expression())
        self.expect("SYMBOL", "]")
        return A.ListLiteral(elements, line)

    def parse_dict_literal(self):
        line = self.expect("SYMBOL", "{").line
        pairs = []
        if not self.check("SYMBOL", "}"):
            pairs.append(self._parse_dict_pair())
            while self.check("SYMBOL", ","):
                self.advance()
                pairs.append(self._parse_dict_pair())
        self.expect("SYMBOL", "}")
        return A.DictLiteral(pairs, line)

    def _parse_dict_pair(self):
        key = self.parse_expression()
        self.expect("SYMBOL", ":")
        value = self.parse_expression()
        return (key, value)


def parse(tokens: List[Token]) -> A.Program:
    return Parser(tokens).parse_program()
