"""
FLANG Lexer
-----------
Turns FLANG source text into a flat list of tokens.
"""

from dataclasses import dataclass
from typing import List

KEYWORDS = {
    "import", "from", "as", "function", "if", "elif", "else", "for", "in",
    "while", "true", "false", "return", "and", "or", "not",
    "try", "catch", "break", "continue",
}

SYMBOLS = [
    # 3-char and 2-char symbols must come before their 1-char prefixes;
    # the tokenizer matches longest-first so order here doesn't strictly
    # matter, but grouping by length keeps the grammar easy to audit.
    "**", "//", ":=", "->", "==", "!=", "<=", ">=",
    "+=", "-=", "*=", "/=", "%=", "++", "--",
    "{", "}", "(", ")", "[", "]", ",", ";", ":", "?",
    "+", "-", "*", "/", "%",
    "<", ">", ".",
]


class LexError(Exception):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"Lex error at {line}:{col}: {message}")
        self.line = line
        self.col = col


@dataclass
class Token:
    kind: str      # IDENT, KEYWORD, STRING, FSTRING, NUMBER, SYMBOL, EOF
    value: str
    line: int
    col: int

    def __repr__(self):
        return f"Token({self.kind!r}, {self.value!r}, {self.line}:{self.col})"


def tokenize(source: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(source)
    line = 1
    col = 1

    def advance(k=1):
        nonlocal i, line, col
        for _ in range(k):
            if i < n and source[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    while i < n:
        ch = source[i]

        # whitespace
        if ch in " \t\r\n":
            advance()
            continue

        # comments
        if ch == "#":
            while i < n and source[i] != "\n":
                advance()
            continue

        start_line, start_col = line, col

        # strings (including f-strings)
        if ch == 'f' and i + 1 < n and source[i + 1] == '"':
            advance(2)  # consume f"
            buf = []
            while i < n and source[i] != '"':
                if source[i] == "\\" and i + 1 < n:
                    nxt = source[i + 1]
                    escapes = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
                    buf.append(escapes.get(nxt, nxt))
                    advance(2)
                else:
                    buf.append(source[i])
                    advance()
            if i >= n:
                raise LexError("Unterminated f-string", start_line, start_col)
            advance()  # closing quote
            tokens.append(Token("FSTRING", "".join(buf), start_line, start_col))
            continue

        if ch == '"':
            advance()
            buf = []
            while i < n and source[i] != '"':
                if source[i] == "\\" and i + 1 < n:
                    nxt = source[i + 1]
                    escapes = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
                    buf.append(escapes.get(nxt, nxt))
                    advance(2)
                else:
                    buf.append(source[i])
                    advance()
            if i >= n:
                raise LexError("Unterminated string", start_line, start_col)
            advance()  # closing quote
            tokens.append(Token("STRING", "".join(buf), start_line, start_col))
            continue

        # numbers
        if ch.isdigit():
            buf = []
            while i < n and (source[i].isdigit() or source[i] == "."):
                buf.append(source[i])
                advance()
            tokens.append(Token("NUMBER", "".join(buf), start_line, start_col))
            continue

        # identifiers / keywords
        if ch.isalpha() or ch == "_":
            buf = []
            while i < n and (source[i].isalnum() or source[i] == "_"):
                buf.append(source[i])
                advance()
            word = "".join(buf)
            kind = "KEYWORD" if word in KEYWORDS else "IDENT"
            tokens.append(Token(kind, word, start_line, start_col))
            continue

        # multi-char symbols first
        matched = False
        for sym in sorted(SYMBOLS, key=len, reverse=True):
            if source.startswith(sym, i):
                tokens.append(Token("SYMBOL", sym, start_line, start_col))
                advance(len(sym))
                matched = True
                break
        if matched:
            continue

        raise LexError(f"Unexpected character {ch!r}", start_line, start_col)

    tokens.append(Token("EOF", "", line, col))
    return tokens