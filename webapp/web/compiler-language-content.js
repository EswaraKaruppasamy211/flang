const COMPILER_SAMPLES = [
  {
    id: "sample-1",
    title: "Sample 1: Lexer & Tokens",
    summary: "How FLANG source text becomes a validated stream of tokens.",
    passingPercent: 70,
    questions: [
      { id: "s1q1", text: "Which token kind represents a quoted value such as \"case-01\"?", options: ["STRING", "TEXT", "VALUE", "LITERAL"], correctIndex: 0 },
      { id: "s1q2", text: "Which symbol assigns a value to a new variable?", options: ["=", ":=", "==", "->"], correctIndex: 1 },
      { id: "s1q3", text: "What starts a FLANG comment?", options: ["//", "/*", "#", "--"], correctIndex: 2 },
      { id: "s1q4", text: "What does the lexer raise for an unknown character?", options: ["ParseError", "LexError", "TokenError", "RuntimeError"], correctIndex: 1 },
      { id: "s1q5", text: "Which token is appended after all source text is consumed?", options: ["END", "STOP", "EOF", "NULL"], correctIndex: 2 }
    ]
  },
  {
    id: "sample-2",
    title: "Sample 2: Parser & AST",
    summary: "How the recursive-descent parser turns tokens into executable syntax trees.",
    passingPercent: 70,
    questions: [
      { id: "s2q1", text: "What kind of parser does FLANG use?", options: ["LR parser", "Recursive-descent parser", "Pratt-only parser", "PEG parser"], correctIndex: 1 },
      { id: "s2q2", text: "Which statement creates a variable in the grammar?", options: ["IDENT := expression ;", "let IDENT = expression", "var IDENT ;", "set IDENT to expression"], correctIndex: 0 },
      { id: "s2q3", text: "What does the parser produce?", options: ["Bytecode", "A JSON document", "An AST", "Machine code"], correctIndex: 2 },
      { id: "s2q4", text: "Which construct is represented by a block delimited with braces?", options: ["A comment", "A statement block", "A token", "A string"], correctIndex: 1 },
      { id: "s2q5", text: "Which error includes the unexpected token location?", options: ["ParseError", "LexError", "AuditError", "CaseError"], correctIndex: 0 }
    ]
  },
  {
    id: "sample-3",
    title: "Sample 3: Interpreter Basics",
    summary: "Variables, control flow, functions, and expressions in the tree-walking interpreter.",
    passingPercent: 70,
    questions: [
      { id: "s3q1", text: "Which loop iterates over each value in a collection?", options: ["repeat", "for ... in", "foreach ... as", "each"], correctIndex: 1 },
      { id: "s3q2", text: "Which keyword defines a FLANG function?", options: ["def", "fn", "function", "procedure"], correctIndex: 2 },
      { id: "s3q3", text: "What happens to compound assignment such as x += 1?", options: ["It is rejected", "It is desugared to a normal assignment", "It becomes a string", "It is sent to the server"], correctIndex: 1 },
      { id: "s3q4", text: "Which expression checks membership?", options: ["contains", "has", "in", "within"], correctIndex: 2 },
      { id: "s3q5", text: "What protects the runtime from an endless while loop?", options: ["A loop iteration limit", "A network timeout", "A parser rewrite", "A browser alert"], correctIndex: 0 }
    ]
  },
  {
    id: "sample-4",
    title: "Sample 4: Evidence & Audit",
    summary: "Read-only evidence handles, hashing, RBAC, and the tamper-evident audit trail.",
    passingPercent: 70,
    questions: [
      { id: "s4q1", text: "What does an evidence handle expose to analysis code?", options: ["A read-only evidence reference", "A writable raw path", "A database cursor", "A shell command"], correctIndex: 0 },
      { id: "s4q2", text: "Which hash is available for an evidence handle?", options: ["MD4", "SHA-256", "CRC-16", "None"], correctIndex: 1 },
      { id: "s4q3", text: "When is a built-in call written to the audit log?", options: ["After the result is printed", "Only on errors", "Before the call returns its result", "Only when requested"], correctIndex: 2 },
      { id: "s4q4", text: "What controls whether a role may call a built-in?", options: ["The browser", "The minimum role on its BuiltinSpec", "The filename", "The loop counter"], correctIndex: 1 },
      { id: "s4q5", text: "What reveals a retroactive audit edit?", options: ["A broken hash chain", "A changed CSS color", "A missing semicolon", "A new browser tab"], correctIndex: 0 }
    ]
  },
  {
    id: "sample-5",
    title: "Sample 5: Timeline & Reports",
    summary: "Correlate findings, build reports, and apply signed evidence of conclusions.",
    passingPercent: 70,
    questions: [
      { id: "s5q1", text: "What can timeline correlation use to join events?", options: ["Time proximity", "Font size", "Variable names only", "Browser history"], correctIndex: 0 },
      { id: "s5q2", text: "Which operation orders timeline events?", options: ["timeline.sort", "timeline.orderby", "events.rank", "sort.timeline"], correctIndex: 0 },
      { id: "s5q3", text: "What does a report signature provide?", options: ["HMAC-backed integrity", "A screen capture", "A new lexer token", "A network connection"], correctIndex: 0 },
      { id: "s5q4", text: "Which format is shown as a report export option?", options: ["JSON", "WAV", "EXE", "DLL"], correctIndex: 0 },
      { id: "s5q5", text: "What is co-signing used for?", options: ["Dual control", "Loop control", "Tokenization", "Browser caching"], correctIndex: 0 }
    ]
  }
];
