/**
 * The policy language (0.74): the same bounded CEL subset as opentine/_policy_lang.py,
 * opentine/_policy_lex.py and opentine/_policy_eval.py, evaluated with the same
 * semantics, bounds and error codes. Shared vectors: tests/data/policy_vectors.json.
 *
 * Strings are compared and measured by Unicode code point (never by UTF-16 unit),
 * numbers are one type (1 == 1.0), and an integral number beyond 2**53 - 1 is refused
 * both as a literal and in the input document.
 */

export type PValue = null | boolean | number | string | PValue[] | { [key: string]: PValue };

export const MAX_SOURCE = 4096;
export const MAX_DEPTH = 32;
export const MAX_NODES = 1024;
export const MAX_HEIGHT = 64;
export const MAX_STEPS = 10_000;
export const MAX_INPUT_DEPTH = 64;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const KEYWORDS: Record<string, PValue> = { true: true, false: false, null: null };
const RESERVED = new Set(["in", "as", "break", "const", "continue", "else", "for", "function",
  "if", "import", "let", "loop", "package", "namespace", "return", "var", "void", "while"]);
const RELOPS = new Set(["==", "!=", "<", "<=", ">", ">="]);

export class PolicyError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

class Fatal extends Error {
  constructor(readonly error: PolicyError) {
    super(error.message);
  }
}

export type Node =
  | { op: "lit"; value: PValue }
  | { op: "var"; name: string }
  | { op: "list"; items: Node[] }
  | { op: "and" | "or"; a: Node; b: Node }
  | { op: "not" | "neg" | "size"; a: Node }
  | { op: "cmp"; rel: string; a: Node; b: Node }
  | { op: "in"; a: Node; b: Node }
  | { op: "sel" | "has"; a: Node; field: string }
  | { op: "idx"; a: Node; b: Node }
  | { op: "all" | "exists"; a: Node; name: string; body: Node };

type Tok = [string, PValue];

export function numberOk(v: number): boolean {
  if (!Number.isFinite(v)) return false;
  return !Number.isInteger(v) || Math.abs(v) <= MAX_SAFE;
}

function codePoints(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

const TOKEN = new RegExp(
  "(?<ws>[ \\t\\r\\n]+)|(?<num>(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)" +
    "|(?<ident>[A-Za-z_][A-Za-z0-9_]*)|(?<op>&&|\\|\\||==|!=|<=|>=|[<>!()\\[\\],.\\-])|(?<str>[\"'])",
  "y",
);
const ESC: Record<string, string> = { "\\": "\\", '"': '"', "'": "'", n: "\n", r: "\r", t: "\t" };

function readString(src: string, start: number, quote: string): [string, number] {
  let out = "";
  let pos = start;
  for (;;) {
    if (pos >= src.length || src[pos] === "\r" || src[pos] === "\n") {
      throw new PolicyError("policy.parse", "unterminated string");
    }
    const ch = src[pos];
    if (ch === quote) return [out, pos + 1];
    if (ch !== "\\") {
      out += ch;
      pos += 1;
      continue;
    }
    const esc = src.slice(pos + 1, pos + 2);
    if (Object.prototype.hasOwnProperty.call(ESC, esc)) {
      out += ESC[esc];
      pos += 2;
      continue;
    }
    const width = esc === "u" ? 4 : esc === "U" ? 8 : 0;
    const digits = width ? src.slice(pos + 2, pos + 2 + width) : "";
    if (!width || digits.length !== width || !/^[0-9A-Fa-f]+$/.test(digits)) {
      throw new PolicyError("policy.parse", "invalid escape in string");
    }
    const code = parseInt(digits, 16);
    if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
      throw new PolicyError("policy.parse", "escape is not a Unicode scalar value");
    }
    out += String.fromCodePoint(code);
    pos += 2 + width;
  }
}

export function tokens(src: string): Tok[] {
  if (typeof src !== "string" || codePoints(src) > MAX_SOURCE) {
    throw new PolicyError("policy.parse", `an expression is a string of at most ${MAX_SOURCE}`);
  }
  const out: Tok[] = [];
  let pos = 0;
  while (pos < src.length) {
    TOKEN.lastIndex = pos;
    const m = TOKEN.exec(src);
    if (!m || !m.groups) throw new PolicyError("policy.parse", `unexpected character at ${pos}`);
    const g = m.groups;
    if (g.str !== undefined) {
      const [value, next] = readString(src, pos + 1, g.str);
      out.push(["str", value]);
      pos = next;
      continue;
    }
    pos += m[0].length;
    if (g.num !== undefined) {
      const value = Number(g.num);
      if (!numberOk(value)) throw new PolicyError("policy.parse", "number literal out of range");
      if (/^[A-Za-z0-9_.]$/.test(src.slice(pos, pos + 1))) {
        throw new PolicyError("policy.parse", "malformed number literal");
      }
      out.push(["num", value]);
    } else if (g.ident !== undefined) {
      out.push(["ident", g.ident]);
    } else if (g.op !== undefined) {
      out.push(["op", g.op]);
    }
  }
  out.push(["end", null]);
  return out;
}

class Parser {
  private toks: Tok[];
  private pos = 0;
  private depth = 0;
  private nodes = 0;

  constructor(src: string) {
    this.toks = tokens(src);
  }

  node(n: Node): Node {
    this.nodes += 1;
    if (this.nodes > MAX_NODES) throw new PolicyError("policy.parse", `more than ${MAX_NODES} nodes`);
    return n;
  }

  peek(): Tok {
    return this.toks[this.pos];
  }

  isOp(op: string): boolean {
    const t = this.peek();
    return t[0] === "op" && t[1] === op;
  }

  take(op?: string): Tok {
    const tok = this.toks[this.pos];
    if (op !== undefined && !(tok[0] === "op" && tok[1] === op)) {
      throw new PolicyError("policy.parse", `expected '${op}'`);
    }
    this.pos += 1;
    return tok;
  }

  enter(): void {
    this.depth += 1;
    if (this.depth > MAX_DEPTH) throw new PolicyError("policy.parse", `nesting deeper than ${MAX_DEPTH}`);
  }

  expr(): Node {
    this.enter();
    let left = this.conj();
    while (this.isOp("||")) {
      this.take();
      left = this.node({ op: "or", a: left, b: this.conj() });
    }
    this.depth -= 1;
    return left;
  }

  conj(): Node {
    let left = this.rel();
    while (this.isOp("&&")) {
      this.take();
      left = this.node({ op: "and", a: left, b: this.rel() });
    }
    return left;
  }

  isRel(t: Tok): boolean {
    return (t[0] === "op" && RELOPS.has(t[1] as string)) || (t[0] === "ident" && t[1] === "in");
  }

  rel(): Node {
    let left = this.unary();
    const tok = this.peek();
    if (!this.isRel(tok)) return left;
    this.take();
    left =
      tok[0] === "op"
        ? this.node({ op: "cmp", rel: tok[1] as string, a: left, b: this.unary() })
        : this.node({ op: "in", a: left, b: this.unary() });
    if (this.isRel(this.peek())) throw new PolicyError("policy.parse", "comparisons do not chain");
    return left;
  }

  unary(): Node {
    if (this.isOp("!") || this.isOp("-")) {
      const op = this.take()[1];
      this.enter();
      const inner = this.unary();
      this.depth -= 1;
      return this.node({ op: op === "!" ? "not" : "neg", a: inner });
    }
    return this.member();
  }

  args(): Node[] {
    this.take("(");
    const out: Node[] = [];
    if (!this.isOp(")")) {
      out.push(this.expr());
      while (this.isOp(",")) {
        this.take();
        out.push(this.expr());
      }
    }
    this.take(")");
    return out;
  }

  member(): Node {
    let target = this.primary();
    for (;;) {
      if (this.isOp(".")) {
        this.take();
        const [kind, value] = this.take();
        const name = value as string;
        if (kind !== "ident" || Object.prototype.hasOwnProperty.call(KEYWORDS, name) || RESERVED.has(name)) {
          throw new PolicyError("policy.parse", "expected a field name after '.'");
        }
        if (!this.isOp("(")) {
          target = this.node({ op: "sel", a: target, field: name });
          continue;
        }
        if (name === "size") {
          if (this.args().length) throw new PolicyError("policy.parse", "x.size() takes no arguments");
          target = this.node({ op: "size", a: target });
        } else if (name === "all" || name === "exists") {
          const args = this.args();
          if (args.length !== 2 || args[0].op !== "var") {
            throw new PolicyError("policy.parse", `${name}(var, predicate) takes a variable name`);
          }
          target = this.node({ op: name, a: target, name: args[0].name, body: args[1] });
        } else {
          throw new PolicyError("policy.parse", `unknown function ${name}`);
        }
      } else if (this.isOp("[")) {
        this.take();
        const key = this.expr();
        this.take("]");
        target = this.node({ op: "idx", a: target, b: key });
      } else {
        return target;
      }
    }
  }

  primary(): Node {
    const [kind, value] = this.take();
    if (kind === "num" || kind === "str") return this.node({ op: "lit", value });
    if (kind === "op" && value === "(") {
      const inner = this.expr();
      this.take(")");
      return inner;
    }
    if (kind === "op" && value === "[") {
      const items: Node[] = [];
      if (!this.isOp("]")) {
        items.push(this.expr());
        while (this.isOp(",")) {
          this.take();
          items.push(this.expr());
        }
      }
      this.take("]");
      return this.node({ op: "list", items });
    }
    const name = value as string;
    if (kind === "ident" && Object.prototype.hasOwnProperty.call(KEYWORDS, name)) {
      return this.node({ op: "lit", value: KEYWORDS[name] });
    }
    if (kind === "ident" && !RESERVED.has(name)) {
      if (!this.isOp("(")) return this.node({ op: "var", name });
      if (name !== "has" && name !== "size") throw new PolicyError("policy.parse", `unknown function ${name}`);
      const args = this.args();
      if (args.length !== 1) throw new PolicyError("policy.parse", `${name}() takes one argument`);
      const arg = args[0];
      if (name === "has") {
        if (arg.op !== "sel") throw new PolicyError("policy.parse", "has() takes a field selection a.b");
        return this.node({ op: "has", a: arg.a, field: arg.field });
      }
      return this.node({ op: "size", a: arg });
    }
    throw new PolicyError("policy.parse", "expected an expression");
  }
}

export function height(n: Node): number {
  switch (n.op) {
    case "lit":
    case "var":
      return 1;
    case "list":
      return 1 + Math.max(0, ...n.items.map(height));
    case "not":
    case "neg":
    case "size":
    case "sel":
    case "has":
      return 1 + height(n.a);
    case "all":
    case "exists":
      return 1 + Math.max(height(n.a), height(n.body));
    default:
      return 1 + Math.max(height(n.a), height(n.b));
  }
}

export function parse(src: string): Node {
  const parser = new Parser(src);
  const tree = parser.expr();
  if (parser.peek()[0] !== "end") throw new PolicyError("policy.parse", "unexpected input after the expression");
  if (height(tree) > MAX_HEIGHT) throw new PolicyError("policy.parse", `expression tree taller than ${MAX_HEIGHT}`);
  return tree;
}
