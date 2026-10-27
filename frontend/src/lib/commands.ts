/**
 * Static command parsing. NOTHING here executes commands (Zero Host
 * Execution invariant) — we only tokenize text produced by a model.
 */

export interface ParsedCommand {
  raw: string;
  tokens: string[];
  tool: string | null;
}

const WRAPPERS = new Set(['sudo', 'proxychains', 'proxychains4', 'time', 'nohup', 'env', 'timeout', 'exec']);
const INTERPRETERS = new Set(['python', 'python2', 'python3', 'perl', 'ruby', 'bash', 'sh']);

/** Strip markdown fences, shell prompts and comment lines from model output. */
export function cleanModelOutput(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('```') && !l.startsWith('#'))
    .map((l) => l.replace(/^(\$|>|PS>|root@\S+[#$])\s+/, ''));
}

/** Split one line on ; && || | — but only outside of quotes. */
export function splitChain(line: string): string[] {
  const out: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      buf += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      buf += c;
      continue;
    }
    const two = line.slice(i, i + 2);
    if (two === '&&' || two === '||') {
      out.push(buf);
      buf = '';
      i++;
      continue;
    }
    if (c === ';' || c === '|') {
      out.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  out.push(buf);
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Minimal shlex-style tokenizer (quotes removed, contents preserved). */
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd)) !== null) tokens.push(m[1] ?? m[2] ?? m[3]);
  return tokens;
}

function basename(t: string): string {
  return t.split('/').pop()!.toLowerCase();
}

export function detectTool(tokens: string[]): string | null {
  let i = 0;
  while (i < tokens.length && (WRAPPERS.has(basename(tokens[i])) || /^\w+=/.test(tokens[i]) || /^-/.test(tokens[i]))) i++;
  if (i >= tokens.length) return null;
  const first = basename(tokens[i]);
  if (INTERPRETERS.has(first) && tokens[i + 1]) return basename(tokens[i + 1]).replace(/\.py$/, '');
  return first.replace(/\.py$/, '');
}

export function parseCommands(text: string): ParsedCommand[] {
  return cleanModelOutput(text)
    .flatMap(splitChain)
    .map((raw) => {
      const tokens = tokenize(raw);
      return { raw, tokens, tool: detectTool(tokens) };
    })
    .filter((c) => c.tool !== null);
}
