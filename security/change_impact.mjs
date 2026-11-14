#!/usr/bin/env node
/**
 * Conservative, dependency-free Go change inventory for the matrix review.
 *
 * This is a lexical impact report, not a Go parser or a security decision. It
 * never declares an obligation covered. Unexpected source shape fails the
 * command instead of quietly omitting a changed function.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROUTE_METHODS = new Set([
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'Any', 'Handle',
]);
const OPERATORS = [
  '<<=', '>>=', '&^=', '...', '==', '!=', '<=', '>=', ':=', '&&', '||',
  '++', '--', '<-', '<<', '>>', '&^', '+=', '-=', '*=', '/=', '%=', '&=',
  '|=', '^=',
];
const OPEN_TO_CLOSE = new Map([['(', ')'], ['[', ']'], ['{', '}']]);
const CLOSE = new Set(OPEN_TO_CLOSE.values());

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function normalized(tokens) {
  return JSON.stringify(tokens.map((token) => [token.kind, token.text]));
}

function lineAt(source, offset) {
  let line = 1;
  for (let i = 0; i < offset; i += 1) {
    if (source[i] === '\n') line += 1;
  }
  return line;
}

function isIdentifierStart(character) {
  return character !== undefined && /[\p{L}_]/u.test(character);
}

function isIdentifierPart(character) {
  return character !== undefined && /[\p{L}\p{N}\p{M}_]/u.test(character);
}

function currentCharacter(source, offset) {
  if (offset >= source.length) return undefined;
  return String.fromCodePoint(source.codePointAt(offset));
}

function advance(offset, character) {
  return offset + character.length;
}

export function tokenizeGo(source, label = '<source>') {
  const tokens = [];
  const directives = [];
  let i = 0;
  while (i < source.length) {
    const start = i;
    const character = currentCharacter(source, i);
    const next = source[i + 1];
    if (/\s/u.test(character)) {
      i = advance(i, character);
      continue;
    }
    if (character === '/' && next === '/') {
      const newline = source.indexOf('\n', i + 2);
      i = newline < 0 ? source.length : newline;
      const comment = source.slice(start, i).trim();
      if (/^\/\/go:|^\/\/\s*\+build\b/.test(comment)) {
        directives.push({ text: comment, start, end: i });
      }
      continue;
    }
    if (character === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end < 0) throw new Error(`${label}:${lineAt(source, start)}: unclosed comment`);
      i = end + 2;
      continue;
    }
    if (character === '"' || character === "'") {
      const quote = character;
      i += 1;
      let closed = false;
      while (i < source.length) {
        if (source[i] === '\\') {
          i += 2;
        } else if (source[i] === quote) {
          i += 1;
          closed = true;
          break;
        } else if (source[i] === '\n') {
          throw new Error(`${label}:${lineAt(source, start)}: newline in quoted literal`);
        } else {
          i += 1;
        }
      }
      if (!closed) throw new Error(`${label}:${lineAt(source, start)}: unclosed quoted literal`);
      tokens.push({ kind: 'literal', text: source.slice(start, i), start, end: i });
      continue;
    }
    if (character === '`') {
      const end = source.indexOf('`', i + 1);
      if (end < 0) throw new Error(`${label}:${lineAt(source, start)}: unclosed raw string`);
      i = end + 1;
      tokens.push({ kind: 'literal', text: source.slice(start, i), start, end: i });
      continue;
    }
    if (isIdentifierStart(character)) {
      i = advance(i, character);
      while (isIdentifierPart(currentCharacter(source, i))) {
        i = advance(i, currentCharacter(source, i));
      }
      tokens.push({ kind: 'identifier', text: source.slice(start, i), start, end: i });
      continue;
    }
    if (/[0-9]/u.test(character)) {
      i += 1;
      while (/[\p{L}\p{N}_]/u.test(currentCharacter(source, i) ?? '')) {
        i = advance(i, currentCharacter(source, i));
      }
      tokens.push({ kind: 'number', text: source.slice(start, i), start, end: i });
      continue;
    }
    const operator = OPERATORS.find((candidate) => source.startsWith(candidate, i));
    if (operator) {
      i += operator.length;
      tokens.push({ kind: 'punctuation', text: operator, start, end: i });
      continue;
    }
    if ('()[]{}.,;:+-*/%&|^!<>=~'.includes(character)) {
      i += 1;
      tokens.push({ kind: 'punctuation', text: character, start, end: i });
      continue;
    }
    throw new Error(`${label}:${lineAt(source, start)}: unsupported character ${JSON.stringify(character)}`);
  }
  return { tokens, directives };
}

function delimiterPairs(tokens, label) {
  const stack = [];
  const pairs = new Map();
  for (let i = 0; i < tokens.length; i += 1) {
    const text = tokens[i].text;
    if (OPEN_TO_CLOSE.has(text)) {
      stack.push(i);
    } else if (CLOSE.has(text)) {
      const open = stack.pop();
      if (open === undefined || OPEN_TO_CLOSE.get(tokens[open].text) !== text) {
        throw new Error(`${label}: mismatched delimiter near token ${i}`);
      }
      pairs.set(open, i);
    }
  }
  if (stack.length) throw new Error(`${label}: unclosed delimiter`);
  return pairs;
}

function receiverName(receiverTokens) {
  // The first identifier in a named receiver is its variable, not its type.
  let tokens = receiverTokens;
  if (tokens.length > 1 && tokens[0].kind === 'identifier') {
    tokens = tokens.slice(1);
  }
  const result = tokens.map((token) => token.text).join('');
  if (!result) throw new Error('empty method receiver');
  return result;
}

function parseFunction(tokens, pairs, index, label) {
  let cursor = index + 1;
  let receiver = null;
  if (tokens[cursor]?.text === '(') {
    const end = pairs.get(cursor);
    if (end === undefined) throw new Error(`${label}: invalid receiver`);
    if (tokens[end + 1]?.kind !== 'identifier') return null; // function literal or type
    receiver = receiverName(tokens.slice(cursor + 1, end));
    cursor = end + 1;
  }
  if (tokens[cursor]?.kind !== 'identifier') return null;
  const name = tokens[cursor].text;
  cursor += 1;
  if (tokens[cursor]?.text === '[') cursor = pairs.get(cursor) + 1; // type params
  if (tokens[cursor]?.text !== '(') {
    throw new Error(`${label}: ambiguous function declaration ${name}`);
  }
  cursor = pairs.get(cursor) + 1;
  while (cursor < tokens.length) {
    const text = tokens[cursor].text;
    if (text === '{') {
      if (['struct', 'interface'].includes(tokens[cursor - 1]?.text)) {
        cursor = pairs.get(cursor) + 1;
        continue;
      }
      return {
        symbol: receiver ? `${receiver}.${name}` : name,
        startIndex: index,
        endIndex: pairs.get(cursor),
      };
    }
    if (text === '(' || text === '[') {
      cursor = pairs.get(cursor) + 1;
      continue;
    }
    if (text === ';') {
      throw new Error(`${label}: ambiguous or bodyless function declaration ${name}`);
    }
    cursor += 1;
  }
  throw new Error(`${label}: bodyless function declaration ${name}`);
}

function routeCalls(tokens, pairs, functionInfo, pathName, source) {
  const calls = [];
  for (let i = functionInfo.startIndex; i <= functionInfo.endIndex; i += 1) {
    if (tokens[i]?.kind !== 'identifier' || tokens[i + 1]?.text !== '.' ||
        !ROUTE_METHODS.has(tokens[i + 2]?.text) || tokens[i + 3]?.text !== '(') continue;
    const end = pairs.get(i + 3);
    if (end === undefined || end > functionInfo.endIndex) continue;
    const firstArgEnd = (() => {
      for (let j = i + 4; j < end; j += 1) {
        if (tokens[j].text === ',') return j;
        if (OPEN_TO_CLOSE.has(tokens[j].text)) j = pairs.get(j);
      }
      return end;
    })();
    const receiver = tokens[i].text;
    const method = tokens[i + 2].text;
    const routeExpression = normalized(tokens.slice(i + 4, firstArgEnd));
    const firstArgument = tokens.slice(i + 4, firstArgEnd);
    const route = firstArgument.length === 1 && firstArgument[0].kind === 'literal'
      ? firstArgument[0].text.slice(1, -1) : null;
    const callTokens = tokens.slice(i, end + 1);
    calls.push({
      path: pathName,
      owner: functionInfo.symbol,
      receiver,
      method,
      route,
      route_expression: routeExpression,
      signature: `${pathName}::${functionInfo.symbol}::${receiver}.${method}::${routeExpression}`,
      hash: digest(normalized(callTokens)),
      start: lineAt(source, tokens[i].start),
      end: lineAt(source, tokens[end].end),
    });
    i = end;
  }
  return calls;
}

export function analyzeGoSource(source, pathName = '<source>') {
  const { tokens, directives } = tokenizeGo(source, pathName);
  const pairs = delimiterPairs(tokens, pathName);
  const functions = [];
  const routes = [];
  const attributed = new Set();
  let braceDepth = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    // A function type or literal inside a top-level declaration is not a
    // named declaration. Go declarations begin a new line or follow `;`/`}`.
    const previous = tokens[i - 1];
    const followsOtherDeclaration = previous &&
      !source.slice(previous.end, tokens[i].start).includes('\n') &&
      previous.text !== ';' && previous.text !== '}';
    if (braceDepth === 0 && tokens[i].text === 'func' && !followsOtherDeclaration &&
        !['=', 'type', ':'].includes(previous?.text)) {
      const info = parseFunction(tokens, pairs, i, pathName);
      if (info) {
        const entry = {
          path: pathName,
          symbol: info.symbol,
          hash: digest(normalized(tokens.slice(i, info.endIndex + 1))),
          start: lineAt(source, tokens[i].start),
          end: lineAt(source, tokens[info.endIndex].end),
        };
        if (functions.some((previous) => previous.symbol === entry.symbol)) {
          throw new Error(`${pathName}: duplicate function symbol ${entry.symbol}`);
        }
        functions.push(entry);
        routes.push(...routeCalls(tokens, pairs, info, pathName, source));
        for (let j = i; j <= info.endIndex; j += 1) attributed.add(j);
        i = info.endIndex;
        continue;
      }
    }
    if (tokens[i].text === '{') braceDepth += 1;
    if (tokens[i].text === '}') braceDepth -= 1;
    if (braceDepth < 0) throw new Error(`${pathName}: unexpected closing brace`);
  }
  if (braceDepth !== 0) throw new Error(`${pathName}: unbalanced top-level braces`);
  const unattributedTokens = tokens.filter((_, index) => !attributed.has(index));
  // Go directives are comments with language-level effects, so include them.
  const topLevel = normalized(unattributedTokens) + JSON.stringify(directives.map((item) => item.text));
  return { functions, routes, top_level_hash: digest(topLevel) };
}

function asMap(files) {
  return files instanceof Map ? files : new Map(Object.entries(files));
}

function diffNamed(beforeItems, afterItems, keyOf, fields) {
  const before = new Map(beforeItems.map((item) => [keyOf(item), item]));
  const after = new Map(afterItems.map((item) => [keyOf(item), item]));
  if (before.size !== beforeItems.length || after.size !== afterItems.length) {
    throw new Error('ambiguous duplicate change key');
  }
  const changed = [];
  for (const key of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const oldItem = before.get(key);
    const newItem = after.get(key);
    if (oldItem && newItem && oldItem.hash === newItem.hash) continue;
    const item = newItem ?? oldItem;
    changed.push({
      ...Object.fromEntries(fields.map((field) => [field, item[field]])),
      status: !oldItem ? 'added' : !newItem ? 'removed' : 'modified',
      start: item.start,
      end: item.end,
      before_hash: oldItem?.hash ?? null,
      after_hash: newItem?.hash ?? null,
      before_span: oldItem ? { start: oldItem.start, end: oldItem.end } : null,
      after_span: newItem ? { start: newItem.start, end: newItem.end } : null,
    });
  }
  return changed;
}

export function compareSnapshots(baseFiles, headFiles) {
  const before = asMap(baseFiles);
  const after = asMap(headFiles);
  const changedFiles = [...new Set([...before.keys(), ...after.keys()])]
    .filter((file) => before.get(file) !== after.get(file)).sort();
  const changedFunctions = [];
  const changedRoutes = [];
  const changedTopLevel = [];
  for (const file of changedFiles) {
    const previous = before.has(file) ? analyzeGoSource(before.get(file), file) : null;
    const current = after.has(file) ? analyzeGoSource(after.get(file), file) : null;
    changedFunctions.push(...diffNamed(
      previous?.functions ?? [], current?.functions ?? [], (item) => item.symbol,
      ['path', 'symbol'],
    ));
    changedRoutes.push(...diffNamed(
      previous?.routes ?? [], current?.routes ?? [], (item) => item.signature,
      ['path', 'owner', 'receiver', 'method', 'route', 'route_expression', 'signature'],
    ));
    if (previous?.top_level_hash !== current?.top_level_hash) {
      changedTopLevel.push({
        path: file,
        status: !previous ? 'added' : !current ? 'removed' : 'modified',
        before_hash: previous?.top_level_hash ?? null,
        after_hash: current?.top_level_hash ?? null,
      });
    }
  }
  return {
    schema_version: 1,
    analysis_skipped: false,
    changed_files: changedFiles,
    changed_functions: changedFunctions,
    changed_routes: changedRoutes,
    changed_top_level: changedTopLevel,
  };
}

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
}

function snapshot(ref) {
  const files = git(['ls-tree', '-r', '--name-only', ref]).split(/\r?\n/)
    .filter((file) => file.endsWith('.go') && !file.endsWith('_test.go'));
  return new Map(files.map((file) => [file, git(['show', `${ref}:${file}`])]));
}

function options(argv) {
  const result = { head: 'HEAD' };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--full') result.full = true;
    else if (['--base', '--head', '--output'].includes(argv[i]) && argv[i + 1]) {
      result[argv[i].slice(2)] = argv[++i];
    } else {
      throw new Error(`unknown or incomplete option: ${argv[i]}`);
    }
  }
  return result;
}

function main() {
  const args = options(process.argv.slice(2));
  const skip = args.full || !args.base || /^0{40}$/.test(args.base);
  const report = skip ? {
    schema_version: 1,
    analysis_skipped: true,
    skip_reason: args.full ? 'full run' : 'no usable base commit',
    changed_files: [],
    changed_functions: [],
    changed_routes: [],
    changed_top_level: [],
  } : compareSnapshots(snapshot(git(['merge-base', args.base, args.head]).trim()), snapshot(args.head));
  report.base = skip ? args.base ?? null : git(['merge-base', args.base, args.head]).trim();
  report.requested_base = args.base ?? null;
  report.head = args.head;
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (args.output) writeFileSync(args.output, serialized, 'utf8');
  else process.stdout.write(serialized);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`ERROR: ${error.message}\n`);
    process.exitCode = 1;
  }
}
