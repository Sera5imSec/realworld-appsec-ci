#!/usr/bin/env node
// Turn changed Go symbols into a review queue without narrowing the runtime selector.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultCatalog = path.join(root, 'security/matrices/catalog.json');
const defaultDecisions = path.join(root, 'security/matrices/code_decisions.json');

function flagValue(args, flag) {
  const position = args.indexOf(flag);
  if (position < 0) return null;
  if (!args[position + 1] || args[position + 1].startsWith('--')) {
    throw new Error(`${flag} needs a value`);
  }
  return args[position + 1];
}

function variantsFor(catalog, matrixIds) {
  const ids = new Set(matrixIds);
  return catalog.matrices
    .filter(matrix => ids.has(matrix.id))
    .flatMap(matrix => matrix.variants.map(variant => variant.id));
}

function sourceRefWithin(matrix, changed) {
  const span = changed.after_span ?? changed.before_span;
  if (!span) return false;
  return matrix.source_refs.some(ref => {
    const separator = ref.lastIndexOf(':');
    if (separator < 0 || ref.slice(0, separator) !== changed.path) return false;
    const line = Number(ref.slice(separator + 1));
    return line >= span.start && line <= span.end;
  });
}

function findDecision(decisions, kind, changed) {
  const key = kind === 'route' ? changed.signature :
    kind === 'top_level' ? '(outside named functions)' : changed.symbol;
  const fingerprint = changed.after_hash ?? changed.before_hash;
  return decisions.decisions.find(row => row.kind === kind &&
    row.path === changed.path && row.symbol === key &&
    row.fingerprint === fingerprint) ?? null;
}

export function validateDecisions(decisions, catalog) {
  const errors = [];
  if (decisions.schema_version !== 1 || !Array.isArray(decisions.decisions)) {
    return ['invalid code decisions schema'];
  }
  const byId = new Map(catalog.matrices.map(matrix => [matrix.id, matrix]));
  const seen = new Set();
  for (const [index, row] of decisions.decisions.entries()) {
    const label = `decision ${index + 1}`;
    if (!['function', 'route', 'top_level'].includes(row.kind) ||
        typeof row.path !== 'string' || !row.path.endsWith('.go') ||
        typeof row.symbol !== 'string' || !row.symbol ||
        typeof row.fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(row.fingerprint) ||
        typeof row.reason !== 'string' || !row.reason.trim()) {
      errors.push(`${label}: missing kind, Go path, symbol, fingerprint or reason`);
      continue;
    }
    const key = `${row.kind}:${row.path}:${row.symbol}:${row.fingerprint}`;
    if (seen.has(key)) errors.push(`${label}: duplicate ${key}`);
    seen.add(key);
    if (!['existing_rule', 'add_variant', 'new_matrix', 'not_security'].includes(row.decision)) {
      errors.push(`${label}: invalid decision`);
      continue;
    }
    const matrixIds = row.matrix_ids;
    const variantIds = row.variant_ids;
    if (!Array.isArray(matrixIds) || !Array.isArray(variantIds) ||
        matrixIds.some(id => typeof id !== 'string') ||
        variantIds.some(id => typeof id !== 'string')) {
      errors.push(`${label}: matrix_ids and variant_ids must be arrays of IDs`);
      continue;
    }
    if (row.decision === 'not_security') {
      if (matrixIds.length || variantIds.length) errors.push(`${label}: not_security must not claim matrix evidence`);
      continue;
    }
    if (!matrixIds.length || !variantIds.length) {
      errors.push(`${label}: a security decision needs matrix and variant IDs`);
      continue;
    }
    for (const id of matrixIds) {
      if (!byId.has(id)) errors.push(`${label}: unknown matrix ${id}`);
      else if (!variantIds.some(vid => byId.get(id).variants.some(variant => variant.id === vid))) {
        errors.push(`${label}: matrix ${id} has no named variant`);
      }
    }
    const validVariants = new Set(variantsFor(catalog, matrixIds));
    for (const id of variantIds) {
      if (!validVariants.has(id)) errors.push(`${label}: variant ${id} is not in the named matrices`);
    }
  }
  return errors;
}

function decisionDeltaError(decision, baseCatalog) {
  if (!baseCatalog || !['add_variant', 'new_matrix'].includes(decision.decision)) return null;
  const baseById = new Map(baseCatalog.matrices.map(matrix => [matrix.id, matrix]));
  if (decision.decision === 'new_matrix' &&
      !decision.matrix_ids.some(id => !baseById.has(id))) {
    return `${decision.path}:${decision.symbol}: new_matrix cites no matrix added in this change`;
  }
  if (decision.decision === 'add_variant') {
    const oldVariants = new Set(decision.matrix_ids.flatMap(id =>
      (baseById.get(id)?.variants ?? []).map(variant => variant.id)));
    if (!decision.variant_ids.some(id => !oldVariants.has(id))) {
      return `${decision.path}:${decision.symbol}: add_variant cites no variant added in this change`;
    }
  }
  return null;
}

export function buildReview(impact, catalog, decisions, baseCatalog = null) {
  const errors = validateDecisions(decisions, catalog);
  if (impact.schema_version !== 1 || !Array.isArray(impact.changed_functions) ||
      !Array.isArray(impact.changed_routes) || !Array.isArray(impact.changed_top_level)) {
    errors.push('invalid change impact schema');
  }
  if (errors.length) return { schema_version: 1, errors, rows: [], blocking: [] };

  const rows = [];
  const blocking = [];
  for (const changed of impact.changed_functions) {
    const direct = catalog.matrices.filter(matrix => sourceRefWithin(matrix, changed)).map(matrix => matrix.id);
    const fallback = catalog.matrices.filter(matrix =>
      matrix.ci_watch_seed.includes(changed.path)).map(matrix => matrix.id);
    const matrixIds = direct.length ? direct : fallback;
    const decision = findDecision(decisions, 'function', changed);
    if (decision) {
      const error = decisionDeltaError(decision, baseCatalog);
      if (error) errors.push(error);
    }
    const needsDecision = !decision;
    const row = {
      kind: 'function', path: changed.path, symbol: changed.symbol, status: changed.status,
      relation: direct.length ? 'SOURCE_REF_CANDIDATE' :
        fallback.length ? 'FILE_WATCH_CANDIDATE' : 'NO_CANDIDATE',
      candidate_matrix_ids: matrixIds,
      candidate_variant_ids: variantsFor(catalog, matrixIds),
      decision: decision?.decision ?? null,
      recorded_matrix_ids: decision?.matrix_ids ?? [],
      recorded_variant_ids: decision?.variant_ids ?? [],
      decision_reason: decision?.reason ?? null,
      review: needsDecision ? 'DECISION_REQUIRED' : 'DECISION_RECORDED',
    };
    rows.push(row);
    if (needsDecision) blocking.push(`${changed.path}:${changed.symbol}: changed function needs a coverage decision`);
  }
  for (const changed of impact.changed_routes) {
    const decision = findDecision(decisions, 'route', changed);
    if (decision) {
      const error = decisionDeltaError(decision, baseCatalog);
      if (error) errors.push(error);
    }
    const routeCandidates = changed.route === null ? [] : catalog.matrices
      .filter(matrix => matrix.reach.some(reach => {
        const separator = reach.indexOf(' ');
        return separator > 0 && reach.slice(0, separator) === changed.method &&
          reach.slice(separator + 1).endsWith(changed.route);
      })).map(matrix => matrix.id);
    const fileCandidates = catalog.matrices.filter(matrix =>
      matrix.ci_watch_seed.includes(changed.path)).map(matrix => matrix.id);
    const candidateIds = routeCandidates.length ? routeCandidates : fileCandidates;
    const row = {
      kind: 'route', path: changed.path, symbol: changed.signature, status: changed.status,
      owner: changed.owner, method: changed.method, route: changed.route,
      relation: routeCandidates.length ? 'ROUTE_SUFFIX_CANDIDATE' :
        fileCandidates.length ? 'FILE_WATCH_CANDIDATE' : 'NO_CANDIDATE',
      candidate_matrix_ids: candidateIds,
      candidate_variant_ids: variantsFor(catalog, candidateIds),
      decision: decision?.decision ?? null,
      recorded_matrix_ids: decision?.matrix_ids ?? [],
      recorded_variant_ids: decision?.variant_ids ?? [],
      decision_reason: decision?.reason ?? null,
      review: decision ? 'DECISION_RECORDED' : 'DECISION_REQUIRED',
    };
    rows.push(row);
    if (!decision) blocking.push(`${changed.path}:${changed.signature}: changed route registration needs a coverage decision`);
  }
  for (const changed of impact.changed_top_level) {
    const decision = findDecision(decisions, 'top_level', changed);
    if (decision) {
      const error = decisionDeltaError(decision, baseCatalog);
      if (error) errors.push(error);
    }
    const candidateIds = catalog.matrices.filter(matrix =>
      matrix.ci_watch_seed.includes(changed.path)).map(matrix => matrix.id);
    rows.push({kind: 'top_level', path: changed.path, symbol: '(outside named functions)',
      status: changed.status,
      relation: candidateIds.length ? 'FILE_WATCH_CANDIDATE' : 'NO_CANDIDATE',
      candidate_matrix_ids: candidateIds,
      candidate_variant_ids: variantsFor(catalog, candidateIds),
      decision: decision?.decision ?? null,
      recorded_matrix_ids: decision?.matrix_ids ?? [],
      recorded_variant_ids: decision?.variant_ids ?? [],
      decision_reason: decision?.reason ?? null,
      review: decision ? 'DECISION_RECORDED' : 'DECISION_REQUIRED'});
    if (!decision) blocking.push(`${changed.path}: top-level Go change needs a coverage decision`);
  }
  return {schema_version: 1, analysis_skipped: Boolean(impact.analysis_skipped),
    changed_files: impact.changed_files ?? [], rows, blocking, errors};
}

export function reviewMarkdown(review) {
  const lines = ['## Boundary change review', '',
    'This report identifies changed code and candidate checks. A matrix link is not proof that new behavior is covered.', ''];
  if (review.analysis_skipped) lines.push('No PR diff to review (full scheduled/manual run).', '');
  if (!review.rows.length && !review.analysis_skipped) lines.push('No changed Go symbols or route registrations.', '');
  for (const row of review.rows) {
    const label = `${row.path}:${row.symbol}`.replaceAll('`', "'");
    lines.push(`- **${row.review}** ${row.kind} \`${label}\` (${row.status})`);
    if (row.candidate_matrix_ids?.length) lines.push(`  - Candidate matrices: ${row.candidate_matrix_ids.join(', ')}`);
    if (row.decision) lines.push(`  - Recorded decision: ${row.decision}; ${row.decision_reason}`);
  }
  if (review.blocking.length) lines.push('', 'Unresolved coverage decisions:',
    ...review.blocking.map(item => `- ${item}`));
  if (review.errors.length) lines.push('', 'Report errors:', ...review.errors.map(item => `- ${item}`));
  return lines.join('\n') + '\n';
}

function main() {
  const args = process.argv.slice(2);
  const impactPath = flagValue(args, '--impact');
  const outputPath = flagValue(args, '--output');
  const markdownPath = flagValue(args, '--markdown-out');
  if (!impactPath || !outputPath) throw new Error('usage: boundary_review.mjs --impact FILE --output FILE [--markdown-out FILE]');
  const catalog = JSON.parse(fs.readFileSync(flagValue(args, '--catalog') ?? defaultCatalog, 'utf8'));
  const decisions = JSON.parse(fs.readFileSync(flagValue(args, '--decisions') ?? defaultDecisions, 'utf8'));
  const impact = JSON.parse(fs.readFileSync(impactPath, 'utf8'));
  const baseCatalog = impact.analysis_skipped || !impact.base ? null : JSON.parse(
    execFileSync('git', ['show', `${impact.base}:security/matrices/catalog.json`],
      {cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024}));
  const review = buildReview(impact, catalog, decisions, baseCatalog);
  fs.writeFileSync(outputPath, JSON.stringify(review, null, 2) + '\n');
  const markdown = reviewMarkdown(review);
  if (markdownPath) fs.writeFileSync(markdownPath, markdown);
  process.stdout.write(markdown);
  if (review.errors.length || review.blocking.length) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`ERROR: ${error.message}\n`); process.exitCode = 1; }
}
