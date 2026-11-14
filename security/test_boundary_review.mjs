import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import { buildReview, validateDecisions } from './boundary_review.mjs';
import {compareSnapshots} from './change_impact.mjs';

const catalog = {matrices: [{
  id: 'RW-COMMENT-03',
  ci_watch_seed: ['articles/routers.go'],
  source_refs: ['articles/routers.go:203'],
  reach: ['DELETE /api/articles/:slug/comments/:id'],
  variants: [{id: 'RW-COMMENT-03-P01'}, {id: 'RW-COMMENT-03-N01'}],
}]};
const empty = {schema_version: 1, decisions: []};
const fingerprint = 'a'.repeat(64);
const base = {schema_version: 1, analysis_skipped: false,
  changed_files: ['articles/routers.go'], changed_functions: [],
  changed_routes: [], changed_top_level: []};
const functionChange = (status, span, symbol = 'ArticleCommentDelete') => ({
  path: 'articles/routers.go', symbol, status,
  before_hash: status === 'added' ? null : fingerprint,
  after_hash: status === 'removed' ? null : fingerprint,
  after_span: status === 'removed' ? null : span,
  before_span: status === 'added' ? null : span,
});

test('changed guard names its direct matrix and variants but still needs semantic review', () => {
  const impact = {...base, changed_functions: [functionChange('modified', {start: 201, end: 224})]};
  const review = buildReview(impact, catalog, empty);
  assert.equal(review.blocking.length, 1);
  assert.equal(review.rows[0].relation, 'SOURCE_REF_CANDIDATE');
  assert.deepEqual(review.rows[0].candidate_matrix_ids, ['RW-COMMENT-03']);
  assert.deepEqual(review.rows[0].candidate_variant_ids, ['RW-COMMENT-03-P01', 'RW-COMMENT-03-N01']);
  assert.equal(review.rows[0].review, 'DECISION_REQUIRED');
});

test('new helper without a direct rule link requires a recorded decision', () => {
  const impact = {...base, changed_functions: [functionChange('added', {start: 230, end: 235}, 'newHelper')]};
  const review = buildReview(impact, catalog, empty);
  assert.equal(review.rows[0].relation, 'FILE_WATCH_CANDIDATE');
  assert.equal(review.rows[0].review, 'DECISION_REQUIRED');
  assert.equal(review.blocking.length, 1);

  const classified = {schema_version: 1, decisions: [{
    kind: 'function', path: 'articles/routers.go', symbol: 'newHelper',
    fingerprint,
    decision: 'existing_rule', matrix_ids: ['RW-COMMENT-03'],
    variant_ids: ['RW-COMMENT-03-N01'], reason: 'Helper enforces the same comment ownership rule.',
  }]};
  assert.deepEqual(buildReview(impact, catalog, classified).blocking, []);
  const stale = structuredClone(classified);
  stale.decisions[0].fingerprint = 'b'.repeat(64);
  assert.equal(buildReview(impact, catalog, stale).blocking.length, 1);
});

test('new function still needs review even when a source reference points inside it', () => {
  const impact = {...base, changed_functions: [functionChange('added', {start: 200, end: 210})]};
  const review = buildReview(impact, catalog, empty);
  assert.equal(review.blocking.length, 1);
  assert.equal(review.rows[0].relation, 'SOURCE_REF_CANDIDATE');
});

test('changed route registration requires an explicit decision', () => {
  const route = {path: 'articles/routers.go', owner: 'ArticlesRegister', method: 'DELETE',
    route: '/:slug/comments/:id', signature: 'router.DELETE|/:slug/comments/:id|ArticleCommentDelete',
    status: 'modified', before_hash: 'b'.repeat(64), after_hash: fingerprint};
  const impact = {...base, changed_routes: [route]};
  assert.equal(buildReview(impact, catalog, empty).blocking.length, 1);
  const classified = {schema_version: 1, decisions: [{
    kind: 'route', path: route.path, symbol: route.signature,
    fingerprint,
    decision: 'existing_rule', matrix_ids: ['RW-COMMENT-03'],
    variant_ids: ['RW-COMMENT-03-N01'], reason: 'The same comment identity rule applies.',
  }]};
  assert.deepEqual(buildReview(impact, catalog, classified).blocking, []);
});

test('catalog IDs and variant membership are checked, not only a written reason', () => {
  const invalid = {schema_version: 1, decisions: [{
    kind: 'function', path: 'articles/routers.go', symbol: 'newHelper',
    fingerprint,
    decision: 'existing_rule', matrix_ids: ['RW-COMMENT-03'],
    variant_ids: ['RW-OTHER-N01'], reason: 'Some reason',
  }]};
  assert.match(validateDecisions(invalid, catalog).join(' '), /not in the named matrices/);
});

test('add_variant and new_matrix decisions require a real catalog delta', () => {
  const impact = {...base, changed_functions: [functionChange('modified', {start: 201, end: 224})]};
  const decision = {
    kind: 'function', path: 'articles/routers.go', symbol: 'ArticleCommentDelete', fingerprint,
    decision: 'add_variant', matrix_ids: ['RW-COMMENT-03'],
    variant_ids: ['RW-COMMENT-03-N01'], reason: 'A new negative case checks the changed rule.',
  };
  const recorded = {schema_version: 1, decisions: [decision]};
  assert.match(buildReview(impact, catalog, recorded, catalog).errors.join(' '), /no variant added/);
  const oldCatalog = {matrices: [{...catalog.matrices[0], variants: [{id: 'RW-COMMENT-03-P01'}]}]};
  assert.deepEqual(buildReview(impact, catalog, recorded, oldCatalog).errors, []);
  decision.decision = 'new_matrix';
  assert.match(buildReview(impact, catalog, recorded, catalog).errors.join(' '), /no matrix added/);
  assert.deepEqual(buildReview(impact, catalog, recorded, {matrices: []}).errors, []);
});

test('top-level change stays visible even without a changed named function', () => {
  const impact = {...base, changed_top_level: [{path: 'articles/routers.go', status: 'modified',
    before_hash: 'b'.repeat(64), after_hash: fingerprint}]};
  const review = buildReview(impact, catalog, empty);
  assert.equal(review.rows[0].kind, 'top_level');
  assert.equal(review.rows[0].review, 'DECISION_REQUIRED');
  assert.equal(review.blocking.length, 1);
  const classified = {schema_version: 1, decisions: [{
    kind: 'top_level', path: 'articles/routers.go', symbol: '(outside named functions)',
    fingerprint, decision: 'not_security', matrix_ids: [], variant_ids: [],
    reason: 'Import order changed without changing runtime behavior.',
  }]};
  assert.deepEqual(buildReview(impact, catalog, classified).blocking, []);
});

test('real comment-article guard change points reviewers to the comment identity matrix', () => {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const source = fs.readFileSync(path.join(repo, 'articles/routers.go'), 'utf8');
  const guard = 'if commentModel.ArticleID != articleModel.ID {';
  assert.equal(source.split(guard).length, 2);
  const altered = source.replace(guard, 'if commentModel.ArticleID != articleModel.ID && false {');
  const impact = compareSnapshots({'articles/routers.go': source}, {'articles/routers.go': altered});
  const actualCatalog = JSON.parse(fs.readFileSync(path.join(repo, 'security/matrices/catalog.json'), 'utf8'));
  const review = buildReview(impact, actualCatalog, empty);
  const handler = review.rows.find(row => row.kind === 'function' && row.symbol === 'ArticleCommentDelete');
  assert.ok(handler);
  assert.ok(handler.candidate_matrix_ids.includes('RW-COMMENT-03'));
  assert.equal(handler.review, 'DECISION_REQUIRED');
  assert.equal(review.blocking.length, 1);
  const classified = {schema_version: 1, decisions: [{
    kind: 'function', path: 'articles/routers.go', symbol: 'ArticleCommentDelete',
    fingerprint: impact.changed_functions[0].after_hash,
    decision: 'existing_rule', matrix_ids: ['RW-COMMENT-03'],
    variant_ids: ['RW-COMMENT-03-N01'],
    reason: 'Existing comment identity case checks this guard.',
  }]};
  assert.deepEqual(buildReview(impact, actualCatalog, classified).blocking, []);
});

test('a router group prefix change is blocked even without a direct route-call change', () => {
  const before = 'package main\nfunc register() { router.Group("/api") }\n';
  const after = 'package main\nfunc register() { router.Group("/admin") }\n';
  const impact = compareSnapshots({'hello.go': before}, {'hello.go': after});
  assert.equal(impact.changed_routes.length, 0);
  assert.equal(impact.changed_functions.length, 1);
  const review = buildReview(impact, catalog, empty);
  assert.equal(review.blocking.length, 1);
  assert.match(review.blocking[0], /hello\.go:register/);
});
