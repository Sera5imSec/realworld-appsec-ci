import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyzeGoSource, compareSnapshots, tokenizeGo } from './change_impact.mjs';

const base = `package demo
type Record struct { OwnerID int }
func Delete(c *Context) {
  if record.OwnerID != user.ID { return }
  store.Delete(record)
}
func Register(router *Router) {
  router.DELETE("/:id", Delete)
}
`;

test('whitespace and ordinary comments do not mark a function changed', () => {
  const formatted = `package demo
type Record struct { OwnerID int }
// Ordinary comment only.
func Delete( c *Context ) {
  if record.OwnerID != user.ID { /* note */ return }
  store.Delete( record )
}
func Register(router *Router) { router.DELETE("/:id", Delete) }
`;
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': formatted });
  assert.deepEqual(report.changed_functions, []);
  assert.deepEqual(report.changed_routes, []);
  assert.deepEqual(report.changed_top_level, []);
  assert.deepEqual(report.changed_files, ['demo/routers.go']);
});

test('changed guard is attributed to its named function', () => {
  const changed = base.replace('record.OwnerID != user.ID', 'record.OwnerID == user.ID');
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': changed });
  assert.equal(report.changed_functions.length, 1);
  assert.equal(report.changed_functions[0].symbol, 'Delete');
  assert.equal(report.changed_functions[0].status, 'modified');
  assert.equal(report.changed_functions[0].start, 3);
  assert.equal(report.changed_functions[0].end, 6);
  assert.deepEqual(report.changed_routes, []);
  assert.deepEqual(report.changed_top_level, []);
});

test('new function and route registration are reported separately', () => {
  const changed = base + `func Patch(c *Context) { c.Save() }
func RegisterPatch(router *Router) { router.PATCH("/:id", Patch) }
`;
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': changed });
  assert.deepEqual(report.changed_functions.map((item) => [item.symbol, item.status]), [
    ['Patch', 'added'], ['RegisterPatch', 'added'],
  ]);
  assert.equal(report.changed_routes.length, 1);
  assert.equal(report.changed_routes[0].method, 'PATCH');
  assert.equal(report.changed_routes[0].route, '/:id');
  assert.equal(report.changed_routes[0].owner, 'RegisterPatch');
  assert.equal(report.changed_routes[0].status, 'added');
});

test('replacing one route with another reports removal and addition', () => {
  const changed = base.replace('"/:id", Delete', '"/:slug", Delete');
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': changed });
  assert.deepEqual(report.changed_routes.map((item) => item.status), ['removed', 'added']);
  assert.equal(report.changed_functions.length, 1);
  assert.equal(report.changed_functions[0].symbol, 'Register');
});

test('changing a route handler reports a modified registration', () => {
  const changed = base.replace('"/:id", Delete', '"/:id", OtherDelete');
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': changed });
  assert.equal(report.changed_routes.length, 1);
  assert.equal(report.changed_routes[0].status, 'modified');
});

test('comments, interpreted strings, raw strings and runes cannot create fake code', () => {
  const source = `package demo
// func Fake() { router.GET("/fake", Fake) }
/* router.POST("/fake", Fake) */
const Text = "func Fake() { router.DELETE(\\"/fake\\", Fake) }"
const Raw = \`router.GET("/fake", Fake)\`
const Rune = '{'
func Real() { println(Text) }
`;
  const parsed = analyzeGoSource(source, 'demo.go');
  assert.deepEqual(parsed.functions.map((item) => item.symbol), ['Real']);
  assert.deepEqual(parsed.routes, []);
  assert.equal(tokenizeGo(source).tokens.some((item) => item.text === 'Fake'), false);
});

test('method symbol and body changes are recognized', () => {
  const old = 'package demo\nfunc (item *Record) Save() { item.persist() }\n';
  const newer = old.replace('persist', 'validate');
  const report = compareSnapshots({ 'model.go': old }, { 'model.go': newer });
  assert.equal(report.changed_functions[0].symbol, '*Record.Save');
  assert.equal(report.changed_functions[0].status, 'modified');
});

test('top-level function types and literals are not named declarations', () => {
  const source = `package demo
type Handler func(c *Context) error
var callback = func(c *Context) error { return nil }
func Make() func() { return func() {} }
`;
  const parsed = analyzeGoSource(source, 'types.go');
  assert.deepEqual(parsed.functions.map((item) => item.symbol), ['Make']);
});

test('changed global state and Go directives are unattributed changes', () => {
  const changedGlobal = base.replace('OwnerID int', 'OwnerID string');
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': changedGlobal });
  assert.deepEqual(report.changed_functions, []);
  assert.deepEqual(report.changed_routes, []);
  assert.equal(report.changed_top_level[0].status, 'modified');
  const old = '//go:build linux\npackage demo\n';
  const newer = '//go:build windows\npackage demo\n';
  assert.equal(compareSnapshots({ 'tag.go': old }, { 'tag.go': newer }).changed_top_level.length, 1);
});

test('removed function is reported with old span', () => {
  const removed = base.replace(/func Delete\(c \*Context\) \{[\s\S]*?\n\}\n/, '');
  const report = compareSnapshots({ 'demo/routers.go': base }, { 'demo/routers.go': removed });
  assert.equal(report.changed_functions[0].symbol, 'Delete');
  assert.equal(report.changed_functions[0].status, 'removed');
  assert.equal(report.changed_functions[0].before_span.start, 3);
  assert.equal(report.changed_functions[0].after_span, null);
});

test('malformed or ambiguous source fails closed', () => {
  assert.throws(() => analyzeGoSource('package p\nfunc F() {\n', 'p.go'), /unclosed delimiter/);
  assert.throws(() => analyzeGoSource('package p\n/* missing', 'p.go'), /unclosed comment/);
  assert.throws(() => analyzeGoSource('package p\nfunc F()\n', 'p.go'), /bodyless function declaration/);
  assert.throws(() => analyzeGoSource('package p\nfunc F() {}\nfunc F() {}', 'p.go'), /duplicate function/);
  assert.throws(() => analyzeGoSource('package p\nvar x = "missing', 'p.go'), /unclosed quoted literal/);
  assert.throws(() => compareSnapshots(
    { 'routes.go': 'package p\nfunc Register(r *Router) { r.GET("/a", A); r.GET("/a", A) }' },
    { 'routes.go': 'package p\nfunc Register(r *Router) { r.GET("/a", A); r.GET("/a", B) }' },
  ), /ambiguous duplicate change key/);
});
