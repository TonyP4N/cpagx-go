// Run with node scripts/check-history-model.cjs; no browser or fixture server required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const Module = require('node:module');
const compiled = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/components/r20/historyModel.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } });
const model = new Module('history-model'); model._compile(compiled.outputText, 'history-model.cjs');
const { evaluationEvidenceTargets, historicalBacklog, historySelection, visibleBacklog, normalizeRevisions, snapshotCount, number } = model.exports;
(async () => {
  assert.deepEqual(evaluationEvidenceTargets({event_id:'p'}, 'false_positives'), {prediction:{id:'p'}, reference:undefined});
  assert.deepEqual(evaluationEvidenceTargets({event_id:'g'}, 'false_negatives'), {prediction:undefined, reference:{id:'g'}});
  assert.deepEqual(evaluationEvidenceTargets({prediction_id:'p',reference_id:'g'}, 'matches'), {prediction:{id:'p'}, reference:{id:'g'}});
  assert.deepEqual(evaluationEvidenceTargets({event:{id:'old'}}, 'disputed_references'), {prediction:undefined, reference:{id:'old'}});
  const samples = [
    { arrival_seq: 1, available_at: '2026-01-01T00:00:01Z', waiting_operations: 1 },
    { arrival_seq: 2, available_at: '2026-01-01T00:00:02Z', waiting_operations: 2 },
    { arrival_seq: 2, available_at: '2026-01-01T00:00:03Z', waiting_operations: 0 },
    { arrival_seq: 3, available_at: '2026-01-01T00:00:04Z', waiting_operations: 5 },
  ];
  for (const snapshot of [
    { arrival_seq: 0, available_at: '2026-01-01T00:00:00Z' },
    { arrival_seq: 1, available_at: '2026-01-01T00:00:03Z' },
    { arrival_seq: 2, available_at: '2026-01-01T00:00:02Z' },
    { arrival_seq: 2, available_at: '2026-01-01T00:00:03Z' },
  ]) assert.deepEqual(await historicalBacklog(samples.length, snapshot, async i => samples[i]), visibleBacklog(samples, snapshot) ?? null);
  assert.equal(await historicalBacklog(0, {}, async () => { throw Error('must not read'); }), null);
  assert.equal(snapshotCount({ counts: { snapshots: 12 } }), 12);
  assert.equal(snapshotCount({ data: { replay: { snapshot_count: 4 } } }), 4);
  assert.equal(normalizeRevisions({ revisions: [{ revision_number: 1 }], total: 11 }).returned, 1);
  assert.equal(normalizeRevisions({ items: [], total: 0, returned: 0 }).returned, 0);
  assert.equal(number(null), '未提供'); assert.equal(number(0), '0');
  assert.equal(historySelection('?dataset=d&run=r&view=replay&snapshot=12', 'snapshot', 'r', 'd'), '12');
  for (const search of ['?dataset=d&run=other&snapshot=12', '?dataset=d&run=r&snapshot=-1', '?dataset=d&run=r&snapshot=65000', '?dataset=d&run=r&snapshot=1&snapshot=2']) assert.equal(historySelection(search, 'snapshot', 'r', 'd'), '');
  assert.equal(historySelection('?dataset=d&run=r&evaluation=eval_1', 'evaluation', 'r', 'd'), 'eval_1');
  assert.equal(historySelection('?dataset=d&run=r&evaluation=../other', 'evaluation', 'r', 'd'), '');
  console.log('history model: prefix isolation, initial/clock-advance backlog, revision paging and zero/null display passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
