'use strict';

function activity(name, work) {
  print(JSON.stringify({ activity: name, phase: 'begin', timestampMs: Date.now() }));
  if (typeof d8.zoneMemoryMarker === 'function') d8.zoneMemoryMarker(name, true);
  work();
  if (typeof d8.zoneMemoryMarker === 'function') d8.zoneMemoryMarker(name, false);
  print(JSON.stringify({ activity: name, phase: 'end', timestampMs: Date.now() }));
}

let records;
activity('build-records', () => {
  records = Array.from({ length: 100000 }, (_, i) => ({ i, text: `record-${i}` }));
});
activity('use-records', () => {
  const until = Date.now() + 500;
  let total = 0;
  while (Date.now() < until) {
    for (const record of records) total += record.i;
  }
  if (!Number.isFinite(total)) throw new Error('Invalid result.');
});
records = null;
print(JSON.stringify({
  runComplete: true,
  results: [{ name: 'build-records' }, { name: 'use-records' }]
}));
