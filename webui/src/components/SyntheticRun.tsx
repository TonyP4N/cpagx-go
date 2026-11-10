import React, { useEffect, useState } from 'react';
const API = '/api/v2/cpag';
async function request(path: string, init?: RequestInit) {
  const response = await fetch(API + path, init);
  const value = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(value));
  return value;
}
export default function SyntheticRun() {
  const [files, setFiles] = useState<Record<string, File>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [task, setTask] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [artifacts, setArtifacts] = useState<any>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const id = task?.id || task?.task_id;
  const terminal = ['completed', 'failed'].includes(task?.status);
  useEffect(() => {
    if (!id || terminal) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const status = await request(`/status/${encodeURIComponent(id)}`);
        if (cancelled) return;
        if (status.status === 'completed') {
          const [output, inventory] = await Promise.all([request(`/result/${id}/json`), request(`/artifacts/${id}`)]);
          if (cancelled) return;
          setResult(output); setArtifacts(inventory);
        }
        setTask(status);
      } catch (err) { if (!cancelled) setError(String(err)); }
    };
    void poll();
    const timer = window.setInterval(poll, 1500);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [id, terminal]);
  async function submit() {
    setBusy(true); setError(''); setResult(null); setArtifacts(null); setTask(null);
    try {
      const body = new FormData();
      Object.entries(files).forEach(([field, file]) => body.append(field, file));
      body.append('synthetic_confirmed', 'true');
      setTask(await request('/synthetic', { method: 'POST', body }));
    } catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  }
  return <section aria-label="Synthetic M1 verification" className="mb-6 bg-white/80 rounded-2xl shadow-xl border border-slate-200 p-6 space-y-4">
    <h2 className="text-xl font-semibold">Synthetic M1 verification</h2>
    <p className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg p-3">Synthetic demonstration only. This checks upload, execution, results and downloads; it does not establish industrial validity, causal links, attack detection accuracy or CIP protocol coverage.</p>
    <p className="text-sm text-slate-600">Use tests/fixtures/synthetic inputs and profiles/synthetic-demo.json. Normalized network JSONL is not raw packet decoding.</p>
    <div className="grid md:grid-cols-3 gap-4">{[['network_file', 'Synthetic network JSONL', '.jsonl'], ['process_file', 'Synthetic process CSV', '.csv'], ['profile_file', 'Synthetic profile JSON', '.json']].map(([field, label, accept]) => <label key={field} className="text-sm font-medium">{label}<input aria-label={label} type="file" accept={accept} className="block mt-2 w-full text-sm" onChange={event => {
      const file = event.target.files?.[0];
      setFiles(previous => { const next = { ...previous }; if (file) next[field] = file; else delete next[field]; return next; });
    }} /></label>)}</div>
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />I confirm all three inputs are synthetic test data.</label>
    <button disabled={busy || !confirmed || Object.keys(files).length !== 3} onClick={submit} className="rounded-xl px-5 py-3 bg-emerald-700 text-white disabled:bg-slate-300">{busy ? 'Submitting…' : 'Run synthetic verification'}</button>
    {error && <p role="alert" className="text-red-700">{error}</p>}
    {task && <div aria-live="polite" className="text-sm"><p>Task: {id} · {task.status}</p>{task.error && <pre>{JSON.stringify(task.error)}</pre>}</div>}
    {result && <div><h3 className="font-semibold">Synthetic result and evidence</h3><pre className="text-xs max-h-80 overflow-auto bg-slate-50 rounded-lg p-3">{JSON.stringify(result, null, 2)}</pre></div>}
    {artifacts && <div><h3 className="font-semibold mb-2">Download run artifacts</h3><div className="flex flex-wrap gap-3">{artifacts.files.map((file: { filename: string }) => <a key={file.filename} className="text-emerald-800 underline text-sm" href={`${API}/download/${encodeURIComponent(id)}/${encodeURIComponent(file.filename)}`} download>{file.filename}</a>)}</div><details className="mt-3 text-xs"><summary>Artifact checksums and manifest</summary><pre className="overflow-auto">{JSON.stringify(artifacts, null, 2)}</pre></details></div>}
  </section>;
}
