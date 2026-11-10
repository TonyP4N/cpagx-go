import React, { useEffect, useState } from 'react';

type Profile = {
  source_provenance?: { collection_range?: string | {start?: string; end?: string}; mapping_evidence_ref?: string; timezone_basis?: string };
  mappings?: Array<{ asset_id?: string; destination_ip?: string; tag?: string; version?: string }>;
  rule_version?: string;
};

export default function ConfigDetails({ datasetId, configId }: {datasetId: string; configId: string}) {
  const [profile, setProfile] = useState<Profile>();
  const [error, setError] = useState('');
  useEffect(() => {
    const abort = new AbortController();
    setProfile(undefined); setError('');
    fetch('/api/v3/datasets/' + encodeURIComponent(datasetId) + '/configs/' + encodeURIComponent(configId), {
      credentials: 'same-origin', cache: 'no-store', signal: abort.signal,
    }).then(async response => {
      if (!response.ok) throw new Error('配置无法读取（HTTP ' + response.status + '）。请刷新并检查数据集权限。');
      const value = await response.json();
      if (value.config?.id !== configId) throw new Error('配置版本不一致，请重新选择。');
      if (!abort.signal.aborted) setProfile(value.document);
    }).catch(cause => { if (!abort.signal.aborted) setError(String(cause.message)); });
    return () => abort.abort();
  }, [datasetId, configId]);
  if (!profile) return <p role={error ? 'alert' : 'status'}>{error || '正在读取配置…'}</p>;
  const declaredRange = profile.source_provenance?.collection_range;
  const range = typeof declaredRange === 'string' ? declaredRange : declaredRange && (declaredRange.start || declaredRange.end)
    ? [declaredRange.start || '起点未知', declaredRange.end || '终点未知'].join(' 至 ') : '未声明';
  const mappings = Array.isArray(profile.mappings) ? profile.mappings : [];
  return <section className="wb-profile" aria-label="配置覆盖与设备映射">
    <h3>覆盖范围与设备映射</h3>
    <p>声明的采集范围 · {range}　时区依据 · {String(profile.source_provenance?.timezone_basis || '未声明')}</p>
    <p>设备映射 {mappings.length} 项　规则版本 · {profile.rule_version || '未声明'}</p>
    <details><summary>查看映射与完整配置</summary>
      {mappings.length ? <ul>{mappings.map((m,i) => <li key={i}>{m.destination_ip || '未知地址'} → {m.asset_id || '未知设备'} · {m.tag || '未知变量'} · {m.version || '无版本'}</li>)}</ul> : <p>此配置未声明分析设备映射。</p>}
      <pre>{JSON.stringify(profile,null,2)}</pre>
    </details>
  </section>;
}
