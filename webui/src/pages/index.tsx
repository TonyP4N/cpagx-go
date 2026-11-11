import { useEffect } from 'react';
import Head from 'next/head';
import LegacyHome from '../legacy/Home';

/** The public proxy redirects before rendering; this also covers client-side links. */
function WorkbenchEntry() {
  useEffect(() => {
    window.location.replace('/workbench/' + window.location.search);
  }, []);
  return <>
    <Head><title>CPAG · 进入工作台</title></Head>
    <main><p role="status">正在进入新版工作台…</p><a href="/workbench/">打开新版工作台</a></main>
  </>;
}

export default process.env.NEXT_PUBLIC_CPAG_ENTRY === 'legacy' ? LegacyHome : WorkbenchEntry;
