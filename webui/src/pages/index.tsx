import { useEffect } from 'react';
import Head from 'next/head';

/** The public proxy redirects before rendering; this also covers client-side links. */
export default function HomePage() {
  useEffect(() => {
    window.location.replace('/workbench/' + window.location.search);
  }, []);
  return <>
    <Head><title>CPAG · 进入工作台</title></Head>
    <main><p role="status">正在进入新版工作台…</p><a href="/workbench/">打开新版工作台</a></main>
  </>;
}
