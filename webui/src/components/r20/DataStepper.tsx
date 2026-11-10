const steps = [
  { id: 'wb-step-overview', label: '批次概况' },
  { id: 'wb-step-files', label: '原件上传' },
  { id: 'wb-step-config', label: '配置版本' },
  { id: 'wb-step-preflight', label: '预检' },
  { id: 'wb-step-submit', label: '提交运行' },
] as const;

export function DataStepper({ done, hints }: { done: boolean[]; hints: string[] }) {
  return <nav aria-label="数据接收步骤">
    <ol className="wb-stepper">{steps.map((step, index) => {
      const complete = Boolean(done[index]);
      const current = done.findIndex(item => !item);
      const state = complete ? 'done' : index === (current < 0 ? steps.length - 1 : current) ? 'current' : 'todo';
      const hint = hints[index] || (complete ? '已具备' : '未完成');
      return <li key={step.id}><button type="button" data-done={complete ? 'true' : 'false'} data-state={state} onClick={() => document.getElementById(step.id)?.scrollIntoView({ block: 'start' })}><span className="wb-step-index">{complete ? '✓' : index + 1}</span>{step.label}<span className="sr-only">，{hint}</span></button></li>;
    })}</ol>
  </nav>;
}
