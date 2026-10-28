# CI 退出回执清理窗口

39b8b3610431c574bb5c0631eb000174e7f0274b 的 CI 40710256189 在 test_worker_sigkill_parent_pipe_stops_child 失败：Directory not empty: attempt-1.worker。计算子进程消失先于守护进程写入原子退出回执，测试过早进入临时目录清理。首次CI原日志完整保留，见 validation-round19-core-manifest-binding/ci-39b8b36-cleanup-failure.log。

仅修正测试同步：子进程退出后还必须在5秒内收到退出回执，核对child_pid、group_exited、parent_disconnected、attempt。不忽略清理异常，不放宽生产退出条件。15项Worker本地回归通过，见同目录worker-receipt-regression.log。最终远端CI另行绑定最终提交，不能用本次本地通过代替。
