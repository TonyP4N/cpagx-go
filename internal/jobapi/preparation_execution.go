package jobapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"
)

type preparationExecutionKey struct{}
type PreparationExecution struct {
	LockFile      *os.File
	TemporaryRoot string
}

func WithPreparationExecution(ctx context.Context, lock *os.File, temporaryRoot string) context.Context {
	return context.WithValue(ctx, preparationExecutionKey{}, PreparationExecution{lock, temporaryRoot})
}
func PreparationExecutionFrom(ctx context.Context) (PreparationExecution, bool) {
	value, ok := ctx.Value(preparationExecutionKey{}).(PreparationExecution)
	return value, ok
}

// The inherited lock survives a killed Go parent until the actual Python PID
// exits. The Python launcher has independent wall/CPU/memory/file hard bounds.
func GuardPreparationCommand(ctx context.Context, args []string) ([]string, []*os.File, error) {
	policy, ok := PreparationExecutionFrom(ctx)
	if !ok {
		return args, nil, nil
	}
	if policy.LockFile == nil || len(args) < 2 || args[0] != "-m" || (args[1] != "cpag_core.evaluation_artifacts" && args[1] != "cpag_core.replay_spool_cli") {
		return nil, nil, errors.New("unlisted preparation command")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, errors.New("preparation requires a finite deadline")
	}
	seconds := int(math.Ceil(time.Until(deadline).Seconds()))
	if seconds < 1 {
		return nil, nil, context.DeadlineExceeded
	}
	if seconds > 1800 {
		seconds = 1800
	}
	prefix := []string{"-m", "cpag_core.evaluation_preparation_guard", "--seconds", fmt.Sprint(seconds), "--module", args[1], "--"}
	return append(prefix, args[2:]...), []*os.File{policy.LockFile}, nil
}
