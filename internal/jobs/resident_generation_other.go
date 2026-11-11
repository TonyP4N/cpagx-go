//go:build !linux && !darwin

package jobs

func verifyComposeRegistration(string, ResidentExecution) error { return ErrInvalidProof }
func verifyComposeTermination(string, ResidentExecution) error  { return ErrInvalidProof }
