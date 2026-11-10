package catalog

import "errors"

func validateDispatchConfig(c Config) error {
	if c.DispatchMode != "" && c.DispatchMode != "poll" && c.DispatchMode != "rabbit-canary" {
		return errors.New("unsupported dispatch mode")
	}
	if c.DispatcherToken != "" && (len(c.DispatcherToken) < 24 || c.DispatcherToken == c.WorkerToken || c.DispatcherToken == c.CoordinatorToken) {
		return errors.New("distinct dispatcher token of at least 24 characters required")
	}
	if len(c.RabbitCanaryDatasetIDs) > 1000 {
		return errors.New("bounded rabbit canary dataset allowlist required")
	}
	for _, id := range c.RabbitCanaryDatasetIDs {
		if !safeID.MatchString(id) {
			return errors.New("invalid canary dataset identity")
		}
	}
	if c.DispatchMode == "rabbit-canary" && (len(c.RabbitCanaryDatasetIDs) == 0 || c.DispatcherToken == "") {
		return errors.New("rabbit canary requires explicit datasets and dispatcher token")
	}
	return nil
}
func (s *Server) dispatchPartition(dataset string) string {
	if s.cfg.DispatchMode == "rabbit-canary" {
		for _, id := range s.cfg.RabbitCanaryDatasetIDs {
			if id == dataset {
				return "rabbit-v3"
			}
		}
	}
	return "poll"
}
