package store

import (
	"fmt"

	"github.com/dean-2/urGuard/backend/pkg/auditlog"
)

// OpenAuditLog opens the audit buckets in this store and signs checkpoints
// using its authority. Closing the store closes the log's database handle.
func (s *Store) OpenAuditLog(interval uint32) (*auditlog.Log, error) {
	s.authorityMu.Lock()
	defer s.authorityMu.Unlock()
	key, err := view(s, authority)
	if err != nil {
		return nil, err
	}
	return auditlog.Open(s.db, key, interval)
}

// OpenWitnessedAuditLog is the startup path for an enrolled control plane.
// The caller fetches the latest checkpoint from its authenticated witness.
// No writable log is returned when the local history fails verification.
func (s *Store) OpenWitnessedAuditLog(interval uint32, signed []byte) (*auditlog.Log, error) {
	log, err := s.OpenAuditLog(interval)
	if err != nil {
		return nil, err
	}
	report, err := log.VerifyAgainstCheckpoint(signed)
	if err != nil {
		return nil, err
	}
	if !report.Valid {
		return nil, fmt.Errorf("audit witness verification failed at sequence %d: %s", report.BrokenSeq, report.Reason)
	}
	return log, nil
}
