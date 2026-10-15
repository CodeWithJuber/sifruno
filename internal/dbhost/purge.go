package dbhost

import (
	"context"
	"fmt"
)

// PurgeOwner drops every database and user owned by a terminated account.
// Called from removeacct after the OS account is gone. Each item is
// attempted independently; failures are collected, never hidden — the
// caller logs them into the removal step output.
func (s *LocalService) PurgeOwner(ctx context.Context, owner string) (purged []string, errs []string) {
	dbs := s.Registry.databases(owner)
	for _, d := range dbs {
		if _, err := s.Run.Run(ctx, sqlDropDatabase(d.Name)); err != nil {
			errs = append(errs, fmt.Sprintf("database %s: %v", d.Name, err))
			continue
		}
		if err := s.Registry.dropDatabase(d.Name); err != nil {
			errs = append(errs, fmt.Sprintf("registry %s: %v", d.Name, err))
			continue
		}
		purged = append(purged, "database:"+d.Name)
	}
	users := s.Registry.users(owner)
	for _, u := range users {
		if _, err := s.Run.Run(ctx, sqlDropUser(u.Name, s.host())); err != nil {
			errs = append(errs, fmt.Sprintf("user %s: %v", u.Name, err))
			continue
		}
		if err := s.Registry.dropUser(u.Name); err != nil {
			errs = append(errs, fmt.Sprintf("registry %s: %v", u.Name, err))
			continue
		}
		purged = append(purged, "user:"+u.Name)
	}
	return purged, errs
}
