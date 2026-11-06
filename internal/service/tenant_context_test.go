package service

import (
	"errors"
	"testing"

	"ragflow/internal/permission"
)

func TestRequireCurrentTenantIDRequiresSelectedTenant(t *testing.T) {
	if _, err := requireCurrentTenantID(permission.WithIdentity(t.Context(), "actor", "")); !errors.Is(err, permission.ErrTenantContextMissing) {
		t.Fatalf("requireCurrentTenantID() error = %v, want ErrTenantContextMissing", err)
	}
}

func TestRequireCurrentTenantIDValidatesSelectedMembership(t *testing.T) {
	db := setupServiceTestDB(t)
	pushServiceDB(t, db)
	ctx := serviceTestContext(t, "actor", "team")

	got, err := requireCurrentTenantID(ctx)
	if err != nil {
		t.Fatalf("requireCurrentTenantID() error = %v", err)
	}
	if got != "team" {
		t.Fatalf("tenant ID = %q, want team", got)
	}
}
