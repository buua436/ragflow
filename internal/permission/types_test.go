package permission

import "testing"

func TestWithTenantIDExplicitlySelectsTenant(t *testing.T) {
	ctx := WithIdentity(t.Context(), "actor", "request-tenant")
	ctx = WithTenantID(ctx, "resource-tenant")

	if got := UserIDFromContext(ctx); got != "actor" {
		t.Fatalf("user ID = %q, want actor", got)
	}
	if got := TenantIDFromContext(ctx); got != "resource-tenant" {
		t.Fatalf("tenant ID = %q, want resource-tenant", got)
	}
}
