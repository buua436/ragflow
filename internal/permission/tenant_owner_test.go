package permission

import (
	"errors"
	"net/url"
	"testing"

	"ragflow/internal/entity"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestTenantOwnerMembershipUsesMembershipRelation(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+url.QueryEscape(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.UserTenant{}); err != nil {
		t.Fatalf("migrate user_tenant: %v", err)
	}
	status := string(entity.StatusValid)
	owner := entity.UserTenant{ID: "owner-membership", UserID: "user-owner", TenantID: "tenant-team", Role: string(RoleOwner), Status: &status}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatalf("create owner membership: %v", err)
	}

	got, err := TenantOwnerMembership(t.Context(), db, owner.TenantID)
	if err != nil {
		t.Fatalf("TenantOwnerMembership(): %v", err)
	}
	if got.ID != owner.ID || got.UserID != owner.UserID || got.TenantID != owner.TenantID {
		t.Fatalf("TenantOwnerMembership() = %#v, want persisted owner membership %#v", got, owner)
	}
}

func TestTenantOwnerMembershipDoesNotInferMissingOwner(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+url.QueryEscape(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.UserTenant{}); err != nil {
		t.Fatalf("migrate user_tenant: %v", err)
	}
	if _, err := TenantOwnerMembership(t.Context(), db, "personal-tenant"); !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("TenantOwnerMembership() error = %v, want membership not found", err)
	}
}
