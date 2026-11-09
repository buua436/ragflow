//go:build !ee

package service

import (
	"strings"
	"testing"

	"ragflow/internal/common"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
)

func TestListProvidersOfTenantIncludesReadableProviderOwnedByAnotherUser(t *testing.T) {
	db := setupModelProviderServiceTestDB(t)
	if err := db.AutoMigrate(&entity.Tenant{}); err != nil {
		t.Fatalf("migrate tenant table: %v", err)
	}
	useModelProviderServiceTestDB(t, db)
	status := entity.TenantMembershipStatusJoined
	if err := db.Create(&entity.UserTenant{
		ID: "tenant-owner-membership", UserID: "tenant-owner", TenantID: "tenant-2",
		Role: string(permission.RoleOwner), Status: &status,
	}).Error; err != nil {
		t.Fatalf("create tenant owner membership: %v", err)
	}
	ctx := serviceTestContext(t, "reader", "tenant-2")
	tenantName := "Shared Tenant"
	if err := db.Create(&entity.Tenant{ID: "tenant-2", Name: &tenantName}).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := db.Create(&entity.TenantModelProvider{
		ID: "shared-provider", UserID: "tenant-owner", TenantID: "tenant-2", ProviderName: "OpenAI",
	}).Error; err != nil {
		t.Fatalf("create shared tenant provider: %v", err)
	}
	if err := db.Create(&entity.TenantModelInstance{
		ID: "shared-instance", ProviderID: "shared-provider", InstanceName: "shared", APIKey: "sk-test", Status: "active", Extra: "{}",
	}).Error; err != nil {
		t.Fatalf("create shared provider instance: %v", err)
	}
	if err := db.Create(&entity.TenantModel{
		ID: "shared-model", ProviderID: "shared-provider", InstanceID: "shared-instance", ModelName: "gpt-shared",
		ModelType: int(entity.ModelTypeChat), Status: "active", Extra: "{}",
	}).Error; err != nil {
		t.Fatalf("create shared model: %v", err)
	}

	providers, code, err := NewModelProviderService().ListProvidersOfTenant(ctx)
	if err != nil || code != common.CodeSuccess {
		t.Fatalf("ListProvidersOfTenant() = (%v, %v), want success", code, err)
	}
	name := ""
	if len(providers) == 1 {
		name, _ = providers[0]["name"].(string)
	}
	if len(providers) != 1 || !strings.EqualFold(name, "OpenAI") {
		t.Fatalf("ListProvidersOfTenant() = %v, want the readable provider owned by tenant-owner", providers)
	}

	models, code, err := NewModelProviderService().ListModelsForUserInTenant(ctx, "tenant-2", "")
	if err != nil || code != common.CodeSuccess {
		t.Fatalf("ListModelsForUserInTenant() = (%v, %v), want success", code, err)
	}
	if len(models) != 1 || models[0]["name"] != "gpt-shared" {
		t.Fatalf("ListModelsForUserInTenant() = %v, want the model under the readable provider", models)
	}
}
