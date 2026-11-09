//go:build !ee

package service

import (
	"testing"

	"ragflow/internal/dao"
	"ragflow/internal/engine"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
)

func TestUpdateMemoryTeamMemberResolvesModelsAgainstOwnerTenant(t *testing.T) {
	setupMemoryMessageTestDB(t)

	status := "1"
	if err := dao.DB.Create(&entity.Memory{UserID: "owner-user",
		ID: "mem-model", Name: "Shared model memory", TenantID: "memory-tenant", MemoryType: dao.MemoryTypeRaw,
		StorageType: "table", EmbdID: "old-embd", LLMID: "old-llm",
		Permissions: string(entity.TenantPermissionTeam), MemorySize: MemorySizeLimit,
	}).Error; err != nil {
		t.Fatalf("seed memory: %v", err)
	}
	for _, membership := range []entity.UserTenant{
		{ID: "ut-owner", UserID: "owner-user", TenantID: "memory-tenant", Role: string(permission.RoleOwner), Status: &status},
		{ID: "ut-member", UserID: "member-1", TenantID: "memory-tenant", Role: string(permission.RoleNormal), InvitedBy: "owner-user", Status: &status},
	} {
		if err := dao.DB.Create(&membership).Error; err != nil {
			t.Fatalf("seed user tenant: %v", err)
		}
	}
	ctx := serviceTestContext(t, "member-1", "memory-tenant", "owner-user")
	grantServiceTestResource(t, "memory-tenant", "memory", "mem-model", "member-1", testResourcePermissionRead|testResourcePermissionWrite)

	for _, row := range []struct {
		providerID string
		userID     string
		tenantID   string
		modelID    string
	}{
		{providerID: "provider-owner", userID: "owner-user", tenantID: "memory-tenant", modelID: "tenant-llm-owner"},
		{providerID: "provider-member", userID: "member-1", tenantID: "member-1", modelID: "tenant-llm-member"},
	} {
		if err := dao.DB.Create(&entity.TenantModelProvider{ID: row.providerID, UserID: row.userID, ProviderName: "OpenAI", TenantID: row.tenantID}).Error; err != nil {
			t.Fatalf("seed provider %s: %v", row.providerID, err)
		}
		instanceID := row.providerID + "-default"
		if err := dao.DB.Create(&entity.TenantModelInstance{ID: instanceID, InstanceName: "default", ProviderID: row.providerID, APIKey: "test-key", Status: "active"}).Error; err != nil {
			t.Fatalf("seed instance %s: %v", instanceID, err)
		}
		if err := dao.DB.Create(&entity.TenantModel{
			ID: row.modelID, ModelName: "gpt-4o", ProviderID: row.providerID, InstanceID: instanceID,
			ModelType: int(entity.ModelTypeChat), Status: "active",
		}).Error; err != nil {
			t.Fatalf("seed model %s: %v", row.modelID, err)
		}
	}

	llmID := "gpt-4o@default@OpenAI"
	if _, err := NewMemoryService(dao.DB, engine.Get()).UpdateMemory(ctx, "mem-model", &UpdateMemoryRequest{LLMID: &llmID}); err != nil {
		t.Fatalf("UpdateMemory model error = %v", err)
	}
	updated, err := dao.NewMemoryDAO().GetByID(t.Context(), dao.DB, "mem-model")
	if err != nil {
		t.Fatalf("get updated memory: %v", err)
	}
	if updated.TenantLLMID == nil || *updated.TenantLLMID != "tenant-llm-owner" {
		t.Fatalf("tenant_llm_id = %v, want tenant-llm-owner", updated.TenantLLMID)
	}
}
