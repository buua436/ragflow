//go:build !ee

package permission

import (
	"context"
	"net/url"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"ragflow/internal/entity"
)

func TestDatabaseCheckerScopesChatChannelsToTenantMembers(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+url.QueryEscape(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.ChatChannel{}, &entity.UserTenant{}); err != nil {
		t.Fatalf("migrate chat-channel permission tables: %v", err)
	}

	valid := "1"
	channels := []entity.ChatChannel{
		{ID: "team-channel", UserID: "tenant-owner", TenantID: "tenant-a", Name: "team", Channel: "slack", Config: entity.JSONMap{}, Status: 1},
		{ID: "inactive-channel", UserID: "tenant-owner", TenantID: "tenant-a", Name: "inactive", Channel: "slack", Config: entity.JSONMap{}, Status: 1},
		{ID: "other-channel", UserID: "other-owner", TenantID: "tenant-b", Name: "other", Channel: "slack", Config: entity.JSONMap{}, Status: 1},
	}
	if err := db.Create(&channels).Error; err != nil {
		t.Fatalf("create chat channels: %v", err)
	}
	if err := db.Model(&entity.ChatChannel{}).Where("id = ?", "inactive-channel").Update("status", 0).Error; err != nil {
		t.Fatalf("deactivate chat channel: %v", err)
	}
	if err := db.Create(&entity.UserTenant{
		ID: "membership-a", UserID: "member-a", TenantID: "tenant-a", Role: string(RoleNormal), Status: &valid,
	}).Error; err != nil {
		t.Fatalf("create tenant membership: %v", err)
	}

	checker := newCommunityDatabaseChecker(db)
	member := permissionTestIdentity{UserID: "member-a"}
	for _, operation := range []Operation{OperationRead, OperationUpdate, OperationDelete, OperationUse} {
		if err := checker.CheckResource(WithIdentity(context.Background(), member.UserID, member.TenantID), ResourceRef{Kind: ResourceKindChatChannel, ID: "team-channel"}, operation); err != nil {
			t.Errorf("member cannot %s team channel: %v", operation, err)
		}
	}
	if err := checker.CheckResource(WithIdentity(context.Background(), member.UserID, member.TenantID), ResourceRef{Kind: ResourceKindChatChannel, ID: "other-channel"}, OperationRead); err != ErrPermissionDenied {
		t.Errorf("cross-tenant access error = %v, want %v", err, ErrPermissionDenied)
	}
	if err := checker.CheckResource(WithIdentity(context.Background(), member.UserID, member.TenantID), ResourceRef{Kind: ResourceKindChatChannel, ID: "inactive-channel"}, OperationRead); err != nil {
		t.Errorf("inactive channel should remain manageable: %v", err)
	}

	scope, err := checker.scope(WithIdentity(context.Background(), member.UserID, member.TenantID), ScopeQuery{Kind: ResourceKindChatChannel, Operation: OperationRead})
	if err != nil {
		t.Fatalf("scope chat channels: %v", err)
	}
	if scope.Mode != scopeIDs || len(scope.ResourceIDs) != 2 {
		t.Fatalf("chat-channel scope = %+v, want both tenant channels", scope)
	}

	queryScope, err := checker.QueryScope(WithIdentity(context.Background(), member.UserID, member.TenantID), ScopeQuery{
		Kind: ResourceKindChatChannel, Operation: OperationRead, OwnerUserIDs: []string{"tenant-owner"},
	})
	if err != nil {
		t.Fatalf("query scope chat channels by resource owner: %v", err)
	}
	var channelIDs []string
	if err := queryScope.Apply(db.Model(&entity.ChatChannel{})).Order("chat_channel.id").Pluck("chat_channel.id", &channelIDs).Error; err != nil {
		t.Fatalf("query channels by resource owner: %v", err)
	}
	if len(channelIDs) != 2 || channelIDs[0] != "inactive-channel" || channelIDs[1] != "team-channel" {
		t.Fatalf("owner-scoped channels = %v, want both tenant-owner channels", channelIDs)
	}
}
