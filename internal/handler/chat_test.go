package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
	"ragflow/internal/permission/testsupport"
	"ragflow/internal/service"
)

func setupChatHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	if err = db.AutoMigrate(&entity.Chat{}, &entity.Tenant{}, &entity.UserTenant{}, &entity.User{}); err != nil {
		t.Fatalf("failed to migrate test schema: %v", err)
	}

	origDB := dao.DB
	dao.DB = db
	t.Cleanup(func() { dao.DB = origDB })

	status := string(entity.StatusValid)
	if err = db.Create(&entity.Tenant{
		ID:        "user-1",
		ParserIDs: "naive",
		Status:    &status,
	}).Error; err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	if err = db.Create(&entity.UserTenant{
		ID: "owner-user-1", UserID: "user-1", TenantID: "user-1", Role: "owner", Status: &status,
		LLMID: "model-a", EmbdID: "embd-a", ASRID: "asr-a", Img2TxtID: "img2txt-a", RerankID: "rerank-a",
	}).Error; err != nil {
		t.Fatalf("failed to create owner membership: %v", err)
	}
	if err = testsupport.PrepareEnterprisePermissionFixture(db, "user-1", "user-1"); err != nil {
		t.Fatalf("prepare chat permission fixture: %v", err)
	}

	return db
}

func createChatHandlerTestChat(t *testing.T, db *gorm.DB, id, tenantID string) {
	t.Helper()

	name := "chat-" + id
	status := string(entity.StatusValid)
	chat := &entity.Chat{
		ID:           id,
		UserID:       tenantID,
		TenantID:     tenantID,
		Name:         &name,
		LLMID:        "model-a",
		LLMSetting:   entity.JSONMap{},
		PromptType:   "simple",
		PromptConfig: entity.JSONMap{"system": "sys"},
		KBIDs:        entity.JSONSlice{},
		Status:       &status,
	}
	if err := db.Create(chat).Error; err != nil {
		t.Fatalf("failed to create chat: %v", err)
	}
}

func TestDeleteChatHandlerSuccess(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "user-1")

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("DELETE", "/api/v1/chats/chat-1", "")
	c.Params = []gin.Param{{Key: "chat_id", Value: "chat-1"}}

	h.DeleteChat(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeSuccess) {
		t.Fatalf("expected success code, got %v", resp["code"])
	}
	if data, exists := resp["data"]; exists {
		t.Fatalf("data must be omitted, got %v", data)
	}
}

func TestBulkDeleteChatsHandlerPartialSuccess(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "user-1")
	createChatHandlerTestChat(t, db, "chat-2", "tenant-2")

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("DELETE", "/api/v1/chats", `{"ids":["chat-1","chat-2","chat-1"]}`)

	h.BulkDeleteChats(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeSuccess) {
		t.Fatalf("expected success code, got %v", resp["code"])
	}

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected object data, got %+v", resp["data"])
	}
	if data["success_count"] != float64(1) {
		t.Fatalf("expected success_count=1, got %v", data["success_count"])
	}
	errorsList, ok := data["errors"].([]interface{})
	if !ok || len(errorsList) != 2 {
		t.Fatalf("expected 2 errors, got %+v", data["errors"])
	}
	if resp["message"] != "Partially deleted 1 chats with 2 errors" {
		t.Fatalf("unexpected message: %v", resp["message"])
	}
}

func TestPatchChatHandlerSuccess(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "user-1")

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("PATCH", "/api/v1/chats/chat-1", `{"name":" updated chat "}`)
	c.Params = []gin.Param{{Key: "chat_id", Value: "chat-1"}}

	h.PatchChat(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeSuccess) {
		t.Fatalf("expected success code, got %v", resp["code"])
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected object data, got %+v", resp["data"])
	}
	if data["name"] != "updated chat" {
		t.Fatalf("expected trimmed name in response, got %+v", data["name"])
	}
	if _, ok := data["kb_ids"]; ok {
		t.Fatalf("response must not expose kb_ids: %+v", data)
	}
	if _, ok := data["dataset_ids"]; !ok {
		t.Fatalf("response should expose dataset_ids: %+v", data)
	}
}

func TestUpdateChatHandlerRejectsNonOwner(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "tenant-2")
	if err := testsupport.PrepareEnterprisePermissionFixture(db, "tenant-2", "tenant-2", "user-1"); err != nil {
		t.Fatalf("prepare non-owner chat permission fixture: %v", err)
	}

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("PUT", "/api/v1/chats/chat-1", `{"name":"updated"}`)
	setGinContextSubject(c, "user-1", "tenant-2")
	c.Params = []gin.Param{{Key: "chat_id", Value: "chat-1"}}

	h.UpdateChat(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeForbidden) {
		t.Fatalf("expected permission-denied code, got %v", resp["code"])
	}
	if resp["data"] != nil {
		t.Fatalf("expected data=null, got %v", resp["data"])
	}
	if resp["message"] != "Permission denied" {
		t.Fatalf("unexpected message: %v", resp["message"])
	}
}

func TestGetChatHandlerRejectsNonOwner(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "tenant-2")

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("GET", "/api/v1/chats/chat-1", "")
	c.Params = []gin.Param{{Key: "chat_id", Value: "chat-1"}}

	h.GetChat(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeNotFound) {
		t.Fatalf("expected hidden resource code, got %v", resp["code"])
	}
	if resp["data"] != nil {
		t.Fatalf("expected data=null, got %v", resp["data"])
	}
	if resp["message"] != "Resource not found" {
		t.Fatalf("unexpected message: %v", resp["message"])
	}
}

func TestListChatsHandlerUsesSelectedTenantWithSeparateUserID(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	active := string(entity.StatusValid)
	if err := db.Create(&entity.Tenant{ID: "team-1", ParserIDs: "naive", Status: &active}).Error; err != nil {
		t.Fatalf("create selected tenant: %v", err)
	}
	if err := db.Create(&entity.UserTenant{
		ID: "user-1-team-1", UserID: "user-1", TenantID: "team-1", Role: "normal", Status: &active,
	}).Error; err != nil {
		t.Fatalf("create selected tenant membership: %v", err)
	}
	if err := db.Create(&entity.UserTenant{
		ID: "user-2-team-1", UserID: "user-2", TenantID: "team-1", Role: string(permission.RoleOwner), Status: &active,
	}).Error; err != nil {
		t.Fatalf("create selected tenant owner membership: %v", err)
	}
	if err := testsupport.PrepareEnterprisePermissionFixture(db, "team-1", "user-2", "user-1"); err != nil {
		t.Fatalf("prepare selected tenant permission fixture: %v", err)
	}
	seedChat := func(id, userID, tenantID string) {
		t.Helper()
		name := "chat-" + id
		status := string(entity.StatusValid)
		if err := db.Create(&entity.Chat{
			ID: id, UserID: userID, TenantID: tenantID, Name: &name, LLMID: "model-a",
			LLMSetting: entity.JSONMap{}, PromptType: "simple", PromptConfig: entity.JSONMap{},
			KBIDs: entity.JSONSlice{}, Status: &status,
		}).Error; err != nil {
			t.Fatalf("create chat %q: %v", id, err)
		}
	}
	seedChat("selected-owned", "user-1", "team-1")
	seedChat("selected-other-owner", "user-2", "team-1")
	seedChat("personal-owned", "user-1", "user-1")
	chatCtx := permission.WithIdentity(t.Context(), "user-1", "team-1")
	chatRef := permission.ResourceRef{Kind: permission.ResourceKindChat, ID: "selected-owned"}
	checker := permission.NewDatabaseChecker(db)
	if err := checker.GrantResourceOwner(chatCtx, chatRef); err != nil {
		t.Fatalf("grant selected chat owner: %v", err)
	}
	if err := checker.CheckResource(chatCtx, chatRef, permission.OperationRead); err != nil {
		t.Fatalf("selected chat owner cannot read their chat: %v", err)
	}

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUserInTenant(http.MethodGet, "/api/v1/chats", "", "user-1", "team-1")
	h.ListChats(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Code common.ErrorCode `json:"code"`
		Data struct {
			Total int64 `json:"total"`
			Chats []struct {
				ID string `json:"id"`
			} `json:"chats"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if response.Code != common.CodeSuccess || response.Data.Total != 1 || len(response.Data.Chats) != 1 || response.Data.Chats[0].ID != "selected-owned" {
		t.Fatalf("list response = %+v, want only the selected tenant's resource owned by user-1", response)
	}
}

func TestDeleteChatHandlerRejectsNonOwner(t *testing.T) {
	db := setupChatHandlerTestDB(t)
	createChatHandlerTestChat(t, db, "chat-1", "tenant-2")

	h := NewChatHandler(service.NewChatService(), service.NewUserService())
	c, w := setupGinContextWithUser("DELETE", "/api/v1/chats/chat-1", "")
	c.Params = []gin.Param{{Key: "chat_id", Value: "chat-1"}}

	h.DeleteChat(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["code"] != float64(common.CodeNotFound) {
		t.Fatalf("expected hidden resource code, got %v", resp["code"])
	}
	if resp["message"] != "Resource not found" {
		t.Fatalf("unexpected message: %v", resp["message"])
	}
}
