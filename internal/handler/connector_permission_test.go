package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
	"ragflow/internal/permission/testsupport"
	"ragflow/internal/service"
)

func TestConnectorListAPIUsesConnectorReadScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	if err := db.AutoMigrate(&entity.User{}, &entity.UserTenant{}, &entity.Connector{}); err != nil {
		t.Fatalf("migrate connector tables: %v", err)
	}
	status := entity.TenantMembershipStatusJoined
	if err := db.Create(&entity.UserTenant{
		ID: "tenant-owner-membership", UserID: "tenant-owner", TenantID: "tenant-1",
		Role: string(permission.RoleOwner), Status: &status,
	}).Error; err != nil {
		t.Fatalf("create tenant owner membership: %v", err)
	}
	if err := db.Create(&entity.UserTenant{
		ID: "reader-membership", UserID: "reader", TenantID: "tenant-1",
		Role: string(permission.RoleNormal), Status: &status,
	}).Error; err != nil {
		t.Fatalf("create reader membership: %v", err)
	}
	if err := testsupport.PrepareEnterprisePermissionFixture(db, "tenant-1", "tenant-owner", "reader"); err != nil {
		t.Fatalf("prepare permission fixture: %v", err)
	}
	for _, connector := range []entity.Connector{
		{ID: "reader-connector", UserID: "reader", TenantID: "tenant-1", Name: "Reader", Source: "test", InputType: "poll", Config: entity.JSONMap{}, Status: "5"},
		{ID: "owner-connector", UserID: "tenant-owner", TenantID: "tenant-1", Name: "Owner", Source: "test", InputType: "poll", Config: entity.JSONMap{}, Status: "5"},
	} {
		if err := db.Create(&connector).Error; err != nil {
			t.Fatalf("create connector %q: %v", connector.ID, err)
		}
	}
	originalDB := dao.DB
	dao.DB = db
	t.Cleanup(func() { dao.DB = originalDB })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/connector/list", nil)
	ctx.Request = ctx.Request.WithContext(permission.WithIdentity(ctx.Request.Context(), "reader", "tenant-1"))
	NewConnectorHandler(service.NewConnectorService(), nil).ListConnectors(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 1 || response.Data[0].ID != "reader-connector" {
		t.Fatalf("API connector IDs = %v, want only reader-connector", response.Data)
	}
}
