package service

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
)

func TestListConnectorsAppliesReadScopeWithinTenant(t *testing.T) {
	db := setupServiceTestDB(t)
	pushServiceDB(t, db)
	if err := db.AutoMigrate(&entity.Connector{}); err != nil {
		t.Fatalf("migrate connector table: %v", err)
	}
	status := entity.TenantMembershipStatusJoined
	if err := db.Create(&entity.UserTenant{
		ID: "tenant-owner-membership", UserID: "tenant-owner", TenantID: "tenant-1",
		Role: string(permission.RoleOwner), Status: &status,
	}).Error; err != nil {
		t.Fatalf("create tenant owner membership: %v", err)
	}
	ctx := serviceTestContext(t, "reader", "tenant-1")
	for _, connector := range []entity.Connector{
		{ID: "reader-connector", UserID: "reader", TenantID: "tenant-1", Name: "Reader", Source: "test", InputType: "poll", Config: entity.JSONMap{}, Status: "5"},
		{ID: "owner-connector", UserID: "tenant-owner", TenantID: "tenant-1", Name: "Owner", Source: "test", InputType: "poll", Config: entity.JSONMap{}, Status: "5"},
	} {
		if err := db.Create(&connector).Error; err != nil {
			t.Fatalf("create connector %q: %v", connector.ID, err)
		}
	}

	result, err := NewConnectorService().ListConnectors(ctx, "")
	if err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	if len(result.Connectors) != 1 || result.Connectors[0].ID != "reader-connector" {
		t.Fatalf("listed connector IDs = %v, want only reader-connector", connectorListIDs(result.Connectors))
	}
}

func TestUpdateConnectorKeepsAuthorizationInWriteQuery(t *testing.T) {
	db := setupServiceTestDB(t)
	pushServiceDB(t, db)
	if err := db.AutoMigrate(&entity.Connector{}); err != nil {
		t.Fatalf("migrate connector table: %v", err)
	}
	ctx := serviceTestContext(t, "owner", "owner")
	if err := db.Create(&entity.Connector{
		ID: "connector-update", UserID: "owner", TenantID: "owner", Name: "Connector",
		Source: "test", InputType: "poll", Config: entity.JSONMap{"endpoint": "before"}, Status: "5",
	}).Error; err != nil {
		t.Fatalf("create connector: %v", err)
	}
	writeScope, err := permission.NewDatabaseChecker(db).QueryScope(ctx, permission.ScopeQuery{
		Kind: permission.ResourceKindConnector, Operation: permission.OperationUpdate,
	})
	if err != nil {
		t.Fatalf("build connector update scope: %v", err)
	}
	statement := writeScope.Apply(db.Session(&gorm.Session{DryRun: true}).Model(&entity.Connector{})).
		Where("id = ?", "connector-update").Updates(map[string]interface{}{"config": entity.JSONMap{"endpoint": "after"}}).Statement
	querySQL := strings.ToLower(statement.SQL.String())
	if querySQL == "" || (!strings.Contains(querySQL, "user_id") && !strings.Contains(querySQL, "permission")) {
		t.Fatalf("connector update SQL is missing its authorization predicate: %s", statement.SQL.String())
	}

	revoked := false
	callbackName := "test:reassign-connector-before-update"
	if err := db.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if revoked || tx.Statement.Table != "connector" {
			return
		}
		result := tx.Exec("UPDATE connector SET user_id = ? WHERE id = ?", "new-owner", "connector-update")
		if result.Error != nil {
			t.Errorf("reassign connector during update: %v", result.Error)
			return
		}
		revoked = true
	}); err != nil {
		t.Fatalf("register update callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove(callbackName) })

	_, _, err = NewConnectorService().UpdateConnector(ctx, "connector-update", &UpdateConnectorRequest{
		Config: entity.JSONMap{"endpoint": "after"},
	})
	if !revoked {
		t.Fatal("test did not reassign connector during the write")
	}
	if !errors.Is(err, permission.ErrResourceNotFound) {
		t.Fatalf("UpdateConnector error = %v, want hidden resource-not-found", err)
	}

	var connector entity.Connector
	if err := db.Where("id = ?", "connector-update").Take(&connector).Error; err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	if connector.UserID != "new-owner" || connector.Config["endpoint"] != "before" {
		t.Fatalf("connector after access change = owner %q, config %v; want new-owner and unchanged config", connector.UserID, connector.Config)
	}
}

func connectorListIDs(connectors []*dao.ConnectorListItem) []string {
	ids := make([]string, len(connectors))
	for i, connector := range connectors {
		ids[i] = connector.ID
	}
	return ids
}
