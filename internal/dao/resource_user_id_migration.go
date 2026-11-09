//
// Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package dao

import (
	"context"
	"fmt"
	"strings"

	"ragflow/internal/entity"

	"gorm.io/gorm"
)

const (
	resourceUserIDMigrationMarker        = "mysql_migration.database.resource_user_id.version"
	resourceUserIDMigrationTargetVersion = "v1.0.0.2"
)

type resourceUserOwnerCandidate struct {
	ID             string
	TenantID       string
	UserID         string
	CreatedBy      string `gorm:"column:created_by"`
	DatasetOwnerID string `gorm:"column:dataset_owner_id"`
	IsTenantRoot   bool   `gorm:"column:is_tenant_root"`
}

type resourceUserIDMigration struct {
	table        string
	updateTable  string
	createdBy    bool
	rootFolders  bool
	queryDataset bool
}

// migrateResourceUserIDs repairs legacy resource rows whose user_id contains a
// tenant ID or is empty. A creator is used only when that user is still an
// active tenant member; tenant ownership remains an explicit membership lookup.
func migrateResourceUserIDs(ctx context.Context, db *gorm.DB) error {
	scoped := db.WithContext(ctx)
	if !scoped.Migrator().HasTable(&entity.UserTenant{}) {
		return nil
	}
	version, err := getDatabaseMigrationVersion(ctx, db, resourceUserIDMigrationMarker)
	if err != nil {
		return fmt.Errorf("read resource user_id migration version: %w", err)
	}
	if shouldSkipMigration(version, resourceUserIDMigrationTargetVersion) {
		return nil
	}
	if err := migrateUserCanvasTenantID(ctx, db); err != nil {
		return err
	}

	migrations := []resourceUserIDMigration{
		{table: "knowledgebase", updateTable: "knowledgebase", createdBy: true},
		{table: "dialog", updateTable: "dialog"},
		{table: "search", updateTable: "search", createdBy: true},
		{table: "user_canvas", updateTable: "user_canvas"},
		{table: "memory", updateTable: "memory"},
		{table: "file", updateTable: "file", createdBy: true, rootFolders: true},
		{table: "mcp_server", updateTable: "mcp_server"},
		{table: "connector", updateTable: "connector"},
		{table: "chat_channel", updateTable: "chat_channel"},
		{table: "tenant_model_provider", updateTable: "tenant_model_provider"},
		{table: "compilation_template_group", updateTable: "compilation_template_group"},
		{table: "compilation_template", updateTable: "compilation_template"},
		{table: "skill_spaces", updateTable: "skill_spaces"},
		{table: "evaluation_datasets", updateTable: "evaluation_datasets", createdBy: true},
		{table: "document AS resource_rows JOIN knowledgebase AS tenant_rows ON tenant_rows.id = resource_rows.kb_id", updateTable: "document", createdBy: true, queryDataset: true},
	}

	return scoped.Transaction(func(tx *gorm.DB) error {
		migrator := tx.Migrator()
		for _, migration := range migrations {
			tableName := strings.Fields(migration.table)[0]
			if !migrator.HasTable(tableName) || !migrator.HasColumn(tableName, "id") ||
				!migrator.HasColumn(tableName, "user_id") {
				continue
			}
			if migration.queryDataset {
				if !migrator.HasTable("knowledgebase") || !migrator.HasColumn("document", "kb_id") || !migrator.HasColumn("document", "created_by") {
					continue
				}
			} else if !migrator.HasColumn(tableName, "tenant_id") {
				continue
			}
			if migration.createdBy && !migrator.HasColumn(tableName, "created_by") {
				continue
			}
			if err := migrateResourceUserIDsInTable(ctx, tx, migration); err != nil {
				return err
			}
		}
		if err := setDatabaseMigrationVersionForMarker(ctx, tx, resourceUserIDMigrationMarker, resourceUserIDMigrationTargetVersion); err != nil {
			return fmt.Errorf("mark resource user_id migration version %s: %w", resourceUserIDMigrationTargetVersion, err)
		}
		return nil
	})
}

func migrateResourceUserIDsInTable(ctx context.Context, tx *gorm.DB, migration resourceUserIDMigration) error {
	query := tx.WithContext(ctx)
	selectFields := "resource_rows.id, resource_rows.tenant_id, resource_rows.user_id"
	if migration.queryDataset {
		selectFields = "resource_rows.id, tenant_rows.tenant_id, resource_rows.user_id, resource_rows.created_by, tenant_rows.user_id AS dataset_owner_id, 0 AS is_tenant_root"
	} else if migration.createdBy {
		selectFields += ", resource_rows.created_by"
	} else {
		selectFields += ", '' AS created_by"
	}
	if migration.rootFolders {
		selectFields += ", CASE WHEN resource_rows.parent_id = resource_rows.id AND resource_rows.type = 'folder' THEN 1 ELSE 0 END AS is_tenant_root"
	} else if !migration.queryDataset {
		selectFields += ", 0 AS is_tenant_root"
	}
	queryTable := migration.table
	if !migration.queryDataset {
		queryTable += " AS resource_rows"
	}
	query = query.Table(queryTable).Select(selectFields)
	if migration.queryDataset {
		query = query.Where(`tenant_rows.tenant_id IS NOT NULL AND tenant_rows.tenant_id <> '' AND NOT EXISTS (
			SELECT 1 FROM user_tenant active_membership
			WHERE active_membership.tenant_id = tenant_rows.tenant_id
			  AND active_membership.user_id = resource_rows.user_id
			  AND active_membership.status = ?
		)`, string(entity.StatusValid))
	} else {
		rootClause := ""
		if migration.rootFolders {
			rootClause = " OR (resource_rows.parent_id = resource_rows.id AND resource_rows.type = 'folder')"
		}
		query = query.Where(`resource_rows.tenant_id IS NOT NULL AND resource_rows.tenant_id <> '' AND (
			NOT EXISTS (
				SELECT 1 FROM user_tenant active_membership
				WHERE active_membership.tenant_id = resource_rows.tenant_id
				  AND active_membership.user_id = resource_rows.user_id
				  AND active_membership.status = ?
			)`+rootClause+`
		)`, string(entity.StatusValid))
	}
	const batchSize = 500
	lastID := ""
	for {
		batch := make([]resourceUserOwnerCandidate, 0, batchSize)
		batchQuery := query.Session(&gorm.Session{Initialized: true}).Order("resource_rows.id ASC").Limit(batchSize)
		if lastID != "" {
			batchQuery = batchQuery.Where("resource_rows.id > ?", lastID)
		}
		if err := batchQuery.Find(&batch).Error; err != nil {
			return fmt.Errorf("load legacy resource owners from %s: %w", migration.table, err)
		}
		if len(batch) == 0 {
			return nil
		}
		tenantIDs := make([]string, 0, len(batch))
		for _, candidate := range batch {
			tenantIDs = append(tenantIDs, candidate.TenantID)
		}
		owners, err := activeTenantOwnerUserIDs(ctx, tx, tenantIDs)
		if err != nil {
			return fmt.Errorf("resolve owners for legacy resources in %s: %w", migration.table, err)
		}
		var memberships []entity.UserTenant
		if err := tx.WithContext(ctx).Select("user_id", "tenant_id").
			Where("tenant_id IN ? AND status = ?", tenantIDs, string(entity.StatusValid)).Find(&memberships).Error; err != nil {
			return fmt.Errorf("load active memberships for legacy resources in %s: %w", migration.table, err)
		}
		activeUsers := make(map[string]map[string]struct{}, len(tenantIDs))
		for _, membership := range memberships {
			if activeUsers[membership.TenantID] == nil {
				activeUsers[membership.TenantID] = make(map[string]struct{})
			}
			activeUsers[membership.TenantID][membership.UserID] = struct{}{}
		}
		for _, candidate := range batch {
			ownerUserID := owners[candidate.TenantID]
			if !candidate.IsTenantRoot {
				if _, ok := activeUsers[candidate.TenantID][strings.TrimSpace(candidate.CreatedBy)]; ok {
					ownerUserID = strings.TrimSpace(candidate.CreatedBy)
				} else if _, ok := activeUsers[candidate.TenantID][strings.TrimSpace(candidate.DatasetOwnerID)]; ok {
					ownerUserID = strings.TrimSpace(candidate.DatasetOwnerID)
				}
			}
			if ownerUserID == "" {
				return fmt.Errorf("resource %s/%s has no active tenant owner to repair user_id", migration.table, candidate.ID)
			}
			if err := tx.WithContext(ctx).Table(migration.updateTable).
				Where("id = ?", candidate.ID).UpdateColumn("user_id", ownerUserID).Error; err != nil {
				return fmt.Errorf("backfill %s.user_id for resource %s: %w", migration.updateTable, candidate.ID, err)
			}
		}
		lastID = batch[len(batch)-1].ID
		if len(batch) < batchSize {
			return nil
		}
	}
}
