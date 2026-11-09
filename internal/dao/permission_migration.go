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

const permissionMigrationTargetVersion = "v1.0.0-rc3.dev5"

// migratePermissions applies the permission schema migration and records its version.
func migratePermissions(ctx context.Context, db *gorm.DB) error {
	if err := migrateResourceUserIDs(ctx, db); err != nil {
		return err
	}
	version, err := GetDatabaseMigrationVersion(ctx, db)
	if err != nil {
		return fmt.Errorf("read database migration version: %w", err)
	}
	if shouldSkipMigration(version, permissionMigrationTargetVersion) {
		return migratePermissionDataEE(ctx, db)
	}
	if err := migrateUserCanvasTenantID(ctx, db); err != nil {
		return err
	}
	if err := migrateLegacyTenantInvitationStatuses(ctx, db); err != nil {
		return err
	}
	if err := migrateInvitedByNullable(ctx, db); err != nil {
		return err
	}
	if err := migrateTenantModelProviderUserID(ctx, db); err != nil {
		return err
	}
	if err := migrateAPITokenUserID(ctx, db); err != nil {
		return err
	}
	if err := setDatabaseMigrationVersion(ctx, db, permissionMigrationTargetVersion); err != nil {
		return fmt.Errorf("mark permission migration version: %w", err)
	}
	if err := migratePermissionDataEE(ctx, db); err != nil {
		return fmt.Errorf("migrate enterprise permission data: %w", err)
	}
	return nil
}

func migrateLegacyTenantInvitationStatuses(ctx context.Context, db *gorm.DB) error {
	scoped := db.WithContext(ctx)
	migrator := scoped.Migrator()
	if !migrator.HasTable(&entity.UserTenant{}) || !migrator.HasColumn(&entity.UserTenant{}, "role") || !migrator.HasColumn(&entity.UserTenant{}, "status") {
		return nil
	}
	result := scoped.Model(&entity.UserTenant{}).
		Where("role = ? AND (status = ? OR status IS NULL)", "invite", entity.TenantMembershipStatusJoined).
		Updates(map[string]interface{}{"role": "", "status": entity.TenantMembershipStatusInvited})
	if result.Error != nil {
		return fmt.Errorf("migrate legacy Tenant invitations to pending status: %w", result.Error)
	}
	return nil
}

// migrateUserTenantDuplicates removes duplicate legacy memberships before
// AutoMigrate creates the unique (user_id, tenant_id) index.
func migrateUserTenantDuplicates(ctx context.Context, db *gorm.DB) error {
	scoped := db.WithContext(ctx)
	migrator := scoped.Migrator()
	if !migrator.HasTable(&entity.UserTenant{}) {
		return nil
	}
	hasIndex, err := hasUserTenantUniqueIndex(ctx, scoped)
	if err != nil {
		return fmt.Errorf("inspect user_tenant unique index: %w", err)
	}
	if hasIndex {
		return nil
	}

	return scoped.Transaction(func(tx *gorm.DB) error {
		var duplicateKeys []struct {
			UserID   string `gorm:"column:user_id"`
			TenantID string `gorm:"column:tenant_id"`
		}
		if err := tx.Model(&entity.UserTenant{}).
			Select("user_id, tenant_id").
			Group("user_id, tenant_id").
			Having("COUNT(*) > 1").
			Scan(&duplicateKeys).Error; err != nil {
			return fmt.Errorf("find duplicate user_tenant memberships: %w", err)
		}

		for _, key := range duplicateKeys {
			var memberships []entity.UserTenant
			if err := tx.Where("user_id = ? AND tenant_id = ?", key.UserID, key.TenantID).
				Order("CASE WHEN status = '1' THEN 0 ELSE 1 END").
				Order("CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'normal' THEN 2 WHEN 'invite' THEN 3 ELSE 4 END").
				Order("update_time DESC").
				Order("create_time ASC").
				Order("id ASC").
				Find(&memberships).Error; err != nil {
				return fmt.Errorf("list duplicate user_tenant memberships for user %s in tenant %s: %w", key.UserID, key.TenantID, err)
			}
			if len(memberships) < 2 {
				continue
			}
			keepID := memberships[0].ID
			for _, duplicate := range memberships[1:] {
				if err := remapUserTenantReferences(ctx, tx, duplicate.ID, keepID); err != nil {
					return err
				}
				if err := tx.Where("id = ?", duplicate.ID).Delete(&entity.UserTenant{}).Error; err != nil {
					return fmt.Errorf("delete duplicate user_tenant membership %s: %w", duplicate.ID, err)
				}
			}
		}
		return nil
	})
}

func hasUserTenantUniqueIndex(ctx context.Context, db *gorm.DB) (bool, error) {
	indexes, err := db.WithContext(ctx).Migrator().GetIndexes(&entity.UserTenant{})
	if err != nil {
		return false, err
	}
	for _, index := range indexes {
		unique, known := index.Unique()
		if !known || !unique {
			continue
		}
		columns := index.Columns()
		if len(columns) != 2 {
			continue
		}
		columnSet := map[string]struct{}{"user_id": {}, "tenant_id": {}}
		for _, column := range columns {
			delete(columnSet, strings.ToLower(column))
		}
		if len(columnSet) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func remapUserTenantReferences(ctx context.Context, tx *gorm.DB, oldID, newID string) error {
	references := []struct {
		table  string
		column string
	}{
		{table: "group_info", column: "owner_id"},
		{table: "group_member", column: "member_id"},
		{table: "department_member", column: "member_id"},
		{table: "permission", column: "member_id"},
	}
	for _, reference := range references {
		migrator := tx.WithContext(ctx).Migrator()
		if !migrator.HasTable(reference.table) || !migrator.HasColumn(reference.table, reference.column) {
			continue
		}
		if err := tx.WithContext(ctx).Table(reference.table).
			Where(reference.column+" = ?", oldID).
			Update(reference.column, newID).Error; err != nil {
			return fmt.Errorf("remap %s.%s from membership %s to %s: %w", reference.table, reference.column, oldID, newID, err)
		}
	}
	return nil
}

// migrateTenantModelProviderUserID backfills missing model provider owner IDs.
func migrateTenantModelProviderUserID(ctx context.Context, db *gorm.DB) error {
	scoped := db.WithContext(ctx)
	migrator := scoped.Migrator()
	if !migrator.HasTable(&entity.TenantModelProvider{}) {
		return nil
	}
	if !migrator.HasColumn(&entity.TenantModelProvider{}, "UserID") {
		return fmt.Errorf("tenant_model_provider.user_id is missing after GORM migration")
	}
	var tenantIDs []string
	if err := scoped.Model(&entity.TenantModelProvider{}).
		Distinct("tenant_id").Where("user_id IS NULL OR user_id = ''").Pluck("tenant_id", &tenantIDs).Error; err != nil {
		return fmt.Errorf("load tenants with model providers missing owner user_id: %w", err)
	}
	owners, err := activeTenantOwnerUserIDs(ctx, scoped, tenantIDs)
	if err != nil {
		return fmt.Errorf("resolve model provider owners: %w", err)
	}
	for _, tenantID := range tenantIDs {
		if err := scoped.Model(&entity.TenantModelProvider{}).
			Where("tenant_id = ? AND (user_id IS NULL OR user_id = '')", tenantID).
			UpdateColumn("user_id", owners[tenantID]).Error; err != nil {
			return fmt.Errorf("backfill tenant_model_provider.user_id for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// activeTenantOwnerUserIDs resolves one persisted owner membership per tenant.
func activeTenantOwnerUserIDs(ctx context.Context, db *gorm.DB, tenantIDs []string) (map[string]string, error) {
	owners := make(map[string]string, len(tenantIDs))
	if len(tenantIDs) == 0 {
		return owners, nil
	}
	var memberships []entity.UserTenant
	if err := db.WithContext(ctx).
		Where("tenant_id IN ? AND role = ? AND status = ?", tenantIDs, "owner", string(entity.StatusValid)).
		Find(&memberships).Error; err != nil {
		return nil, fmt.Errorf("load active owner memberships: %w", err)
	}
	counts := make(map[string]int, len(tenantIDs))
	for _, membership := range memberships {
		counts[membership.TenantID]++
		owners[membership.TenantID] = strings.TrimSpace(membership.UserID)
	}
	for _, tenantID := range tenantIDs {
		if counts[tenantID] != 1 || owners[tenantID] == "" {
			return nil, fmt.Errorf("tenant %q has %d active owner memberships; expected exactly one to backfill its owner user_id", tenantID, counts[tenantID])
		}
	}
	return owners, nil
}

// migrateUserCanvasTenantID backfills tenant IDs from active memberships.
func migrateUserCanvasTenantID(ctx context.Context, db *gorm.DB) error {
	migrator := db.WithContext(ctx).Migrator()
	if !migrator.HasTable(&entity.UserCanvas{}) {
		return nil
	}
	if !migrator.HasColumn(&entity.UserCanvas{}, "TenantID") {
		return fmt.Errorf("user_canvas.tenant_id is missing after GORM migration")
	}
	var canvases []struct {
		ID     string
		UserID string
	}
	if err := db.WithContext(ctx).Model(&entity.UserCanvas{}).
		Select("id", "user_id").Where("tenant_id IS NULL OR tenant_id = ''").Find(&canvases).Error; err != nil {
		return fmt.Errorf("load canvases missing tenant_id: %w", err)
	}
	if len(canvases) == 0 {
		return nil
	}
	userIDs := make([]string, 0, len(canvases))
	for _, canvas := range canvases {
		userIDs = append(userIDs, canvas.UserID)
	}
	var memberships []entity.UserTenant
	if err := db.WithContext(ctx).Where("user_id IN ? AND status = ?", userIDs, string(entity.StatusValid)).Find(&memberships).Error; err != nil {
		return fmt.Errorf("load active canvas owner memberships: %w", err)
	}
	tenantsByUser := make(map[string]map[string]struct{}, len(userIDs))
	for _, membership := range memberships {
		if tenantsByUser[membership.UserID] == nil {
			tenantsByUser[membership.UserID] = make(map[string]struct{})
		}
		tenantsByUser[membership.UserID][membership.TenantID] = struct{}{}
	}
	for _, canvas := range canvases {
		tenantIDs := tenantsByUser[canvas.UserID]
		selectedTenantID := ""
		// Older personal canvases used the creator ID as their tenant ID. Keep
		// that established mapping only when the membership row confirms it.
		if _, ok := tenantIDs[canvas.UserID]; ok {
			selectedTenantID = canvas.UserID
		} else if len(tenantIDs) == 1 {
			for tenantID := range tenantIDs {
				selectedTenantID = tenantID
			}
		}
		if selectedTenantID == "" {
			return fmt.Errorf("canvas %q owner %q has no unique tenant membership to backfill tenant_id", canvas.ID, canvas.UserID)
		}
		if err := db.WithContext(ctx).Model(&entity.UserCanvas{}).
			Where("id = ? AND (tenant_id IS NULL OR tenant_id = '')", canvas.ID).
			Update("tenant_id", selectedTenantID).Error; err != nil {
			return fmt.Errorf("backfill user_canvas.tenant_id for canvas %s: %w", canvas.ID, err)
		}
	}
	return nil
}

// migrateAPITokenUserID backfills user IDs for existing API tokens.
func migrateAPITokenUserID(ctx context.Context, db *gorm.DB) error {
	migrator := db.WithContext(ctx).Migrator()
	if !migrator.HasTable(&entity.APIToken{}) {
		return nil
	}
	if !migrator.HasColumn(&entity.APIToken{}, "UserID") {
		return fmt.Errorf("api_token.user_id is missing after GORM migration")
	}
	var tenantIDs []string
	if err := db.WithContext(ctx).Model(&entity.APIToken{}).
		Distinct("tenant_id").Where("user_id IS NULL OR user_id = ''").Pluck("tenant_id", &tenantIDs).Error; err != nil {
		return fmt.Errorf("load tenants with API tokens missing owner user_id: %w", err)
	}
	owners, err := activeTenantOwnerUserIDs(ctx, db, tenantIDs)
	if err != nil {
		return fmt.Errorf("resolve API token owners: %w", err)
	}
	for _, tenantID := range tenantIDs {
		if err := db.WithContext(ctx).Model(&entity.APIToken{}).
			Where("tenant_id = ? AND (user_id IS NULL OR user_id = '')", tenantID).
			Update("user_id", owners[tenantID]).Error; err != nil {
			return fmt.Errorf("backfill api_token.user_id for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// migrateInvitedByNullable allows tenant membership requests without an inviter.
func migrateInvitedByNullable(ctx context.Context, db *gorm.DB) error {
	migrator := db.WithContext(ctx).Migrator()
	columns, err := migrator.ColumnTypes(&entity.UserTenant{})
	if err != nil {
		return fmt.Errorf("inspect user_tenant columns: %w", err)
	}
	for _, column := range columns {
		if column.Name() != "invited_by" {
			continue
		}
		nullable, known := column.Nullable()
		if !known {
			return fmt.Errorf("user_tenant.invited_by nullability is unknown")
		}
		if nullable {
			return nil
		}
		// AutoMigrate does not relax NOT NULL on an existing column for every
		// supported dialect, so use GORM's migrator for this one legacy constraint.
		if err := migrator.AlterColumn(&entity.UserTenant{}, "InvitedBy"); err != nil {
			return fmt.Errorf("make user_tenant.invited_by nullable: %w", err)
		}
		return nil
	}
	return fmt.Errorf("user_tenant.invited_by column is missing")
}
