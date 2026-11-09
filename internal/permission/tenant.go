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

package permission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"ragflow/internal/common"
	"ragflow/internal/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// LoadTenantMembership loads an active user-to-Tenant relationship and
// optionally locks it for an update transaction.
func LoadTenantMembership(db *gorm.DB, tenantID, userID string, lock bool) (*entity.UserTenant, error) {
	query := db.Model(&entity.UserTenant{}).
		Where("tenant_id = ? AND user_id = ? AND status = ?", tenantID, userID, string(entity.StatusValid))
	if lock {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var membership entity.UserTenant
	if err := query.Take(&membership).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, common.NewCodedError(common.CodeForbidden, "User is not an active member of this Tenant")
		}
		return nil, fmt.Errorf("permission: load Tenant membership: %w", err)
	}
	return &membership, nil
}

// TenantMemberAccess returns the active member and effective Tenant
// management permissions for the identity attached to ctx.
func TenantMemberAccess(ctx context.Context, db *gorm.DB, tenantID string, required int32) (*entity.UserTenant, int32, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	tenantID = strings.TrimSpace(tenantID)
	if userID == "" {
		return nil, 0, common.NewCodedError(common.CodeUnauthorized, "User is required")
	}
	if tenantID == "" || tenantID != strings.TrimSpace(TenantIDFromContext(ctx)) {
		return nil, 0, ErrIdentityMismatch
	}
	if required&^(entity.TenantPermissionManageMembers|entity.TenantPermissionManageRoles|entity.TenantPermissionOwner) != 0 {
		return nil, 0, ErrInvalidPermission
	}
	membership, err := LoadTenantMembership(db, tenantID, userID, false)
	if err != nil {
		return nil, 0, err
	}
	mask, err := tenantPermissionMask(ctx, db, membership.ID, tenantID, membership.Role)
	if err != nil {
		return nil, 0, err
	}
	if mask&entity.TenantPermissionOwner != 0 {
		mask |= entity.TenantPermissionManageMembers | entity.TenantPermissionManageRoles
	}
	if required != 0 && mask&required != required {
		return nil, mask, common.NewCodedError(common.CodeForbidden, "Tenant permission denied")
	}
	return membership, mask, nil
}
