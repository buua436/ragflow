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
	"strings"

	"ragflow/internal/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func listDatasetResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	err = s.db.WithContext(ctx).Model(&entity.Knowledgebase{}).
		Where("tenant_id IN ? AND status = ?", tenantIDs, string(entity.StatusValid)).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listDocumentResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	parentColumn, _ := resourceParentColumn(definition, parent.Kind)
	if err := s.db.WithContext(ctx).Model(&entity.Document{}).
		Where(clause.Eq{Column: clause.Column{Table: "document", Name: parentColumn}, Value: parent.ID}).
		Where("status = ?", string(entity.StatusValid)).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listCanvasResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	userID := UserIDFromContext(ctx)
	var ids []string
	tenantIDs, err := s.activeTenantIDsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	ownerIDs := append(append(make([]string, 0, len(tenantIDs)+1), tenantIDs...), userID)
	if err := s.db.WithContext(ctx).Model(&entity.UserCanvas{}).
		Where("user_id IN ? OR tenant_id IN ?", ownerIDs, tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listAgentSessionResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	parentColumn, _ := resourceParentColumn(definition, parent.Kind)
	if err := s.db.WithContext(ctx).Model(&entity.API4Conversation{}).
		Where(clause.Eq{Column: clause.Column{Table: "api_4_conversation", Name: parentColumn}, Value: parent.ID}).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listMemoryResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.Memory{}).
		Where("tenant_id IN ?", tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listFileResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	parentQuery := s.db.WithContext(ctx).Model(&entity.File{}).
		Where("id = ? AND type = ?", parent.ID, "folder")
	var parentFile entity.File
	if err := parentQuery.First(&parentFile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []ResourceRef{}, nil
		}
		return nil, err
	}
	parentColumn, _ := resourceParentColumn(definition, parent.Kind)
	query := s.db.WithContext(ctx).Model(&entity.File{}).
		Select("id").
		Where("tenant_id = ?", parentFile.TenantID).
		Where(clause.Eq{Column: clause.Column{Table: "file", Name: parentColumn}, Value: parentFile.ID}).
		Where("id <> ?", parentFile.ID)
	if kind == ResourceKindFolder {
		query = query.Where("type = ?", "folder")
	} else {
		query = query.Where("type <> ?", "folder")
	}
	if err := query.Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listSearchAppResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.Search{}).
		Where("status = ? AND tenant_id IN ?", string(entity.StatusValid), tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listChatResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.Chat{}).
		Where("tenant_id IN ? AND status = ?", tenantIDs, string(entity.StatusValid)).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listChatSessionResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	parentColumn, _ := resourceParentColumn(definition, parent.Kind)
	var chatCount int64
	if err := s.db.WithContext(ctx).Model(&entity.Chat{}).
		Where("id = ? AND status = ?", parent.ID, string(entity.StatusValid)).
		Count(&chatCount).Error; err != nil {
		return nil, err
	}
	if chatCount == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.ChatSession{}).
		Where(clause.Eq{Column: clause.Column{Table: "conversation", Name: parentColumn}, Value: parent.ID}).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listChatChannelResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.ChatChannel{}).
		Where("tenant_id IN ?", tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listConnectorResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	userID := UserIDFromContext(ctx)
	var ids []string
	var tenantIDs []string
	if err := s.db.WithContext(ctx).Model(&entity.UserTenant{}).
		Distinct("tenant_id").
		Where("user_id = ? AND status = ?", userID, string(entity.StatusValid)).
		Pluck("tenant_id", &tenantIDs).Error; err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.Connector{}).
		Where("tenant_id IN ?", tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listSyncTaskResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantID := strings.TrimSpace(TenantIDFromContext(ctx))
	if tenantID == "" {
		return nil, ErrInvalidPermission
	}
	query := s.db.WithContext(ctx).Model(&entity.SyncLogs{}).
		Select("sync_logs.id").
		Joins("JOIN connector ON connector.id = sync_logs.connector_id").
		Where("connector.tenant_id = ?", tenantID).
		Where("EXISTS (SELECT 1 FROM connector2kb JOIN knowledgebase ON knowledgebase.id = connector2kb.kb_id WHERE connector2kb.connector_id = sync_logs.connector_id AND connector2kb.kb_id = sync_logs.kb_id)")
	if parent.ID != "" {
		parentColumn, _ := resourceParentColumn(definition, parent.Kind)
		query = query.Where(clause.Eq{Column: clause.Column{Table: "sync_logs", Name: parentColumn}, Value: parent.ID})
	}
	if err := query.Pluck("sync_logs.id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listModelProviderResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, _ resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if err := s.db.WithContext(ctx).Model(&entity.TenantModelProvider{}).
		Where("tenant_id IN ?", tenantIDs).
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listModelInstanceResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	query := s.db.WithContext(ctx).Model(&entity.TenantModelInstance{}).Select("tenant_model_instance.id")
	if parent.ID != "" {
		parentColumn, _ := resourceParentColumn(definition, parent.Kind)
		query = query.Where(clause.Eq{Column: clause.Column{Table: "tenant_model_instance", Name: parentColumn}, Value: parent.ID})
	} else {
		tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
		if err != nil {
			return nil, err
		}
		if len(tenantIDs) == 0 {
			return []ResourceRef{}, nil
		}
		query = query.Joins("JOIN tenant_model_provider ON tenant_model_provider.id = tenant_model_instance.provider_id").
			Where("tenant_model_provider.tenant_id IN ?", tenantIDs)
	}
	if err := query.Pluck("tenant_model_instance.id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listModelResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	query := s.db.WithContext(ctx).Model(&entity.TenantModel{}).Select("tenant_model.id")
	if parent.ID != "" {
		parentColumn, _ := resourceParentColumn(definition, parent.Kind)
		query = query.Where(clause.Eq{Column: clause.Column{Table: "tenant_model", Name: parentColumn}, Value: parent.ID})
	} else {
		tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
		if err != nil {
			return nil, err
		}
		if len(tenantIDs) == 0 {
			return []ResourceRef{}, nil
		}
		providerColumn, _ := resourceParentColumn(definition, ResourceKindModelProvider)
		query = query.Joins("JOIN tenant_model_provider ON tenant_model_provider.id = tenant_model."+providerColumn).
			Where("tenant_model_provider.tenant_id IN ?", tenantIDs)
	}
	if err := query.Pluck("tenant_model.id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}

func listTenantResourceRefs(s *databaseSource, ctx context.Context, kind ResourceKind, parent ResourceRef, definition resourceDefinition) ([]ResourceRef, error) {
	var ids []string
	tenantIDs, err := s.tenantIDsForCurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenantIDs) == 0 {
		return []ResourceRef{}, nil
	}
	if definition.tenantColumn == "" {
		return nil, ErrInvalidPermission
	}
	query := s.db.WithContext(ctx).Table(definition.table).
		Where(clause.IN{Column: clause.Column{Table: definition.table, Name: definition.tenantColumn}, Values: stringValues(tenantIDs)})
	if definition.statusColumn != "" {
		query = query.Where(clause.Eq{Column: clause.Column{Table: definition.table, Name: definition.statusColumn}, Value: definition.statusValue})
	}
	if err := query.Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	refs := make([]ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, ResourceRef{Kind: kind, ID: id})
	}
	return refs, nil
}
