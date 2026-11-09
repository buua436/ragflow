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

	"ragflow/internal/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type communityPolicy struct {
	source Source
}

type membershipResult struct {
	membership *Membership
	err        error
}

type evaluation struct {
	source      Source
	memberships map[string]membershipResult
	resources   map[ResourceRef]Resource
	resourceErr map[ResourceRef]error
}

func newPolicy(source Source) policy {
	if activePolicy, handled := newPolicyEE(source); handled {
		return activePolicy
	}
	return &communityPolicy{source: source}
}

func checkResource(ctx context.Context, resolve func(context.Context, ResourceRef) (Access, error), ref ResourceRef, operation Operation) error {
	if strings.TrimSpace(UserIDFromContext(ctx)) == "" {
		return ErrUnauthenticated
	}
	if !validOperation(operation) {
		return ErrInvalidPermission
	}
	access, err := resolve(ctx, ref)
	if err != nil {
		return err
	}
	if !access.Allows(operation) {
		return ErrPermissionDenied
	}
	return nil
}

func checkDependency(ctx context.Context, session accessSession, entry, dependency ResourceRef, entryOperation, dependencyOperation Operation) error {
	if strings.TrimSpace(UserIDFromContext(ctx)) == "" {
		return ErrUnauthenticated
	}
	if !validOperation(entryOperation) || !validOperation(dependencyOperation) {
		return ErrInvalidPermission
	}
	if session.load != nil {
		if err := session.load(ctx, []ResourceRef{entry, dependency}); err != nil {
			return err
		}
	}
	if err := checkResource(ctx, session.resolve, entry, entryOperation); err != nil {
		return err
	}
	if err := checkResource(ctx, session.resolve, dependency, dependencyOperation); err != nil {
		return err
	}
	entryOwnerID, err := session.ownerID(ctx, entry)
	if err != nil {
		return err
	}
	ownerContext := WithIdentity(ctx, entryOwnerID, TenantIDFromContext(ctx))
	if err := checkResource(ownerContext, session.resolve, dependency, dependencyOperation); err != nil {
		if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrMembershipNotFound) || errors.Is(err, ErrResourceNotFound) {
			return ErrPermissionDenied
		}
		return err
	}
	return nil
}

func (p *communityPolicy) nativeQueryScopeRequired() bool {
	source, ok := p.source.(*databaseSource)
	return ok && source != nil && source.db != nil
}

func (p *communityPolicy) CheckFeature(ctx context.Context, feature Feature, action Action) error {
	if strings.TrimSpace(UserIDFromContext(ctx)) == "" {
		return ErrUnauthenticated
	}
	if strings.TrimSpace(string(feature)) == "" || !validAction(action) {
		return ErrInvalidPermission
	}
	// Community edition has no role-based feature restrictions.
	return nil
}

func (p *communityPolicy) CheckTenant(ctx context.Context, tenantID string, requirement TenantRequirement) error {
	return newEvaluation(p.source).checkTenant(ctx, tenantID, requirement)
}

func (p *communityPolicy) ResolveAccess(ctx context.Context, ref ResourceRef) (Access, error) {
	return newEvaluation(p.source).resolveAccess(ctx, ref)
}

func (p *communityPolicy) newAccessSession() accessSession {
	evaluation := newEvaluation(p.source)
	return accessSession{resolve: evaluation.resolveAccess, ownerID: evaluation.resourceOwnerID, load: evaluation.loadResources}
}

func (p *communityPolicy) resourceOwnerID(ctx context.Context, ref ResourceRef) (string, error) {
	if p.source == nil {
		return "", ErrSourceUnavailable
	}
	resources, err := p.source.GetResources(ctx, []ResourceRef{ref})
	if err != nil {
		return "", fmt.Errorf("permission: load dependency owner: %w", err)
	}
	for _, resource := range resources {
		if resource.Ref == ref {
			return resource.OwnerUserID, nil
		}
	}
	return "", ErrResourceNotFound
}

func (p *communityPolicy) scope(ctx context.Context, query ScopeQuery) (resourceScope, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return resourceScope{}, ErrUnauthenticated
	}
	if strings.TrimSpace(string(query.Kind)) == "" || !validOperation(query.Operation) {
		return resourceScope{}, ErrInvalidPermission
	}
	if (query.Parent.ID == "") != (query.Parent.Kind == "") {
		return resourceScope{}, ErrInvalidPermission
	}
	if query.Entry != nil && (!validResourceRef(*query.Entry) || !validOperation(query.EntryOp)) {
		return resourceScope{}, ErrInvalidPermission
	}

	evaluation := newEvaluation(p.source)
	candidateRefs, err := p.source.ListResourceRefs(ctx, query.Kind, query.Parent)
	if err != nil {
		return resourceScope{}, fmt.Errorf("permission: list resource candidates: %w", err)
	}
	candidateRefs = uniqueRefs(candidateRefs)
	resourcesToLoad := append([]ResourceRef(nil), candidateRefs...)
	if query.Parent.ID != "" {
		resourcesToLoad = append(resourcesToLoad, query.Parent)
	}
	if query.Entry != nil {
		resourcesToLoad = append(resourcesToLoad, *query.Entry)
	}
	if err := evaluation.loadResources(ctx, resourcesToLoad); err != nil {
		return resourceScope{}, err
	}
	var entryRef ResourceRef
	if query.Entry != nil {
		entryRef = *query.Entry
	}
	accessible := make([]ResourceRef, 0, len(candidateRefs))
	access := accessSession{resolve: evaluation.resolveAccess, ownerID: evaluation.resourceOwnerID, load: evaluation.loadResources}
	for _, ref := range candidateRefs {
		resource, resourceErr := evaluation.getResource(ref)
		if resourceErr != nil {
			if errors.Is(resourceErr, ErrResourceNotFound) {
				continue
			}
			return resourceScope{}, resourceErr
		}
		if tenantID := strings.TrimSpace(query.TenantID); tenantID != "" && resource.TenantID != tenantID {
			continue
		}
		var checkErr error
		if query.Entry == nil {
			checkErr = evaluation.checkResource(ctx, ref, query.Operation)
		} else {
			checkErr = checkDependency(ctx, access, entryRef, ref, query.EntryOp, query.Operation)
		}
		if checkErr == nil {
			accessible = append(accessible, ref)
			continue
		}
		if errorsIsPermissionDenial(checkErr) || errors.Is(checkErr, ErrResourceNotFound) {
			continue
		}
		return resourceScope{}, checkErr
	}

	// In the community edition the effective tenant comes from the persisted
	// resource boundary, not from a caller-selected tenant. Scopes without a
	// single parent or entry can contain resources from multiple tenants, so
	// their explicit authorized IDs are the boundary and TenantID stays empty.
	var tenantID string
	if query.Parent.ID != "" {
		if parent, parentErr := evaluation.getResource(query.Parent); parentErr == nil {
			tenantID = parent.TenantID
		}
	}
	if query.Entry != nil {
		if entry, entryErr := evaluation.getResource(*query.Entry); entryErr == nil {
			tenantID = entry.TenantID
		}
	}
	scope := resourceScope{TenantID: tenantID, Kind: query.Kind, Parent: query.Parent, Operation: query.Operation}
	if len(accessible) == 0 {
		scope.Mode = scopeNone
		return scope, nil
	}
	scope.Mode = scopeIDs
	scope.ResourceIDs = make([]string, 0, len(accessible))
	for _, ref := range accessible {
		scope.ResourceIDs = append(scope.ResourceIDs, ref.ID)
	}
	return scope, nil
}

func (p *communityPolicy) QueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	if query.Kind == ResourceKindChatSession {
		return p.chatSessionQueryScope(ctx, query)
	}
	if query.Kind == ResourceKindSyncTask {
		return p.syncTaskQueryScope(ctx, query)
	}
	if query.Kind == ResourceKindModelProvider || query.Kind == ResourceKindModelInstance || query.Kind == ResourceKindModel {
		return p.modelQueryScope(ctx, query)
	}
	switch query.Kind {
	case ResourceKindCanvas:
		return p.communityResourceQueryScope(ctx, query)
	case ResourceKindMemory:
		return p.memoryQueryScope(ctx, query)
	case ResourceKindFile, ResourceKindFolder:
		return p.fileQueryScope(ctx, query)
	case ResourceKindSearchApp:
		return p.communityResourceQueryScope(ctx, query)
	case ResourceKindChat:
		return p.communityResourceQueryScope(ctx, query)
	case ResourceKindChatChannel:
		return p.communityResourceQueryScope(ctx, query)
	case ResourceKindSkillSpace:
		return p.skillSpaceQueryScope(ctx, query)
	case ResourceKindConnector:
		return p.communityResourceQueryScope(ctx, query)
	case ResourceKindAgentSession:
		return p.agentSessionQueryScope(ctx, query)
	case ResourceKindDocument:
		return p.documentQueryScope(ctx, query)
	}
	if query.Kind == ResourceKindMCPServer {
		return p.communityResourceQueryScope(ctx, query)
	}
	if query.Kind == ResourceKindDataset {
		return p.datasetQueryScope(ctx, query)
	}
	return QueryScope{}, false, nil
}

func (p *communityPolicy) datasetQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil {
		return QueryScope{}, false, nil
	}
	if err := source.validateDatasetTenants(ctx, userID); err != nil {
		return QueryScope{}, true, err
	}
	// Enterprise tenant roles are stored as numeric IDs. The generic SQL fast
	// path cannot resolve those IDs safely, so let the normal resource checks
	// evaluate candidate IDs through databaseSource.GetMembership instead.
	if tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}

	var entryOwnerID string
	if query.Entry != nil {
		if query.Entry.Kind != ResourceKindCanvas || query.EntryOp == "" {
			return QueryScope{}, false, nil
		}
		if err := checkResource(ctx, p.ResolveAccess, *query.Entry, query.EntryOp); err != nil {
			return QueryScope{}, true, err
		}
		resources, err := source.GetResources(ctx, []ResourceRef{*query.Entry})
		if err != nil {
			return QueryScope{}, true, err
		}
		if len(resources) != 1 {
			return QueryScope{}, true, ErrResourceNotFound
		}
		entryOwnerID = strings.TrimSpace(resources[0].OwnerUserID)
		if entryOwnerID == "" {
			return QueryScope{}, true, ErrInvalidPermission
		}
	}

	tenantID := strings.TrimSpace(query.TenantID)
	operation := query.Operation
	return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
		query = query.Where("knowledgebase.status = ?", string(entity.StatusValid))
		if tenantID != "" {
			query = query.Where("knowledgebase.tenant_id = ?", tenantID)
		}
		query = communityDatasetAccess(query, userID, operation)
		if entryOwnerID != "" && entryOwnerID != userID {
			query = communityDatasetAccess(query, entryOwnerID, operation)
		}
		return query
	}}, true, nil
}

func communityDatasetAccess(query *gorm.DB, userID string, operation Operation) *gorm.DB {
	definition, _ := resourceDefinitionFor(ResourceKindDataset)
	accessSQL, values := communityUserAccessSQL(
		definition, "knowledgebase", userID, operation,
		definition.ownerOperations, definition.tenantOperations,
		definition.visibilityColumn, definition.tenantValue, definition.tenantRequirement,
	)
	if accessSQL == "" {
		return query.Where("1 = 0")
	}
	return query.Where("("+accessSQL+")", values...)
}

func (p *communityPolicy) memoryQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	if query.Parent.ID != "" || query.Parent.Kind != "" {
		return QueryScope{}, false, nil
	}
	if query.Entry != nil {
		if query.Entry.Kind != ResourceKindCanvas || query.EntryOp == "" {
			return QueryScope{}, false, nil
		}
		if err := checkResource(ctx, p.ResolveAccess, *query.Entry, query.EntryOp); err != nil {
			return QueryScope{}, true, err
		}
	}
	ownerIDs := []string{userID}
	if query.Entry != nil {
		resources, err := p.source.GetResources(ctx, []ResourceRef{*query.Entry})
		if err != nil {
			return QueryScope{}, true, err
		}
		if len(resources) != 1 || strings.TrimSpace(resources[0].OwnerUserID) == "" {
			return QueryScope{}, true, ErrResourceNotFound
		}
		ownerIDs = append(ownerIDs, strings.TrimSpace(resources[0].OwnerUserID))
	}
	definition, ok := resourceDefinitionFor(ResourceKindMemory)
	if !ok {
		return QueryScope{}, true, ErrInvalidPermission
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil {
		return QueryScope{}, false, nil
	}
	if tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}
	operation := query.Operation
	tenantID := strings.TrimSpace(query.TenantID)
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		if tenantID != "" {
			db = db.Where("memory.tenant_id = ?", tenantID)
		}
		access := db
		for _, ownerID := range uniqueStringValues(ownerIDs) {
			accessSQL, values := communityUserAccessSQL(
				definition, definition.table, ownerID, operation,
				definition.ownerOperations, definition.tenantOperations,
				definition.visibilityColumn, definition.tenantValue, definition.tenantRequirement,
			)
			if accessSQL == "" {
				return db.Where("1 = 0")
			}
			access = access.Where("("+accessSQL+")", values...)
		}
		return access
	}}, true, nil
}

func (p *communityPolicy) communityResourceQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	if query.Entry != nil || query.Parent.ID != "" || query.Parent.Kind != "" {
		return QueryScope{}, false, nil
	}
	definition, ok := resourceDefinitionFor(query.Kind)
	if !ok || (definition.tenantColumn == "" && definition.tenantRelation == nil) {
		return QueryScope{}, false, nil
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil {
		return QueryScope{}, false, nil
	}
	if tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}
	if !containsOperation(definition.ownerOperations, query.Operation) && !containsOperation(definition.tenantOperations, query.Operation) {
		return QueryScope{apply: func(db *gorm.DB) *gorm.DB { return db.Where("1 = 0") }}, true, nil
	}
	queryTenantID := strings.TrimSpace(query.TenantID)
	operation := query.Operation
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		if queryTenantID != "" {
			sql, values := resourceFieldEqualsSQL(definition.table, definition.tenantColumn, definition.tenantRelation, queryTenantID)
			db = db.Where(sql, values...)
		}
		if definition.statusColumn != "" {
			db = db.Where(definition.table+"."+definition.statusColumn+" = ?", definition.statusValue)
		}
		accessSQL, values := communityUserAccessSQL(
			definition, definition.table, userID, operation,
			definition.ownerOperations, definition.tenantOperations, definition.visibilityColumn, definition.tenantValue, definition.tenantRequirement,
		)
		if accessSQL == "" {
			return db.Where("1 = 0")
		}
		return db.Where("("+accessSQL+")", values...)
	}}, true, nil
}

func communityUserAccessSQL(
	definition resourceDefinition,
	table, userID string,
	operation Operation,
	ownerOperations, tenantOperations []Operation,
	visibilityColumn, tenantValue string,
	tenantRequirement TenantRequirement,
) (string, []interface{}) {
	branches := make([]string, 0, 2)
	values := make([]interface{}, 0, 6)
	if containsOperation(ownerOperations, operation) {
		ownerColumn, ownerValues := resourceFieldEqualsSQL(table, definition.ownerColumn, definition.ownerRelation, userID)
		if ownerColumn != "" {
			branches = append(branches, ownerColumn)
			values = append(values, ownerValues...)
		}
	}
	if containsOperation(tenantOperations, operation) {
		membershipSQL := communityMembershipSQL(definition, table, userID, tenantRequirement)
		if membershipSQL != "" {
			branch := membershipSQL
			if visibilityColumn != "" {
				branch = "(" + table + "." + visibilityColumn + " = ? AND " + membershipSQL + ")"
				values = append(values, tenantValue)
			}
			branches = append(branches, branch)
			values = append(values, userID, string(entity.StatusValid), communityTenantRoles(tenantRequirement))
		}
	}
	return strings.Join(branches, " OR "), values
}

func communityMembershipSQL(definition resourceDefinition, table, userID string, requirement TenantRequirement) string {
	if definition.tenantColumn == "" && definition.tenantRelation == nil {
		return ""
	}
	var tenantMatch string
	if definition.tenantRelation == nil {
		tenantMatch = "user_tenant.tenant_id = " + table + "." + definition.tenantColumn
	} else {
		relation := definition.tenantRelation
		tenantMatch = "user_tenant.tenant_id IN (SELECT " + relation.relatedColumn + " FROM " + relation.table +
			" WHERE " + relation.table + "." + relation.relatedIDColumn + " = " + table + "." + relation.localColumn + ")"
	}
	return "EXISTS (SELECT 1 FROM user_tenant WHERE " + tenantMatch +
		" AND user_tenant.user_id = ? AND user_tenant.status = ? AND user_tenant.role IN ? )"
}

func communityTenantRoles(requirement TenantRequirement) []string {
	switch requirement {
	case TenantNormalMember:
		return []string{string(RoleNormal)}
	case TenantAdmin:
		return []string{string(RoleOwner), string(RoleAdmin)}
	case TenantOwner:
		return []string{string(RoleOwner)}
	default:
		return []string{string(RoleOwner), string(RoleAdmin), string(RoleNormal)}
	}
}

func resourceFieldEqualsSQL(table, column string, relation *resourceRelation, value string) (string, []interface{}) {
	if relation == nil {
		if column == "" {
			return "", nil
		}
		return table + "." + column + " = ?", []interface{}{value}
	}
	return table + "." + relation.localColumn + " IN (SELECT " + relation.relatedIDColumn + " FROM " + relation.table +
		" WHERE " + relation.table + "." + relation.relatedColumn + " = ?)", []interface{}{value}
}

func (p *communityPolicy) fileQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	if _, ok := resourceDefinitionFor(query.Kind); !ok || query.Entry != nil {
		return QueryScope{}, false, nil
	}
	parentID := strings.TrimSpace(query.Parent.ID)
	if (parentID == "") != (query.Parent.Kind == "") || (parentID != "" && query.Parent.Kind != ResourceKindFolder) {
		return QueryScope{}, false, nil
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil {
		return QueryScope{}, false, nil
	}
	if tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}
	if query.Operation != OperationRead {
		return QueryScope{apply: func(db *gorm.DB) *gorm.DB { return db.Where("1 = 0") }}, true, nil
	}
	tenantID := strings.TrimSpace(query.TenantID)
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		db = db.Where("file.user_id <> ''")
		if parentID != "" {
			db = db.Where("EXISTS (SELECT 1 FROM file AS scope_parent WHERE scope_parent.id = ? AND scope_parent.tenant_id = file.tenant_id AND scope_parent.type = ?)", parentID, "folder")
		}
		if tenantID != "" {
			db = db.Where("file.tenant_id = ?", tenantID)
		} else {
			db = db.Where("file.tenant_id <> ''")
		}
		if query.Kind == ResourceKindFolder {
			db = db.Where("file.type = ?", "folder")
		}
		shared := "EXISTS (SELECT 1 FROM file2document AS f2d JOIN document AS shared_document ON shared_document.id = f2d.document_id JOIN knowledgebase AS shared_dataset ON shared_dataset.id = shared_document.kb_id WHERE f2d.file_id = file.id AND shared_dataset.status = ? AND (shared_dataset.user_id = ? OR (shared_dataset.permission = ? AND EXISTS (SELECT 1 FROM user_tenant AS shared_member WHERE shared_member.tenant_id = shared_dataset.tenant_id AND shared_member.user_id = ? AND shared_member.status = ? AND shared_member.role = ?))))"
		return db.Where("(file.user_id = ? OR "+shared+")", userID,
			string(entity.StatusValid), userID, string(entity.TenantPermissionTeam), userID, string(entity.StatusValid), string(RoleNormal))
	}}, true, nil
}

func (p *communityPolicy) skillSpaceQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	scope, supported, err := p.communityResourceQueryScope(ctx, query)
	if err != nil || !supported {
		return scope, supported, err
	}
	folderExists := QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		return db.Where("EXISTS (SELECT 1 FROM file AS skill_folder WHERE skill_folder.id = skill_spaces.folder_id AND skill_folder.tenant_id = skill_spaces.tenant_id AND skill_folder.type = ?)", "folder")
	}}
	return scope.and(folderExists), true, nil
}

func (p *communityPolicy) agentSessionQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	definition, ok := resourceDefinitionFor(ResourceKindAgentSession)
	if !ok || query.Entry != nil || !validOperation(query.Operation) {
		return QueryScope{}, false, nil
	}
	if query.Parent.ID != "" {
		if _, ok := resourceParentColumn(definition, query.Parent.Kind); !ok {
			return QueryScope{}, true, ErrInvalidPermission
		}
	} else if query.Parent.Kind != "" {
		return QueryScope{}, false, nil
	}
	if _, ok := p.source.(*databaseSource); !ok {
		return QueryScope{}, false, nil
	}
	if !containsOperation([]Operation{OperationRead, OperationRun, OperationUpdate, OperationDelete}, query.Operation) {
		return QueryScope{apply: func(db *gorm.DB) *gorm.DB { return db.Where("1 = 0") }}, true, nil
	}
	tenantID := strings.TrimSpace(query.TenantID)
	parentID := strings.TrimSpace(query.Parent.ID)
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		if tenantID != "" {
			sql, values := resourceFieldEqualsSQL(definition.table, "", definition.tenantRelation, tenantID)
			db = db.Where(sql, values...)
		} else {
			db = db.Where("EXISTS (SELECT 1 FROM user_canvas WHERE user_canvas.id = api_4_conversation.dialog_id AND COALESCE(user_canvas.tenant_id, '') <> '')")
		}
		if parentID != "" {
			parentColumn, _ := resourceParentColumn(definition, query.Parent.Kind)
			db = db.Where(clause.Eq{Column: clause.Column{Table: definition.table, Name: parentColumn}, Value: parentID})
		}
		return db.Where("api_4_conversation.user_id = ?", userID).
			Where("EXISTS (SELECT 1 FROM user_canvas WHERE user_canvas.id = api_4_conversation.dialog_id)")
	}}, true, nil
}

func (p *communityPolicy) documentQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	documentDefinition, ok := resourceDefinitionFor(ResourceKindDocument)
	if !ok || query.Entry != nil {
		return QueryScope{}, false, nil
	}
	if (query.Parent.ID == "") != (query.Parent.Kind == "") || (query.Parent.ID != "" && query.Parent.Kind != ResourceKindDataset) {
		return QueryScope{}, false, nil
	}
	datasetDefinition, ok := resourceDefinitionFor(ResourceKindDataset)
	if !ok {
		return QueryScope{}, true, ErrInvalidPermission
	}
	parentColumn, ok := resourceParentColumn(documentDefinition, ResourceKindDataset)
	if !ok || documentDefinition.parentAccessOperation == "" {
		return QueryScope{}, true, ErrInvalidPermission
	}
	if query.Parent.ID != "" {
		if err := checkResource(ctx, p.ResolveAccess, query.Parent, documentDefinition.parentAccessOperation); err != nil {
			return QueryScope{}, true, err
		}
	}
	if _, ok := p.source.(*databaseSource); !ok {
		return QueryScope{}, false, nil
	}
	if query.Operation != OperationRead && query.Operation != OperationUpdate && query.Operation != OperationDeleteContent && query.Operation != OperationRun && query.Operation != OperationUse &&
		query.Operation != OperationCreate && query.Operation != OperationDelete && query.Operation != OperationShare {
		return QueryScope{apply: func(db *gorm.DB) *gorm.DB { return db.Where("1 = 0") }}, true, nil
	}
	queryTenantID := strings.TrimSpace(query.TenantID)
	parentID := strings.TrimSpace(query.Parent.ID)
	operation := query.Operation
	datasetAccessSQL, datasetValues := communityUserAccessSQL(
		datasetDefinition, "document_dataset", userID, documentDefinition.parentAccessOperation,
		datasetDefinition.ownerOperations, datasetDefinition.tenantOperations,
		datasetDefinition.visibilityColumn, datasetDefinition.tenantValue, datasetDefinition.tenantRequirement,
	)
	if datasetAccessSQL == "" {
		return QueryScope{apply: func(db *gorm.DB) *gorm.DB { return db.Where("1 = 0") }}, true, nil
	}
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		documentTable := documentDefinition.table
		datasetTable := datasetDefinition.table
		if documentDefinition.statusColumn != "" {
			db = db.Where(documentTable+"."+documentDefinition.statusColumn+" = ?", documentDefinition.statusValue)
		}
		parentAccessSQL := "EXISTS (SELECT 1 FROM " + datasetTable + " AS document_dataset WHERE document_dataset.id = " + documentTable + "." + parentColumn
		parentValues := append([]interface{}(nil), datasetValues...)
		if datasetDefinition.statusColumn != "" {
			parentAccessSQL += " AND document_dataset." + datasetDefinition.statusColumn + " = ?"
			parentValues = append([]interface{}{datasetDefinition.statusValue}, parentValues...)
		}
		db = db.Where(parentAccessSQL+" AND ("+datasetAccessSQL+"))", parentValues...)
		if parentID != "" {
			db = db.Where(clause.Eq{Column: clause.Column{Table: documentTable, Name: parentColumn}, Value: parentID})
		}
		if queryTenantID != "" {
			tenantSQL, tenantValues := resourceFieldEqualsSQL(documentTable, documentDefinition.tenantColumn, documentDefinition.tenantRelation, queryTenantID)
			if tenantSQL == "" {
				return db.Where("1 = 0")
			}
			db = db.Where(tenantSQL, tenantValues...)
		}
		ownerAllowed := containsOperation(datasetDefinition.ownerOperations, operation)
		tenantAllowed := containsOperation(datasetDefinition.tenantOperations, operation)
		if ownerAllowed && tenantAllowed {
			tenantAccess := "EXISTS (SELECT 1 FROM " + datasetTable + " AS document_visibility_dataset JOIN user_tenant AS document_member ON document_member.tenant_id = document_visibility_dataset." + datasetDefinition.tenantColumn + " WHERE document_visibility_dataset.id = " + documentTable + "." + parentColumn
			if datasetDefinition.visibilityColumn != "" {
				tenantAccess += " AND document_visibility_dataset." + datasetDefinition.visibilityColumn + " = ?"
			}
			tenantAccess += " AND document_member.user_id = ? AND document_member.status = ? AND document_member.role IN ? )"
			values := []interface{}{userID}
			if datasetDefinition.visibilityColumn != "" {
				values = append(values, datasetDefinition.tenantValue)
			}
			values = append(values, userID, string(entity.StatusValid), communityTenantRoles(datasetDefinition.tenantRequirement))
			return db.Where("("+documentTable+"."+documentDefinition.ownerColumn+" = ? OR "+tenantAccess+")", values...)
		}
		if ownerAllowed {
			return db.Where(documentTable+"."+documentDefinition.ownerColumn+" = ?", userID)
		}
		return db.Where("1 = 0")
	}}, true, nil
}

func (p *communityPolicy) syncTaskQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	if query.Operation != OperationRead && query.Operation != OperationRun {
		return QueryScope{}, false, nil
	}
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil || tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}
	syncTaskDefinition, _ := resourceDefinitionFor(ResourceKindSyncTask)
	connectorColumn, _ := resourceParentColumn(syncTaskDefinition, ResourceKindConnector)
	taskConnector := clause.Column{Table: "sync_logs", Name: connectorColumn}
	if query.Parent.ID == "" && query.Parent.Kind == "" && query.Entry == nil {
		if query.Operation != OperationRead {
			return QueryScope{}, false, nil
		}
		tenantID := query.TenantID
		return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
			ownedConnector := source.db.WithContext(ctx).Model(&entity.Connector{}).
				Select("1").
				Where(clause.Eq{Column: clause.Column{Table: "connector", Name: "id"}, Value: taskConnector}).
				Where("connector.user_id = ?", userID)
			if tenantID != "" {
				ownedConnector = ownedConnector.Where("connector.tenant_id = ?", tenantID)
			}
			linkedDataset := source.db.WithContext(ctx).Model(&entity.Connector2Kb{}).
				Select("1").
				Joins("JOIN knowledgebase ON knowledgebase.id = connector2kb.kb_id").
				Where(clause.Eq{Column: clause.Column{Table: "connector2kb", Name: "connector_id"}, Value: taskConnector}).
				Where(clause.Eq{Column: clause.Column{Table: "connector2kb", Name: "kb_id"}, Value: clause.Column{Table: "sync_logs", Name: "kb_id"}})
			return query.Where("EXISTS (?)", ownedConnector).Where("EXISTS (?)", linkedDataset)
		}}, true, nil
	}
	if _, ok := resourceParentColumn(syncTaskDefinition, query.Parent.Kind); !ok || strings.TrimSpace(query.Parent.ID) == "" ||
		query.Entry == nil || *query.Entry != query.Parent || !validOperation(query.EntryOp) {
		return QueryScope{}, false, nil
	}
	if query.EntryOp != OperationRead && query.EntryOp != OperationRun && query.EntryOp != OperationUse {
		return QueryScope{}, false, nil
	}
	if err := newEvaluation(p.source).checkResource(ctx, query.Parent, query.EntryOp); err != nil {
		return QueryScope{}, true, err
	}
	parentID := query.Parent.ID
	tenantID := query.TenantID
	entryOperation := query.EntryOp
	operation := query.Operation
	return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
		connectorAccess := source.db.WithContext(ctx).Model(&entity.Connector{}).
			Select("1").
			Where("connector.id = ?", parentID)
		if tenantID != "" {
			connectorAccess = connectorAccess.Where("connector.tenant_id = ?", tenantID)
		}
		if entryOperation == OperationRead {
			connectorAccess = connectorAccess.Where("connector.user_id = ?", userID)
		} else {
			activeMembership := source.db.WithContext(ctx).Model(&entity.UserTenant{}).
				Select("1").
				Where("user_tenant.tenant_id = connector.tenant_id AND user_tenant.user_id = ? AND user_tenant.status = ? AND user_tenant.role IN ?",
					userID, string(entity.StatusValid), []string{string(RoleOwner), string(RoleAdmin), string(RoleNormal)})
			connectorAccess = connectorAccess.Where("(connector.user_id = ? OR EXISTS (?))", userID, activeMembership)
		}
		linkedDataset := source.db.WithContext(ctx).Model(&entity.Connector2Kb{}).
			Select("1").
			Joins("JOIN knowledgebase ON knowledgebase.id = connector2kb.kb_id").
			Where(clause.Eq{Column: clause.Column{Table: "connector2kb", Name: "connector_id"}, Value: taskConnector}).
			Where(clause.Eq{Column: clause.Column{Table: "connector2kb", Name: "kb_id"}, Value: clause.Column{Table: "sync_logs", Name: "kb_id"}})
		taskQuery := query.Where(clause.Eq{Column: taskConnector, Value: parentID}).
			Where("EXISTS (?)", connectorAccess).
			Where("EXISTS (?)", linkedDataset)
		if operation == OperationRun {
			taskQuery = taskQuery.Where("LOWER(sync_logs.task_type) = ? AND sync_logs.status = ?", "sync", string(entity.TaskStatusFail))
		}
		return taskQuery
	}}, true, nil
}

func (p *communityPolicy) chatSessionQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	chatSessionDefinition, _ := resourceDefinitionFor(ResourceKindChatSession)
	parentColumn, hasParent := resourceParentColumn(chatSessionDefinition, query.Parent.Kind)
	if !hasParent || strings.TrimSpace(query.Parent.ID) == "" ||
		query.Entry == nil || *query.Entry != query.Parent || !validOperation(query.Operation) || !validOperation(query.EntryOp) {
		return QueryScope{}, false, nil
	}
	if !containsOperation([]Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse}, query.Operation) ||
		!containsOperation([]Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationRun, OperationUse}, query.EntryOp) {
		return QueryScope{}, false, nil
	}
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	if err := newEvaluation(p.source).checkResource(ctx, query.Parent, query.EntryOp); err != nil {
		return QueryScope{}, true, err
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil {
		return QueryScope{}, false, nil
	}
	parentID := query.Parent.ID
	tenantID := query.TenantID
	return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
		activeOwnerChat := source.db.WithContext(ctx).Model(&entity.Chat{}).
			Select("1").
			Where(clause.Eq{Column: clause.Column{Table: "dialog", Name: "id"}, Value: clause.Column{Table: "conversation", Name: parentColumn}}).
			Where("dialog.id = ? AND dialog.user_id = ? AND dialog.status = ?", parentID, userID, string(entity.StatusValid))
		if tenantID != "" {
			activeOwnerChat = activeOwnerChat.Where("dialog.tenant_id = ?", tenantID)
		}
		return query.Where(clause.Eq{Column: clause.Column{Table: "conversation", Name: parentColumn}, Value: parentID}).
			Where("EXISTS (?)", activeOwnerChat)
	}}, true, nil
}

func containsOperation(operations []Operation, operation Operation) bool {
	for _, candidate := range operations {
		if candidate == operation {
			return true
		}
	}
	return false
}

func (p *communityPolicy) modelQueryScope(ctx context.Context, query ScopeQuery) (QueryScope, bool, error) {
	parent := query.Parent
	if query.Entry != nil || (parent.ID == "") != (parent.Kind == "") {
		return QueryScope{}, false, nil
	}
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return QueryScope{}, true, ErrUnauthenticated
	}
	source, ok := p.source.(*databaseSource)
	if !ok || source.db == nil || tenantRoleMembershipEnabled(source.db) {
		return QueryScope{}, false, nil
	}
	definition, ok := resourceDefinitionFor(query.Kind)
	if !ok {
		return QueryScope{}, false, nil
	}
	if parent.ID != "" {
		if _, ok := resourceParentColumn(definition, parent.Kind); !ok {
			return QueryScope{}, false, nil
		}
	}
	modelInstanceDefinition, _ := resourceDefinitionFor(ResourceKindModelInstance)
	modelInstanceProviderColumn, _ := resourceParentColumn(modelInstanceDefinition, ResourceKindModelProvider)
	modelDefinition, _ := resourceDefinitionFor(ResourceKindModel)
	modelProviderColumn, _ := resourceParentColumn(modelDefinition, ResourceKindModelProvider)

	tenantID := query.TenantID
	ownerMembership := func(providerAlias string) *gorm.DB {
		return source.db.WithContext(ctx).Model(&entity.UserTenant{}).
			Select("1").
			Where("user_tenant.tenant_id = "+providerAlias+".tenant_id AND user_tenant.user_id = "+providerAlias+".user_id AND user_tenant.role = ? AND user_tenant.status = ?",
				string(RoleOwner), string(entity.StatusValid))
	}
	providerAccess := func(providerIDColumn, parentID string, ownerOnly bool) *gorm.DB {
		provider := source.db.WithContext(ctx).Model(&entity.TenantModelProvider{}).
			Select("1").
			Where("tenant_model_provider.id = " + providerIDColumn)
		if parentID != "" {
			provider = provider.Where("tenant_model_provider.id = ?", parentID)
		}
		if tenantID != "" {
			provider = provider.Where("tenant_model_provider.tenant_id = ?", tenantID)
		}
		provider = provider.Where("EXISTS (?)", ownerMembership("tenant_model_provider"))
		if ownerOnly {
			return provider.Where("tenant_model_provider.user_id = ?", userID)
		}
		membership := source.db.WithContext(ctx).Model(&entity.UserTenant{}).
			Select("1").
			Where("user_tenant.tenant_id = tenant_model_provider.tenant_id AND user_tenant.user_id = ? AND user_tenant.status = ? AND user_tenant.role IN ?",
				userID, string(entity.StatusValid), []string{string(RoleOwner), string(RoleAdmin), string(RoleNormal)})
		return provider.Where("(tenant_model_provider.user_id = ? OR EXISTS (?))", userID, membership)
	}

	switch query.Kind {
	case ResourceKindModelProvider:
		if parent.ID != "" || query.Operation != OperationRead {
			return QueryScope{}, false, nil
		}
		return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
			db := source.db.WithContext(ctx)
			providerQuery := query
			if tenantID != "" {
				providerQuery = providerQuery.Where("tenant_model_provider.tenant_id = ?", tenantID)
			}
			membership := db.Model(&entity.UserTenant{}).
				Select("1").
				Where("user_tenant.tenant_id = tenant_model_provider.tenant_id AND user_tenant.user_id = ? AND user_tenant.status = ? AND user_tenant.role IN ?",
					userID, string(entity.StatusValid), []string{string(RoleOwner), string(RoleAdmin), string(RoleNormal)})
			return providerQuery.
				Where("EXISTS (?)", ownerMembership("tenant_model_provider")).
				Where("(tenant_model_provider.user_id = ? OR EXISTS (?))", userID, membership)
		}}, true, nil
	case ResourceKindModelInstance:
		if query.Operation != OperationRead && query.Operation != OperationUse {
			return QueryScope{}, false, nil
		}
		ownerOnly := query.Operation == OperationRead
		return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
			return query.Where("EXISTS (?)", providerAccess("tenant_model_instance."+modelInstanceProviderColumn, parent.ID, ownerOnly))
		}}, true, nil
	case ResourceKindModel:
		if query.Operation != OperationRead && query.Operation != OperationUse {
			return QueryScope{}, false, nil
		}
		return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
			modelQuery := query.Where("EXISTS (?)", providerAccess("tenant_model."+modelProviderColumn, "", false))
			if parent.ID != "" {
				parentColumn, _ := resourceParentColumn(definition, parent.Kind)
				modelQuery = modelQuery.Where(clause.Eq{
					Column: clause.Column{Table: "tenant_model", Name: parentColumn},
					Value:  parent.ID,
				})
			}
			return modelQuery
		}}, true, nil
	default:
		return QueryScope{}, false, nil
	}
}

func (s *databaseSource) validateDatasetTenants(ctx context.Context, userID string) error {
	var tenantIDs []string
	err := s.db.WithContext(ctx).Model(&entity.Knowledgebase{}).
		Joins("JOIN user_tenant member ON member.tenant_id = knowledgebase.tenant_id").
		Where("knowledgebase.status = ? AND member.user_id = ? AND member.status = ?", string(entity.StatusValid), userID, string(entity.StatusValid)).
		Distinct("knowledgebase.tenant_id").
		Pluck("knowledgebase.tenant_id", &tenantIDs).Error
	if err != nil {
		return err
	}
	_, err = s.loadTenantOwnerIDs(ctx, tenantIDs)
	return err
}

func (p *communityPolicy) ResolveAccesses(ctx context.Context, refs []ResourceRef) (map[ResourceRef]Access, error) {
	if strings.TrimSpace(UserIDFromContext(ctx)) == "" {
		return nil, ErrUnauthenticated
	}
	evaluation := newEvaluation(p.source)
	refs = uniqueRefs(refs)
	if err := evaluation.loadResources(ctx, refs); err != nil {
		return nil, err
	}
	accesses := make(map[ResourceRef]Access, len(refs))
	for _, ref := range refs {
		access, err := evaluation.resolveAccess(ctx, ref)
		if err == nil {
			accesses[ref] = access
			continue
		}
		if errorsIsPermissionDenial(err) || errors.Is(err, ErrResourceNotFound) {
			continue
		}
		return nil, err
	}
	return accesses, nil
}

func newEvaluation(source Source) *evaluation {
	return &evaluation{
		source:      source,
		memberships: make(map[string]membershipResult),
		resources:   make(map[ResourceRef]Resource),
		resourceErr: make(map[ResourceRef]error),
	}
}

func (e *evaluation) checkTenant(ctx context.Context, tenantID string, requirement TenantRequirement) error {
	return e.checkTenantForUser(ctx, UserIDFromContext(ctx), tenantID, requirement)
}

func (e *evaluation) checkTenantForUser(ctx context.Context, userID, tenantID string, requirement TenantRequirement) error {
	if strings.TrimSpace(userID) == "" {
		return ErrUnauthenticated
	}
	if strings.TrimSpace(tenantID) == "" || !validTenantRequirement(requirement) {
		return ErrInvalidPermission
	}
	membership, err := e.getMembership(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	if !membershipSatisfies(membership, requirement) {
		return ErrMembershipNotFound
	}
	return nil
}

func (e *evaluation) checkResource(ctx context.Context, ref ResourceRef, operation Operation) error {
	if !validOperation(operation) {
		return ErrInvalidPermission
	}
	access, err := e.resolveAccess(ctx, ref)
	if err != nil {
		return err
	}
	if !accessAllows(access, operation) {
		return ErrPermissionDenied
	}
	return nil
}

func (e *evaluation) resolveAccess(ctx context.Context, ref ResourceRef) (Access, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if strings.TrimSpace(userID) == "" {
		return Access{}, ErrUnauthenticated
	}
	if err := e.loadResources(ctx, []ResourceRef{ref}); err != nil {
		return Access{}, err
	}
	resource, err := e.getResource(ref)
	if err != nil {
		return Access{}, err
	}
	return e.resolveResource(ctx, resource)
}

func (e *evaluation) resourceOwnerID(ctx context.Context, ref ResourceRef) (string, error) {
	if err := e.loadResources(ctx, []ResourceRef{ref}); err != nil {
		return "", err
	}
	resource, err := e.getResource(ref)
	if err != nil {
		return "", err
	}
	return resource.OwnerUserID, nil
}

func (e *evaluation) resolveResource(ctx context.Context, resource Resource) (Access, error) {
	userID := strings.TrimSpace(UserIDFromContext(ctx))
	if userID == "" {
		return Access{}, ErrUnauthenticated
	}
	return e.resolveResourceForUser(ctx, userID, resource)
}

func (e *evaluation) resolveResourceForUser(ctx context.Context, userID string, resource Resource) (Access, error) {
	if resource.TenantID == "" || resource.OwnerUserID == "" || !validResourceRef(resource.Ref) {
		return Access{}, fmt.Errorf("%w: incomplete resource authorization facts", ErrInvalidPermission)
	}
	if tenantID := strings.TrimSpace(TenantIDFromContext(ctx)); tenantID != "" && resource.TenantID != tenantID {
		return Access{}, ErrResourceNotFound
	}
	if !resource.Active {
		return Access{}, ErrResourceNotFound
	}
	if resource.ParentAccessOperation != "" {
		if !validOperation(resource.ParentAccessOperation) || len(resource.ParentRefs) == 0 {
			return Access{}, ErrInvalidPermission
		}
		for _, parentRef := range resource.ParentRefs {
			if err := e.loadResources(ctx, []ResourceRef{parentRef}); err != nil {
				return Access{}, err
			}
			parent, err := e.getResource(parentRef)
			if err != nil {
				return Access{}, err
			}
			parentAccess, err := e.resolveResourceForUser(ctx, userID, parent)
			if err != nil {
				if errorsIsPermissionDenial(err) {
					return Access{}, ErrPermissionDenied
				}
				return Access{}, err
			}
			if !parentAccess.Allows(resource.ParentAccessOperation) {
				return Access{}, ErrPermissionDenied
			}
		}
	}
	if !validOperations(resource.OwnerOperations) {
		return Access{}, fmt.Errorf("%w: invalid owner operations", ErrInvalidPermission)
	}
	if !validOperations(resource.TenantOperations) || !validOperations(resource.CreatorOperations) {
		return Access{}, fmt.Errorf("%w: invalid delegated operations", ErrInvalidPermission)
	}
	switch resource.Visibility {
	case VisibilityPrivate, VisibilityTenant, VisibilityShared:
	default:
		return Access{}, fmt.Errorf("%w: unknown resource visibility %q", ErrInvalidPermission, resource.Visibility)
	}
	if userID == resource.OwnerUserID {
		return resourceAccess(resource, AccessSourceOwner), nil
	}

	switch resource.Visibility {
	case VisibilityPrivate:
		return Access{}, ErrPermissionDenied
	case VisibilityTenant:
		requirement := resource.TenantRequirement
		if requirement == "" {
			requirement = TenantNormalMember
		}
		if err := e.checkTenantForUser(ctx, userID, resource.TenantID, requirement); err != nil {
			if errors.Is(err, ErrMembershipNotFound) {
				return Access{}, ErrPermissionDenied
			}
			return Access{}, err
		}
		if userID == resource.CreatedBy && resource.CreatorOperations != nil {
			return resourceAccessWithOperations(resource, AccessSourceCreator, resource.CreatorOperations), nil
		}
		operations := resource.TenantOperations
		if operations == nil {
			operations = resource.OwnerOperations
		}
		return resourceAccessWithOperations(resource, AccessSourceTenant, operations), nil
	case VisibilityShared:
		if contains(resource.SharedWithUserIDs, userID) {
			return resourceAccess(resource, AccessSourceShared), nil
		}
		for _, tenantID := range resource.SharedWithTenantIDs {
			if err := e.checkTenantForUser(ctx, userID, tenantID, TenantNormalMember); err != nil {
				if errors.Is(err, ErrMembershipNotFound) {
					continue
				}
				return Access{}, err
			}
			return resourceAccess(resource, AccessSourceShared), nil
		}
		return Access{}, ErrPermissionDenied
	default:
		return Access{}, fmt.Errorf("%w: unknown resource visibility %q", ErrInvalidPermission, resource.Visibility)
	}
}

func (e *evaluation) loadResources(ctx context.Context, refs []ResourceRef) error {
	if e.source == nil {
		return ErrSourceUnavailable
	}
	var missing []ResourceRef
	for _, ref := range uniqueRefs(refs) {
		if _, ok := e.resources[ref]; ok {
			continue
		}
		if _, ok := e.resourceErr[ref]; ok {
			continue
		}
		if !validResourceRef(ref) {
			return ErrInvalidPermission
		}
		missing = append(missing, ref)
	}
	if len(missing) == 0 {
		return nil
	}
	resources, err := e.source.GetResources(ctx, missing)
	if err != nil {
		return fmt.Errorf("permission: load resources: %w", err)
	}
	for _, ref := range missing {
		e.resourceErr[ref] = ErrResourceNotFound
	}
	for _, resource := range resources {
		if _, requested := e.resourceErr[resource.Ref]; requested {
			e.resources[resource.Ref] = resource
			delete(e.resourceErr, resource.Ref)
		}
	}
	return nil
}

func (e *evaluation) getResource(ref ResourceRef) (Resource, error) {
	if !validResourceRef(ref) {
		return Resource{}, ErrInvalidPermission
	}
	if resource, ok := e.resources[ref]; ok {
		return resource, nil
	}
	if err, ok := e.resourceErr[ref]; ok {
		return Resource{}, err
	}
	return Resource{}, ErrResourceNotFound
}

func (e *evaluation) getMembership(ctx context.Context, userID, tenantID string) (*Membership, error) {
	if e.source == nil {
		return nil, ErrSourceUnavailable
	}
	key := userID + "\x00" + tenantID
	if result, ok := e.memberships[key]; ok {
		return result.membership, result.err
	}
	membership, err := e.source.GetMembership(ctx, userID, tenantID)
	if err != nil {
		err = fmt.Errorf("permission: load tenant membership: %w", err)
	} else if membership == nil || !membership.Active || membership.UserID != userID || membership.TenantID != tenantID {
		membership = nil
		err = ErrMembershipNotFound
	}
	e.memberships[key] = membershipResult{membership: membership, err: err}
	return membership, err
}

func errorsIsPermissionDenial(err error) bool {
	return errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrMembershipNotFound)
}

func validResourceRef(ref ResourceRef) bool {
	return strings.TrimSpace(string(ref.Kind)) != "" && strings.TrimSpace(ref.ID) != ""
}

func validAction(action Action) bool {
	switch action {
	case ActionEnable, ActionRead, ActionWrite, ActionShare:
		return true
	default:
		return false
	}
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationDeleteContent, OperationShare, OperationRun, OperationUse:
		return true
	default:
		return false
	}
}

func validTenantRequirement(requirement TenantRequirement) bool {
	switch requirement {
	case TenantMember, TenantNormalMember, TenantAdmin, TenantOwner:
		return true
	default:
		return false
	}
}

func membershipSatisfies(membership *Membership, requirement TenantRequirement) bool {
	if membership == nil || !membership.Active {
		return false
	}
	switch requirement {
	case TenantMember:
		return membership.Role == RoleOwner || membership.Role == RoleAdmin || membership.Role == RoleNormal
	case TenantNormalMember:
		return membership.Role == RoleNormal
	case TenantAdmin:
		return membership.Role == RoleOwner || membership.Role == RoleAdmin
	case TenantOwner:
		return membership.Role == RoleOwner
	default:
		return false
	}
}

func validOperations(operations []Operation) bool {
	for _, operation := range operations {
		if !validOperation(operation) {
			return false
		}
	}
	return true
}

func resourceAccess(resource Resource, source AccessSource) Access {
	return resourceAccessWithOperations(resource, source, resource.OwnerOperations)
}

func resourceAccessWithOperations(resource Resource, source AccessSource, operations []Operation) Access {
	permissionMask := int32(0)
	for _, operation := range operations {
		switch operation {
		case OperationRead, OperationRun, OperationUse:
			permissionMask |= ResourcePermissionRead
		case OperationCreate, OperationUpdate, OperationDeleteContent:
			permissionMask |= ResourcePermissionWrite
		case OperationDelete, OperationShare:
			permissionMask |= ResourcePermissionManage
		}
	}
	if source == AccessSourceOwner {
		permissionMask = ResourcePermissionOwner
	}
	return Access{
		Resource:       resource.Ref,
		TenantID:       resource.TenantID,
		Source:         source,
		PermissionMask: permissionMask,
		Operations:     append([]Operation(nil), operations...),
	}
}

func accessAllows(access Access, operation Operation) bool {
	return access.Allows(operation)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func uniqueRefs(refs []ResourceRef) []ResourceRef {
	seen := make(map[ResourceRef]struct{}, len(refs))
	unique := make([]ResourceRef, 0, len(refs))
	for _, ref := range refs {
		if !validResourceRef(ref) {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		unique = append(unique, ref)
	}
	return unique
}
