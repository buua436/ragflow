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

type databaseSource struct {
	db       *gorm.DB
	lockRows bool
}

// NewDatabaseChecker creates a Checker backed by the application's SQL database.
func NewDatabaseChecker(db *gorm.DB) *Checker {
	return NewChecker(&databaseSource{db: db})
}

// NewLockingDatabaseChecker creates a database-backed Checker that locks loaded
// resource and membership rows. Use it only with a short-lived transaction.
func NewLockingDatabaseChecker(tx *gorm.DB) *Checker {
	return NewChecker(&databaseSource{db: tx, lockRows: true})
}

// TenantOwnerMembership returns the active owner membership for a tenant.
// Tenant IDs and user IDs are independent values; no ID-based owner fallback
// is applied when the owner relation is missing.
func TenantOwnerMembership(ctx context.Context, db *gorm.DB, tenantID string) (*entity.UserTenant, error) {
	if db == nil {
		return nil, ErrSourceUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, ErrTenantContextMissing
	}
	var owners []entity.UserTenant
	if err := db.WithContext(ctx).
		Where("tenant_id = ? AND role = ? AND status = ?", tenantID, string(RoleOwner), string(entity.StatusValid)).
		Order("id ASC").Find(&owners).Error; err != nil {
		return nil, fmt.Errorf("permission: load tenant owner membership: %w", err)
	}
	if len(owners) == 0 {
		return nil, ErrMembershipNotFound
	}
	if len(owners) != 1 || owners[0].UserID == "" {
		return nil, fmt.Errorf("%w: tenant %q must have exactly one active owner", ErrInvalidPermission, tenantID)
	}
	return &owners[0], nil
}

func (s *databaseSource) GetMembership(ctx context.Context, userID, tenantID string) (*Membership, error) {
	if s == nil || s.db == nil {
		return nil, ErrSourceUnavailable
	}
	query := s.db.WithContext(ctx).Where("user_id = ? AND tenant_id = ? AND status = ?", userID, tenantID, string(entity.StatusValid))
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var relation entity.UserTenant
	if err := query.First(&relation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	role, valid, err := s.resolveMembershipRole(ctx, relation.TenantID, relation.Role)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, nil
	}
	return &Membership{
		ID:       relation.ID,
		UserID:   relation.UserID,
		TenantID: relation.TenantID,
		Role:     role,
		Active:   relation.Status != nil && *relation.Status == string(entity.StatusValid),
	}, nil
}

func (s *databaseSource) resolveMembershipRole(ctx context.Context, tenantID, roleValue string) (TenantRole, bool, error) {
	role := TenantRole(strings.TrimSpace(roleValue))
	switch role {
	case RoleOwner, RoleAdmin, RoleNormal:
		return role, true, nil
	}
	valid, err := isTenantRoleID(ctx, s.db, tenantID, string(role))
	if err != nil {
		return "", false, err
	}
	if !valid {
		return "", false, nil
	}
	// Feature roles grant capabilities, while tenant membership still denotes
	// ordinary membership to the shared resource policy.
	return RoleNormal, true, nil
}

func (s *databaseSource) activeTenantIDsForUser(ctx context.Context, userID string) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, ErrSourceUnavailable
	}
	var memberships []entity.UserTenant
	if err := s.db.WithContext(ctx).
		Select("tenant_id", "role").
		Where("user_id = ? AND status = ?", userID, string(entity.StatusValid)).
		Find(&memberships).Error; err != nil {
		return nil, err
	}

	type roleResult struct {
		role  TenantRole
		valid bool
		err   error
	}
	resolved := make(map[string]roleResult)
	tenantIDs := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		key := membership.TenantID + "\x00" + membership.Role
		result, ok := resolved[key]
		if !ok {
			result.role, result.valid, result.err = s.resolveMembershipRole(ctx, membership.TenantID, membership.Role)
			resolved[key] = result
		}
		if result.err != nil {
			return nil, result.err
		}
		if result.valid {
			tenantIDs = append(tenantIDs, membership.TenantID)
		}
	}
	return uniqueStringValues(tenantIDs), nil
}

func (s *databaseSource) GetResources(ctx context.Context, refs []ResourceRef) ([]Resource, error) {
	if s == nil || s.db == nil {
		return nil, ErrSourceUnavailable
	}
	refs = uniqueRefs(refs)
	idsByLoadGroup := make(map[ResourceKind][]string, len(resourceDirectory))
	for _, ref := range refs {
		definition, ok := resourceDefinitionFor(ref.Kind)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported resource kind %q", ErrInvalidPermission, ref.Kind)
		}
		loadGroup := definition.loadGroup
		if loadGroup == "" {
			loadGroup = ref.Kind
		}
		idsByLoadGroup[loadGroup] = append(idsByLoadGroup[loadGroup], ref.ID)
	}
	idsFor := func(loadGroup ResourceKind) []string { return idsByLoadGroup[loadGroup] }
	datasetIDs := idsFor(ResourceKindDataset)
	documentIDs := idsFor(ResourceKindDocument)
	canvasIDs := idsFor(ResourceKindCanvas)
	agentSessionIDs := idsFor(ResourceKindAgentSession)
	memoryIDs := idsFor(ResourceKindMemory)
	fileIDs := idsFor(ResourceKindFile)
	searchAppIDs := idsFor(ResourceKindSearchApp)
	chatIDs := idsFor(ResourceKindChat)
	chatSessionIDs := idsFor(ResourceKindChatSession)
	chatChannelIDs := idsFor(ResourceKindChatChannel)
	connectorIDs := idsFor(ResourceKindConnector)
	syncTaskIDs := idsFor(ResourceKindSyncTask)
	modelProviderIDs := idsFor(ResourceKindModelProvider)
	modelInstanceIDs := idsFor(ResourceKindModelInstance)
	tenantModelIDs := idsFor(ResourceKindModel)
	mcpServerIDs := idsFor(ResourceKindMCPServer)
	skillSpaceIDs := idsFor(ResourceKindSkillSpace)
	agentSessionsByID, err := s.loadAgentSessions(ctx, agentSessionIDs)
	if err != nil {
		return nil, err
	}
	for _, session := range agentSessionsByID {
		canvasIDs = append(canvasIDs, session.DialogID)
	}
	chatSessionsByID, err := s.loadChatSessions(ctx, chatSessionIDs)
	if err != nil {
		return nil, err
	}
	for _, session := range chatSessionsByID {
		chatIDs = append(chatIDs, session.DialogID)
	}
	documentsByID, err := s.loadDocuments(ctx, documentIDs)
	if err != nil {
		return nil, err
	}
	for _, document := range documentsByID {
		datasetIDs = append(datasetIDs, document.KbID)
	}
	datasetIDs = uniqueStringValues(datasetIDs)
	var datasetsByID map[string]*entity.Knowledgebase
	if len(datasetIDs) > 0 {
		datasetsByID, err = s.loadDatasets(ctx, datasetIDs)
		if err != nil {
			return nil, err
		}
	}
	canvasesByID, err := s.loadCanvases(ctx, canvasIDs)
	if err != nil {
		return nil, err
	}
	memoriesByID, err := s.loadMemories(ctx, memoryIDs)
	if err != nil {
		return nil, err
	}
	filesByID, err := s.loadFiles(ctx, fileIDs)
	if err != nil {
		return nil, err
	}
	fileDatasetIDs, err := s.loadFileDatasetIDs(ctx, fileIDs)
	if err != nil {
		return nil, err
	}
	linkedDatasetIDs := make([]string, 0)
	for _, ids := range fileDatasetIDs {
		linkedDatasetIDs = append(linkedDatasetIDs, ids...)
	}
	linkedDatasetIDs = uniqueStringValues(linkedDatasetIDs)
	linkedDatasetsByID, err := s.loadDatasets(ctx, linkedDatasetIDs)
	if err != nil {
		return nil, err
	}
	searchAppsByID, err := s.loadSearchApps(ctx, searchAppIDs)
	if err != nil {
		return nil, err
	}
	chatsByID, err := s.loadChats(ctx, chatIDs)
	if err != nil {
		return nil, err
	}
	chatChannelsByID, err := s.loadChatChannels(ctx, chatChannelIDs)
	if err != nil {
		return nil, err
	}
	syncTasksByID, err := s.loadSyncTasks(ctx, syncTaskIDs)
	if err != nil {
		return nil, err
	}
	for _, task := range syncTasksByID {
		connectorIDs = append(connectorIDs, task.ConnectorID)
	}
	connectorIDs = uniqueStringValues(connectorIDs)
	connectorsByID, err := s.loadConnectors(ctx, connectorIDs)
	if err != nil {
		return nil, err
	}
	syncTaskMappings, err := s.loadSyncTaskMappings(ctx, syncTasksByID)
	if err != nil {
		return nil, err
	}
	tenantModelsByID, err := s.loadTenantModels(ctx, tenantModelIDs)
	if err != nil {
		return nil, err
	}
	for _, model := range tenantModelsByID {
		modelProviderIDs = append(modelProviderIDs, model.ProviderID)
		modelInstanceIDs = append(modelInstanceIDs, model.InstanceID)
	}
	modelInstancesByID, err := s.loadModelInstances(ctx, modelInstanceIDs)
	if err != nil {
		return nil, err
	}
	for _, instance := range modelInstancesByID {
		modelProviderIDs = append(modelProviderIDs, instance.ProviderID)
	}
	modelProviderIDs = uniqueStringValues(modelProviderIDs)
	modelProvidersByID, err := s.loadModelProviders(ctx, modelProviderIDs)
	if err != nil {
		return nil, err
	}
	mcpServersByID, err := s.loadMCPServers(ctx, mcpServerIDs)
	if err != nil {
		return nil, err
	}
	skillSpacesByID, err := s.loadSkillSpaces(ctx, skillSpaceIDs)
	if err != nil {
		return nil, err
	}
	skillSpaceFolderIDs := make([]string, 0, len(skillSpacesByID))
	for _, space := range skillSpacesByID {
		skillSpaceFolderIDs = append(skillSpaceFolderIDs, space.FolderID)
	}
	skillSpaceFoldersByID, err := s.loadSkillSpaceFolders(ctx, skillSpaceFolderIDs)
	if err != nil {
		return nil, err
	}
	facts := resourceFacts{
		datasetsByID: datasetsByID, documentsByID: documentsByID, canvasesByID: canvasesByID,
		agentSessionsByID: agentSessionsByID, chatSessionsByID: chatSessionsByID, memoriesByID: memoriesByID,
		filesByID: filesByID, fileDatasetIDs: fileDatasetIDs, linkedDatasetsByID: linkedDatasetsByID,
		searchAppsByID: searchAppsByID, chatsByID: chatsByID, chatChannelsByID: chatChannelsByID,
		connectorsByID: connectorsByID, syncTasksByID: syncTasksByID, syncTaskMappings: syncTaskMappings,
		modelProvidersByID: modelProvidersByID, modelInstancesByID: modelInstancesByID, tenantModelsByID: tenantModelsByID,
		mcpServersByID: mcpServersByID, skillSpacesByID: skillSpacesByID, skillSpaceFoldersByID: skillSpaceFoldersByID,
	}
	resources := make([]Resource, 0, len(refs))
	for _, ref := range refs {
		definition, ok := resourceDefinitionFor(ref.Kind)
		if !ok || definition.build == nil {
			return nil, fmt.Errorf("%w: unsupported resource kind %q", ErrInvalidPermission, ref.Kind)
		}
		resource, include, err := definition.build(ref, &facts)
		if err != nil {
			return nil, err
		}
		if include {
			resources = append(resources, resource)
		}
	}
	return resources, nil
}

func (s *databaseSource) ListResourceRefs(ctx context.Context, kind ResourceKind, parent ResourceRef) ([]ResourceRef, error) {
	if s == nil || s.db == nil {
		return nil, ErrSourceUnavailable
	}
	definition, ok := resourceDefinitionFor(kind)
	if !ok || definition.list == nil {
		return nil, fmt.Errorf("%w: unsupported scope resource kind %q", ErrInvalidPermission, kind)
	}
	if err := validateResourceParent(kind, parent, definition); err != nil {
		return nil, err
	}
	return definition.list(s, ctx, kind, parent, definition)
}

func (s *databaseSource) loadConnectors(ctx context.Context, ids []string) (map[string]*entity.Connector, error) {
	connectorsByID := make(map[string]*entity.Connector)
	if len(ids) == 0 {
		return connectorsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Connector{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var connectors []*entity.Connector
	if err := query.Find(&connectors).Error; err != nil {
		return nil, err
	}
	for _, connector := range connectors {
		connectorsByID[connector.ID] = connector
	}
	return connectorsByID, nil
}

func (s *databaseSource) loadSyncTasks(ctx context.Context, ids []string) (map[string]*entity.SyncLogs, error) {
	tasksByID := make(map[string]*entity.SyncLogs)
	if len(ids) == 0 {
		return tasksByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.SyncLogs{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var tasks []*entity.SyncLogs
	if err := query.Find(&tasks).Error; err != nil {
		return nil, err
	}
	for _, task := range tasks {
		tasksByID[task.ID] = task
	}
	return tasksByID, nil
}

type connectorDatasetRef struct {
	connectorID string
	datasetID   string
}

func (s *databaseSource) loadSyncTaskMappings(ctx context.Context, tasks map[string]*entity.SyncLogs) (map[connectorDatasetRef]struct{}, error) {
	mappings := make(map[connectorDatasetRef]struct{})
	connectorIDs := make([]string, 0, len(tasks))
	for _, task := range tasks {
		connectorIDs = append(connectorIDs, task.ConnectorID)
	}
	connectorIDs = uniqueStringValues(connectorIDs)
	if len(connectorIDs) == 0 {
		return mappings, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Connector2Kb{}).
		Joins("JOIN knowledgebase ON knowledgebase.id = connector2kb.kb_id").
		Where("connector2kb.connector_id IN ?", connectorIDs)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var links []entity.Connector2Kb
	if err := query.Find(&links).Error; err != nil {
		return nil, err
	}
	for _, link := range links {
		mappings[connectorDatasetRef{connectorID: link.ConnectorID, datasetID: link.KbID}] = struct{}{}
	}
	return mappings, nil
}

func (s *databaseSource) loadFiles(ctx context.Context, ids []string) (map[string]*entity.File, error) {
	filesByID := make(map[string]*entity.File)
	if len(ids) == 0 {
		return filesByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.File{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var files []*entity.File
	if err := query.Find(&files).Error; err != nil {
		return nil, err
	}
	for _, file := range files {
		filesByID[file.ID] = file
	}
	return filesByID, nil
}

func (s *databaseSource) loadChats(ctx context.Context, ids []string) (map[string]*entity.Chat, error) {
	chatsByID := make(map[string]*entity.Chat)
	if len(ids) == 0 {
		return chatsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Chat{}).
		Where("id IN ? AND status = ?", ids, string(entity.StatusValid))
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var chats []*entity.Chat
	if err := query.Find(&chats).Error; err != nil {
		return nil, err
	}
	for _, chat := range chats {
		chatsByID[chat.ID] = chat
	}
	return chatsByID, nil
}

func (s *databaseSource) loadSearchApps(ctx context.Context, ids []string) (map[string]*entity.Search, error) {
	searchAppsByID := make(map[string]*entity.Search)
	if len(ids) == 0 {
		return searchAppsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Search{}).
		Where("id IN ? AND status = ?", ids, string(entity.StatusValid))
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var searchApps []*entity.Search
	if err := query.Find(&searchApps).Error; err != nil {
		return nil, err
	}
	for _, searchApp := range searchApps {
		searchAppsByID[searchApp.ID] = searchApp
	}
	return searchAppsByID, nil
}

func (s *databaseSource) loadChatSessions(ctx context.Context, ids []string) (map[string]*entity.ChatSession, error) {
	sessionsByID := make(map[string]*entity.ChatSession)
	if len(ids) == 0 {
		return sessionsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.ChatSession{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var sessions []*entity.ChatSession
	if err := query.Find(&sessions).Error; err != nil {
		return nil, err
	}
	for _, session := range sessions {
		sessionsByID[session.ID] = session
	}
	return sessionsByID, nil
}

func (s *databaseSource) loadFileDatasetIDs(ctx context.Context, fileIDs []string) (map[string][]string, error) {
	datasetIDsByFile := make(map[string][]string)
	if len(fileIDs) == 0 {
		return datasetIDsByFile, nil
	}
	var links []struct {
		FileID    string `gorm:"column:file_id"`
		DatasetID string `gorm:"column:dataset_id"`
	}
	query := s.db.WithContext(ctx).Table("file2document AS f2d").
		Select("f2d.file_id AS file_id, document.kb_id AS dataset_id").
		Joins("JOIN document ON document.id = f2d.document_id").
		Where("f2d.file_id IN ?", fileIDs)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := query.Find(&links).Error; err != nil {
		return nil, err
	}
	datasetIDs := make(map[string]struct{})
	for _, link := range links {
		if link.FileID == "" || link.DatasetID == "" {
			continue
		}
		datasetIDsByFile[link.FileID] = append(datasetIDsByFile[link.FileID], link.DatasetID)
		datasetIDs[link.DatasetID] = struct{}{}
	}
	for fileID, ids := range datasetIDsByFile {
		datasetIDsByFile[fileID] = uniqueStringValues(ids)
	}
	return datasetIDsByFile, nil
}

func (s *databaseSource) loadCanvases(ctx context.Context, ids []string) (map[string]*entity.UserCanvas, error) {
	canvasesByID := make(map[string]*entity.UserCanvas)
	if len(ids) == 0 {
		return canvasesByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.UserCanvas{}).
		Select("id", "user_id", "tenant_id", "permission").Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var canvases []*entity.UserCanvas
	if err := query.Find(&canvases).Error; err != nil {
		return nil, err
	}
	for _, canvas := range canvases {
		canvasesByID[canvas.ID] = canvas
	}
	return canvasesByID, nil
}

func (s *databaseSource) loadAgentSessions(ctx context.Context, ids []string) (map[string]*entity.API4Conversation, error) {
	sessionsByID := make(map[string]*entity.API4Conversation)
	if len(ids) == 0 {
		return sessionsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.API4Conversation{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var sessions []*entity.API4Conversation
	if err := query.Find(&sessions).Error; err != nil {
		return nil, err
	}
	for _, session := range sessions {
		sessionsByID[session.ID] = session
	}
	return sessionsByID, nil
}

func (s *databaseSource) loadMemories(ctx context.Context, ids []string) (map[string]*entity.Memory, error) {
	memoriesByID := make(map[string]*entity.Memory)
	if len(ids) == 0 {
		return memoriesByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Memory{}).Where("id IN ?", ids)
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var memories []*entity.Memory
	if err := query.Find(&memories).Error; err != nil {
		return nil, err
	}
	for _, memory := range memories {
		memoriesByID[memory.ID] = memory
	}
	return memoriesByID, nil
}

func (s *databaseSource) loadDocuments(ctx context.Context, ids []string) (map[string]*entity.Document, error) {
	documentsByID := make(map[string]*entity.Document)
	if len(ids) == 0 {
		return documentsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Document{}).
		Where("id IN ? AND status = ?", ids, string(entity.StatusValid))
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var documents []*entity.Document
	if err := query.Find(&documents).Error; err != nil {
		return nil, err
	}
	for _, document := range documents {
		documentsByID[document.ID] = document
	}
	return documentsByID, nil
}

func (s *databaseSource) loadDatasets(ctx context.Context, ids []string) (map[string]*entity.Knowledgebase, error) {
	datasetsByID := make(map[string]*entity.Knowledgebase)
	if len(ids) == 0 {
		return datasetsByID, nil
	}
	query := s.db.WithContext(ctx).Model(&entity.Knowledgebase{}).Where("id IN ? AND status = ?", ids, string(entity.StatusValid))
	if s.lockRows {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var datasets []*entity.Knowledgebase
	if err := query.Find(&datasets).Error; err != nil {
		return nil, err
	}
	for _, dataset := range datasets {
		datasetsByID[dataset.ID] = dataset
	}
	return datasetsByID, nil
}

func datasetResource(dataset *entity.Knowledgebase) Resource {
	visibility := VisibilityPrivate
	switch dataset.Permission {
	case string(entity.TenantPermissionMe):
		visibility = VisibilityPrivate
	case string(entity.TenantPermissionTeam):
		visibility = VisibilityTenant
	}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindDataset, ID: dataset.ID},
		TenantID:          dataset.TenantID,
		CreatedBy:         dataset.CreatedBy,
		OwnerUserID:       dataset.UserID,
		Visibility:        visibility,
		TenantRequirement: TenantNormalMember,
		OwnerOperations:   []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationDeleteContent, OperationShare, OperationRun, OperationUse},
		TenantOperations:  []Operation{OperationRead, OperationUpdate, OperationDeleteContent, OperationRun, OperationUse},
		Active:            dataset.Status != nil && *dataset.Status == string(entity.StatusValid),
	}
}

func documentResource(document *entity.Document, dataset *entity.Knowledgebase) Resource {
	datasetAccess := datasetResource(dataset)
	return Resource{
		Ref:                   ResourceRef{Kind: ResourceKindDocument, ID: document.ID},
		TenantID:              datasetAccess.TenantID,
		CreatedBy:             document.CreatedBy,
		OwnerUserID:           document.UserID,
		ParentRefs:            []ResourceRef{{Kind: ResourceKindDataset, ID: document.KbID}},
		ParentAccessOperation: OperationRead,
		Visibility:            datasetAccess.Visibility,
		TenantRequirement:     datasetAccess.TenantRequirement,
		OwnerOperations:       datasetAccess.OwnerOperations,
		TenantOperations:      datasetAccess.TenantOperations,
		CreatorOperations:     datasetAccess.CreatorOperations,
		Active:                datasetAccess.Active && document.Status != nil && *document.Status == string(entity.StatusValid),
	}
}

func canvasResource(canvas *entity.UserCanvas) Resource {
	tenantID := ""
	if canvas.TenantID != nil {
		tenantID = strings.TrimSpace(*canvas.TenantID)
	}
	visibility := VisibilityPrivate
	if canvas.Permission == string(entity.TenantPermissionTeam) {
		visibility = VisibilityTenant
	}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindCanvas, ID: canvas.ID},
		TenantID:          tenantID,
		CreatedBy:         canvas.UserID,
		OwnerUserID:       canvas.UserID,
		Visibility:        visibility,
		TenantRequirement: TenantMember,
		OwnerOperations:   []Operation{OperationRead, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
		TenantOperations:  []Operation{OperationRead, OperationUpdate, OperationRun, OperationUse},
		Active:            true,
	}
}

func agentSessionResource(session *entity.API4Conversation, canvas *entity.UserCanvas) Resource {
	tenantID := ""
	if canvas.TenantID != nil {
		tenantID = strings.TrimSpace(*canvas.TenantID)
	}
	return Resource{
		Ref:             ResourceRef{Kind: ResourceKindAgentSession, ID: session.ID},
		TenantID:        tenantID,
		CreatedBy:       session.UserID,
		OwnerUserID:     session.UserID,
		Visibility:      VisibilityPrivate,
		OwnerOperations: []Operation{OperationRead, OperationRun, OperationUpdate, OperationDelete},
		Active:          true,
	}
}

func memoryResource(memory *entity.Memory) Resource {
	visibility := VisibilityPrivate
	if memory.Permissions == string(entity.TenantPermissionTeam) {
		visibility = VisibilityTenant
	}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindMemory, ID: memory.ID},
		TenantID:          memory.TenantID,
		OwnerUserID:       memory.UserID,
		Visibility:        visibility,
		TenantRequirement: TenantMember,
		OwnerOperations:   []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
		TenantOperations:  []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		Active:            true,
	}
}

func chatResource(chat *entity.Chat) Resource {
	return Resource{
		Ref:             ResourceRef{Kind: ResourceKindChat, ID: chat.ID},
		TenantID:        chat.TenantID,
		OwnerUserID:     chat.UserID,
		Visibility:      VisibilityPrivate,
		OwnerOperations: []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		Active:          chat.Status != nil && *chat.Status == string(entity.StatusValid),
	}
}

func searchAppResource(searchApp *entity.Search) Resource {
	return Resource{
		Ref:             ResourceRef{Kind: ResourceKindSearchApp, ID: searchApp.ID},
		TenantID:        searchApp.TenantID,
		CreatedBy:       searchApp.CreatedBy,
		OwnerUserID:     searchApp.UserID,
		Visibility:      VisibilityPrivate,
		OwnerOperations: []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		Active:          searchApp.Status != nil && *searchApp.Status == string(entity.StatusValid),
	}
}

func chatSessionResource(session *entity.ChatSession, chat *entity.Chat) Resource {
	createdBy := ""
	if session.UserID != nil {
		createdBy = *session.UserID
	}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindChatSession, ID: session.ID},
		TenantID:          chat.TenantID,
		CreatedBy:         createdBy,
		OwnerUserID:       chat.UserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		TenantOperations:  []Operation{OperationRead},
		CreatorOperations: []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		Active:            true,
	}
}

func chatChannelResource(channel *entity.ChatChannel) Resource {
	operations := []Operation{OperationRead, OperationUpdate, OperationDelete, OperationUse}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindChatChannel, ID: channel.ID},
		TenantID:          channel.TenantID,
		OwnerUserID:       channel.UserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   operations,
		TenantOperations:  operations,
		Active:            true,
	}
}

func connectorResource(connector *entity.Connector) Resource {
	ownerOperations := []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindConnector, ID: connector.ID},
		TenantID:          connector.TenantID,
		OwnerUserID:       connector.UserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   ownerOperations,
		TenantOperations:  []Operation{OperationRun, OperationUse},
		Active:            true,
	}
}

func syncTaskResource(task *entity.SyncLogs, connector *entity.Connector, linked bool) Resource {
	operations := []Operation{OperationRead}
	if strings.EqualFold(task.TaskType, "sync") && task.Status == string(entity.TaskStatusFail) {
		operations = append(operations, OperationRun)
	}
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindSyncTask, ID: task.ID},
		TenantID:          connector.TenantID,
		OwnerUserID:       connector.UserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   operations,
		TenantOperations:  operations,
		Active:            linked,
	}
}

func fileResource(kind ResourceKind, file *entity.File, datasetIDs []string, datasetsByID map[string]*entity.Knowledgebase) Resource {
	sharedWithUserIDs := make([]string, 0, len(datasetIDs))
	sharedWithTenantIDs := make([]string, 0, len(datasetIDs))
	for _, datasetID := range datasetIDs {
		dataset, ok := datasetsByID[datasetID]
		if !ok {
			continue
		}
		datasetAccess := datasetResource(dataset)
		sharedWithUserIDs = append(sharedWithUserIDs, datasetAccess.OwnerUserID)
		if datasetAccess.Visibility == VisibilityTenant {
			sharedWithTenantIDs = append(sharedWithTenantIDs, datasetAccess.TenantID)
		}
	}
	sharedWithUserIDs = uniqueStringValues(sharedWithUserIDs)
	sharedWithTenantIDs = uniqueStringValues(sharedWithTenantIDs)
	visibility := VisibilityPrivate
	if len(sharedWithUserIDs) > 0 || len(sharedWithTenantIDs) > 0 {
		visibility = VisibilityShared
	}
	ownerUserID := strings.TrimSpace(file.UserID)
	if file.ParentID == file.ID {
		return Resource{
			Ref:               ResourceRef{Kind: kind, ID: file.ID},
			TenantID:          file.TenantID,
			CreatedBy:         file.CreatedBy,
			OwnerUserID:       ownerUserID,
			Visibility:        VisibilityTenant,
			TenantRequirement: TenantMember,
			OwnerOperations:   []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
			TenantOperations:  []Operation{OperationRead, OperationCreate},
			Active:            true,
		}
	}
	return Resource{
		Ref:                 ResourceRef{Kind: kind, ID: file.ID},
		TenantID:            file.TenantID,
		CreatedBy:           file.CreatedBy,
		OwnerUserID:         ownerUserID,
		Visibility:          visibility,
		OwnerOperations:     []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
		SharedWithUserIDs:   sharedWithUserIDs,
		SharedWithTenantIDs: sharedWithTenantIDs,
		Active:              true,
	}
}

func mcpServerResource(id, tenantID, ownerUserID string) Resource {
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindMCPServer, ID: id},
		TenantID:          tenantID,
		OwnerUserID:       ownerUserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationUse},
		TenantOperations:  []Operation{OperationUse},
		Active:            true,
	}
}

func skillSpaceResource(id, tenantID, ownerUserID string) Resource {
	return Resource{
		Ref:               ResourceRef{Kind: ResourceKindSkillSpace, ID: id},
		TenantID:          tenantID,
		OwnerUserID:       ownerUserID,
		Visibility:        VisibilityTenant,
		TenantRequirement: TenantMember,
		OwnerOperations:   []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationUse},
		TenantOperations:  []Operation{OperationRead, OperationUse},
		Active:            true,
	}
}

func uniqueStringValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
