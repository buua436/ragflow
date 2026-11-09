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
	"fmt"
	"strings"

	"ragflow/internal/entity"
)

// resourceDirectory is the shared description of persisted resource identity
// and its relationship to tenant, owner, creator, and parent records. Edition
// specific grant metadata is attached by the corresponding build-tagged file.
var resourceDirectory = map[ResourceKind]resourceDefinition{
	ResourceKindDataset: {
		list:  listDatasetResourceRefs,
		table: "knowledgebase", tenantColumn: "tenant_id", ownerColumn: "user_id", creatorColumn: "created_by",
		statusColumn: "status", statusValue: entity.StatusValid,
		ownerOperations:  []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationDeleteContent, OperationShare, OperationRun, OperationUse},
		tenantOperations: []Operation{OperationRead, OperationUpdate, OperationDeleteContent, OperationRun, OperationUse},
		visibilityColumn: "permission", tenantValue: string(entity.TenantPermissionTeam), tenantRequirement: TenantNormalMember,
		build: buildDatasetFact,
	},
	ResourceKindDocument: {
		list:  listDocumentResourceRefs,
		table: "document", ownerColumn: "user_id", creatorColumn: "created_by", statusColumn: "status", statusValue: entity.StatusValid,
		parents: []resourceParent{{kind: ResourceKindDataset, column: "kb_id"}}, requiredParent: true, parentAccessOperation: OperationRead,
		tenantRelation: &resourceRelation{table: "knowledgebase", localColumn: "kb_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		build:          buildDocumentFact,
	},
	ResourceKindCanvas: {
		list:  listCanvasResourceRefs,
		table: "user_canvas", tenantColumn: "tenant_id", ownerColumn: "user_id", creatorColumn: "user_id",
		ownerOperations:  []Operation{OperationRead, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
		tenantOperations: []Operation{OperationRead, OperationUpdate, OperationRun, OperationUse},
		visibilityColumn: "permission", tenantValue: string(entity.TenantPermissionTeam), tenantRequirement: TenantMember,
		build: buildCanvasFact,
	},
	ResourceKindAgentSession: {
		list:  listAgentSessionResourceRefs,
		table: "api_4_conversation", ownerColumn: "user_id", creatorColumn: "user_id",
		parents: []resourceParent{{kind: ResourceKindCanvas, column: "dialog_id"}}, requiredParent: true,
		tenantRelation: &resourceRelation{table: "user_canvas", localColumn: "dialog_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		build:          buildAgentSessionFact,
	},
	ResourceKindMemory: {
		list:  listMemoryResourceRefs,
		table: "memory", tenantColumn: "tenant_id", ownerColumn: "user_id",
		ownerOperations:  []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationShare, OperationRun, OperationUse},
		tenantOperations: []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		visibilityColumn: "permissions", tenantValue: string(entity.TenantPermissionTeam), tenantRequirement: TenantMember,
		build: buildMemoryFact,
	},
	ResourceKindFile: {
		list:  listFileResourceRefs,
		table: "file", tenantColumn: "tenant_id", ownerColumn: "user_id", creatorColumn: "created_by",
		parents: []resourceParent{{kind: ResourceKindFolder, column: "parent_id"}}, requiredParent: true,
		build: buildFileFact,
	},
	ResourceKindFolder: {
		list:  listFileResourceRefs,
		table: "file", tenantColumn: "tenant_id", ownerColumn: "user_id", creatorColumn: "created_by",
		parents: []resourceParent{{kind: ResourceKindFolder, column: "parent_id"}}, requiredParent: true,
		loadGroup: ResourceKindFile, build: buildFileFact,
	},
	ResourceKindSearchApp: {
		list:  listSearchAppResourceRefs,
		table: "search", tenantColumn: "tenant_id", ownerColumn: "user_id", creatorColumn: "created_by", statusColumn: "status", statusValue: entity.StatusValid,
		ownerOperations: []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		build:           buildSearchFact,
	},
	ResourceKindChat: {
		list:  listChatResourceRefs,
		table: "dialog", tenantColumn: "tenant_id", ownerColumn: "user_id", statusColumn: "status", statusValue: entity.StatusValid,
		ownerOperations: []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		build:           buildChatFact,
	},
	ResourceKindChatSession: {
		list:  listChatSessionResourceRefs,
		table: "conversation", parents: []resourceParent{{kind: ResourceKindChat, column: "dialog_id"}}, requiredParent: true,
		tenantRelation: &resourceRelation{table: "dialog", localColumn: "dialog_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		ownerRelation:  &resourceRelation{table: "dialog", localColumn: "dialog_id", relatedIDColumn: "id", relatedColumn: "user_id"},
		creatorColumn:  "user_id",
		build:          buildChatSessionFact,
	},
	ResourceKindChatChannel: {
		list:  listChatChannelResourceRefs,
		table: "chat_channel", tenantColumn: "tenant_id", ownerColumn: "user_id",
		ownerOperations:  []Operation{OperationRead, OperationUpdate, OperationDelete, OperationUse},
		tenantOperations: []Operation{OperationRead, OperationUpdate, OperationDelete, OperationUse}, tenantRequirement: TenantMember,
		build: buildChatChannelFact,
	},
	ResourceKindConnector: {
		list:  listConnectorResourceRefs,
		table: "connector", tenantColumn: "tenant_id", ownerColumn: "user_id",
		ownerOperations:  []Operation{OperationRead, OperationUpdate, OperationDelete, OperationRun, OperationUse},
		tenantOperations: []Operation{OperationRun, OperationUse}, tenantRequirement: TenantMember,
		build: buildConnectorFact,
	},
	ResourceKindSyncTask: {
		list:  listSyncTaskResourceRefs,
		table: "sync_logs", parents: []resourceParent{{kind: ResourceKindConnector, column: "connector_id"}},
		tenantRelation: &resourceRelation{table: "connector", localColumn: "connector_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		ownerRelation:  &resourceRelation{table: "connector", localColumn: "connector_id", relatedIDColumn: "id", relatedColumn: "user_id"},
		build:          buildSyncTaskFact,
	},
	ResourceKindModelProvider: {
		list:  listModelProviderResourceRefs,
		table: "tenant_model_provider", tenantColumn: "tenant_id", ownerColumn: "user_id",
		build: buildModelProviderFact,
	},
	ResourceKindModelInstance: {
		list:  listModelInstanceResourceRefs,
		table: "tenant_model_instance", parents: []resourceParent{{kind: ResourceKindModelProvider, column: "provider_id"}},
		tenantRelation: &resourceRelation{table: "tenant_model_provider", localColumn: "provider_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		ownerRelation:  &resourceRelation{table: "tenant_model_provider", localColumn: "provider_id", relatedIDColumn: "id", relatedColumn: "user_id"},
		build:          buildModelInstanceFact,
	},
	ResourceKindModel: {
		list:  listModelResourceRefs,
		table: "tenant_model", parents: []resourceParent{
			{kind: ResourceKindModelProvider, column: "provider_id"},
			{kind: ResourceKindModelInstance, column: "instance_id", relatedColumn: "provider_id", relatedParentColumn: "provider_id"},
		},
		tenantRelation: &resourceRelation{table: "tenant_model_provider", localColumn: "provider_id", relatedIDColumn: "id", relatedColumn: "tenant_id"},
		ownerRelation:  &resourceRelation{table: "tenant_model_provider", localColumn: "provider_id", relatedIDColumn: "id", relatedColumn: "user_id"},
		build:          buildTenantModelFact,
	},
	ResourceKindMCPServer: {
		list:  listTenantResourceRefs,
		table: "mcp_server", tenantColumn: "tenant_id", ownerColumn: "user_id",
		ownerOperations:  []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationUse},
		tenantOperations: []Operation{OperationUse}, tenantRequirement: TenantMember,
		build: buildMCPServerFact,
	},
	ResourceKindSkillSpace: {
		list:  listTenantResourceRefs,
		table: "skill_spaces", tenantColumn: "tenant_id", ownerColumn: "user_id",
		parents:      []resourceParent{{kind: ResourceKindFolder, column: "folder_id"}},
		statusColumn: "status", statusValue: entity.SpaceStatusActive,
		ownerOperations:  []Operation{OperationRead, OperationCreate, OperationUpdate, OperationDelete, OperationUse},
		tenantOperations: []Operation{OperationRead, OperationUse}, tenantRequirement: TenantMember,
		build: buildSkillSpaceFact,
	},
}

type resourceDefinition struct {
	table                 string
	loadGroup             ResourceKind
	tenantColumn          string
	ownerColumn           string
	creatorColumn         string
	statusColumn          string
	statusValue           interface{}
	parentAccessOperation Operation
	ownerOperations       []Operation
	tenantOperations      []Operation
	visibilityColumn      string
	tenantValue           string
	tenantRequirement     TenantRequirement
	tenantRelation        *resourceRelation
	ownerRelation         *resourceRelation
	parents               []resourceParent
	requiredParent        bool
	list                  func(*databaseSource, context.Context, ResourceKind, ResourceRef, resourceDefinition) ([]ResourceRef, error)
	build                 func(ResourceRef, *resourceFacts) (Resource, bool, error)
}

type resourceFacts struct {
	datasetsByID          map[string]*entity.Knowledgebase
	documentsByID         map[string]*entity.Document
	canvasesByID          map[string]*entity.UserCanvas
	agentSessionsByID     map[string]*entity.API4Conversation
	chatSessionsByID      map[string]*entity.ChatSession
	memoriesByID          map[string]*entity.Memory
	filesByID             map[string]*entity.File
	fileDatasetIDs        map[string][]string
	linkedDatasetsByID    map[string]*entity.Knowledgebase
	searchAppsByID        map[string]*entity.Search
	chatsByID             map[string]*entity.Chat
	chatChannelsByID      map[string]*entity.ChatChannel
	connectorsByID        map[string]*entity.Connector
	syncTasksByID         map[string]*entity.SyncLogs
	syncTaskMappings      map[connectorDatasetRef]struct{}
	modelProvidersByID    map[string]*entity.TenantModelProvider
	modelInstancesByID    map[string]*entity.TenantModelInstance
	tenantModelsByID      map[string]*entity.TenantModel
	mcpServersByID        map[string]mcpServerAuthorization
	skillSpacesByID       map[string]skillSpaceAuthorization
	skillSpaceFoldersByID map[string]folderAuthorization
}

type resourceRelation struct {
	table           string
	localColumn     string
	relatedIDColumn string
	relatedColumn   string
}

type resourceParent struct {
	kind                ResourceKind
	column              string
	relatedColumn       string
	relatedParentColumn string
}

func resourceDefinitionFor(kind ResourceKind) (resourceDefinition, bool) {
	definition, ok := resourceDirectory[kind]
	return definition, ok
}

func resourceParentColumn(definition resourceDefinition, parentKind ResourceKind) (string, bool) {
	for _, parent := range definition.parents {
		if parent.kind == parentKind {
			return parent.column, true
		}
	}
	return "", false
}

func validateResourceParent(kind ResourceKind, parent ResourceRef, definition resourceDefinition) error {
	parentID := strings.TrimSpace(parent.ID)
	if parentID == "" {
		if parent.Kind != "" || definition.requiredParent {
			return fmt.Errorf("%w: invalid parent scope for resource kind %q", ErrInvalidPermission, kind)
		}
		return nil
	}
	if _, ok := resourceParentColumn(definition, parent.Kind); ok {
		return nil
	}
	return fmt.Errorf("%w: invalid parent scope for resource kind %q", ErrInvalidPermission, kind)
}
