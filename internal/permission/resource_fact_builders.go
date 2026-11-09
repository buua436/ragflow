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
	"fmt"
	"strings"
)

func buildDatasetFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	dataset, ok := facts.datasetsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return datasetResource(dataset), true, nil
}

func buildDocumentFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	document, ok := facts.documentsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	dataset, ok := facts.datasetsByID[document.KbID]
	if !ok {
		return Resource{}, false, nil
	}
	return documentResource(document, dataset), true, nil
}

func buildCanvasFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	canvas, ok := facts.canvasesByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return canvasResource(canvas), true, nil
}

func buildAgentSessionFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	session, ok := facts.agentSessionsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	canvas, ok := facts.canvasesByID[session.DialogID]
	if !ok {
		return Resource{}, false, nil
	}
	return agentSessionResource(session, canvas), true, nil
}

func buildMemoryFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	memory, ok := facts.memoriesByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return memoryResource(memory), true, nil
}

func buildFileFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	file, ok := facts.filesByID[ref.ID]
	if !ok || (ref.Kind == ResourceKindFolder) != (file.Type == "folder") {
		return Resource{}, false, nil
	}
	return fileResource(ref.Kind, file, facts.fileDatasetIDs[ref.ID], facts.linkedDatasetsByID), true, nil
}

func buildSearchFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	search, ok := facts.searchAppsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return searchAppResource(search), true, nil
}

func buildChatFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	chat, ok := facts.chatsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return chatResource(chat), true, nil
}

func buildChatSessionFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	session, ok := facts.chatSessionsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	chat, ok := facts.chatsByID[session.DialogID]
	if !ok {
		return Resource{}, false, nil
	}
	return chatSessionResource(session, chat), true, nil
}

func buildChatChannelFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	channel, ok := facts.chatChannelsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return chatChannelResource(channel), true, nil
}

func buildConnectorFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	connector, ok := facts.connectorsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	return connectorResource(connector), true, nil
}

func buildSyncTaskFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	task, ok := facts.syncTasksByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	connector, ok := facts.connectorsByID[task.ConnectorID]
	if !ok {
		return Resource{}, false, nil
	}
	_, linked := facts.syncTaskMappings[connectorDatasetRef{connectorID: task.ConnectorID, datasetID: task.KbID}]
	return syncTaskResource(task, connector, linked), true, nil
}

func buildModelProviderFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	provider, ok := facts.modelProvidersByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	if strings.TrimSpace(provider.UserID) == "" {
		return Resource{}, false, fmt.Errorf("%w: model provider %q has no owner user_id", ErrInvalidPermission, provider.ID)
	}
	return modelProviderResource(provider), true, nil
}

func buildModelInstanceFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	instance, ok := facts.modelInstancesByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	provider, ok := facts.modelProvidersByID[instance.ProviderID]
	if !ok {
		return Resource{}, false, nil
	}
	if strings.TrimSpace(provider.UserID) == "" {
		return Resource{}, false, fmt.Errorf("%w: model provider %q has no owner user_id", ErrInvalidPermission, provider.ID)
	}
	return modelInstanceResource(instance, provider), true, nil
}

func buildTenantModelFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	model, ok := facts.tenantModelsByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	instance, ok := facts.modelInstancesByID[model.InstanceID]
	if !ok || instance.ProviderID != model.ProviderID {
		return Resource{}, false, nil
	}
	provider, ok := facts.modelProvidersByID[model.ProviderID]
	if !ok {
		return Resource{}, false, nil
	}
	if strings.TrimSpace(provider.UserID) == "" {
		return Resource{}, false, fmt.Errorf("%w: model provider %q has no owner user_id", ErrInvalidPermission, provider.ID)
	}
	return tenantModelResource(model, provider), true, nil
}

func buildMCPServerFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	server, ok := facts.mcpServersByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	if strings.TrimSpace(server.UserID) == "" {
		return Resource{}, false, fmt.Errorf("%w: MCP server %q has no owner user_id", ErrInvalidPermission, ref.ID)
	}
	return mcpServerResource(ref.ID, server.TenantID, server.UserID), true, nil
}

func buildSkillSpaceFact(ref ResourceRef, facts *resourceFacts) (Resource, bool, error) {
	space, ok := facts.skillSpacesByID[ref.ID]
	if !ok {
		return Resource{}, false, nil
	}
	folder, ok := facts.skillSpaceFoldersByID[space.FolderID]
	if !ok || folder.TenantID != space.TenantID || folder.Type != "folder" {
		return Resource{}, false, nil
	}
	if strings.TrimSpace(space.UserID) == "" {
		return Resource{}, false, fmt.Errorf("%w: skill space %q has no owner user_id", ErrInvalidPermission, space.ID)
	}
	return skillSpaceResource(space.ID, space.TenantID, space.UserID), true, nil
}
