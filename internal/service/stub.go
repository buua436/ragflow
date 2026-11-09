//
//  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

//go:build !ee

package service

import (
	"context"

	dslpkg "ragflow/internal/agent/dsl"
	"ragflow/internal/common"
	"ragflow/internal/entity"
	"ragflow/internal/permission"

	"gorm.io/gorm"
)

func markChannelAgentRun(ctx context.Context) context.Context { return ctx }

func (s *AgentService) prepareAgentSessionRun(ctx context.Context, runID, _, _, _ string, userInput any, draft, persisted map[string]any) (map[string]any, bool, string, error) {
	if userInput != nil && s.runTracker != nil {
		if interruptID, ok, err := s.runTracker.GetInterruptID(ctx, runID); err == nil && ok {
			if len(persisted) > 0 {
				return dslpkg.NormalizeForRun(persisted), false, interruptID, nil
			}
			return draft, false, interruptID, nil
		}
	}
	if len(persisted) > 0 {
		draft = dslpkg.NormalizeForRun(persisted)
	}
	return draft, false, "", nil
}

// InitHTTPClientEE is a no-op in the community edition.
func (h *AdminClient) InitHTTPClientEE() error { return nil }

// EnrichMessage leaves the heartbeat unchanged in the community edition.
func (h *AdminClient) EnrichMessage(message *common.BaseMessage) (*common.BaseMessage, error) {
	return message, nil
}

// UpdateClient ignores the heartbeat acknowledgement in the community edition.
func (h *AdminClient) UpdateClient(clientInfo any) error { return nil }

// prepareAgentCreation grants no additional permissions before an agent is
// created.
func prepareAgentCreation(ctx context.Context) (string, error) {
	return permission.UserIDFromContext(ctx), nil
}

// tenantMemberPermissionEE leaves membership checks to the community policy.
func tenantMemberPermissionEE(ctx context.Context, db *gorm.DB, tenantID string, required int32) (*entity.UserTenant, int32, bool, error) {
	return nil, 0, false, nil
}

// recordTenantPermissionChangeEE records nothing: the community edition has no
// permission audit trail.
func recordTenantPermissionChangeEE(ctx context.Context, tx *gorm.DB, tenantID, eventType, targetType, targetID, resourceType, resourceID, actionType string, beforePermission, afterPermission int32, beforeData, afterData interface{}) error {
	return nil
}

// resolveTenantInviteRoleEE leaves invite roles to the community default.
func resolveTenantInviteRoleEE(*gorm.DB, string) (tenantInviteRole, bool, error) {
	return tenantInviteRole{}, false, nil
}

// checkTenantInviteEnabledEE leaves the invite switch to the community
// default.
func (*TenantService) checkTenantInviteEnabledEE(context.Context, string) (common.ErrorCode, bool, error) {
	return common.CodeSuccess, false, nil
}

// resolveCurrentUserTenantEE leaves tenant resolution to the community path.
func resolveCurrentUserTenantEE(context.Context, string) (*entity.UserTenant, bool, error) {
	return nil, false, nil
}

// resolveUserAuthTenant selects the user's personal tenant for community auth.
func resolveUserAuthTenant(_ context.Context, user *entity.User, _ string) (string, error) {
	if user == nil || user.ID == "" {
		return "", permission.ErrUnauthenticated
	}
	return user.ID, nil
}

// LoginChannel is one authentication channel advertised to the login page.
type LoginChannel struct {
	Channel     string `json:"channel"`
	DisplayName string `json:"display_name"`
	Icon        string `json:"icon"`
}

// GetLoginChannels returns no channel: the community edition only offers
// password login.
func (s *UserService) GetLoginChannels() ([]*LoginChannel, common.ErrorCode, error) {
	return make([]*LoginChannel, 0), common.CodeSuccess, nil
}
