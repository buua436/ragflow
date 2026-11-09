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

// Package permission provides shared permission contracts and edition policies.
package permission

import (
	"context"
	"errors"
	"strings"
)

type userIDContextKey struct{}
type tenantIDContextKey struct{}

var (
	ErrUnauthenticated      = errors.New("permission: user is required")
	ErrIdentityMismatch     = errors.New("permission: identity does not match request context")
	ErrResourceNotFound     = errors.New("permission: resource not found")
	ErrMembershipNotFound   = errors.New("permission: active tenant membership not found")
	ErrTenantContextMissing = errors.New("permission: tenant context is required")
	ErrPermissionDenied     = errors.New("permission: access denied")
	ErrInvalidPermission    = errors.New("permission: invalid permission request")
	ErrSourceUnavailable    = errors.New("permission: source is not configured")
)

// WithIdentity attaches the authenticated user and active Tenant to a request
// context as separate values.
func WithIdentity(ctx context.Context, userID, tenantID string) context.Context {
	ctx = context.WithValue(ctx, userIDContextKey{}, userID)
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// WithTenantID explicitly selects the tenant for an operation while preserving
// the authenticated user. It does not validate membership or infer a default.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// UserIDFromContext returns the authenticated user ID attached to ctx.
func UserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	userID, _ := ctx.Value(userIDContextKey{}).(string)
	return userID
}

// TenantIDFromContext returns the selected tenant attached to ctx.
func TenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	tenantID, _ := ctx.Value(tenantIDContextKey{}).(string)
	return tenantID
}

// ResourceKind identifies a resource family without coupling this package to business entities.
type ResourceKind string

const (
	ResourceKindDataset       ResourceKind = "dataset"
	ResourceKindDocument      ResourceKind = "document"
	ResourceKindCanvas        ResourceKind = "canvas"
	ResourceKindAgentSession  ResourceKind = "agent_session"
	ResourceKindMemory        ResourceKind = "memory"
	ResourceKindFile          ResourceKind = "file"
	ResourceKindFolder        ResourceKind = "folder"
	ResourceKindSearchApp     ResourceKind = "search_app"
	ResourceKindChat          ResourceKind = "chat"
	ResourceKindChatSession   ResourceKind = "chat_session"
	ResourceKindChatChannel   ResourceKind = "chat_channel"
	ResourceKindConnector     ResourceKind = "connector"
	ResourceKindSyncTask      ResourceKind = "sync_task"
	ResourceKindModelProvider ResourceKind = "model_provider"
	ResourceKindModelInstance ResourceKind = "model_instance"
	ResourceKindModel         ResourceKind = "model"
	ResourceKindMCPServer     ResourceKind = "mcp_server"
	ResourceKindSkillSpace    ResourceKind = "skill_space"
)

// ResourceRef identifies a persisted resource.
type ResourceRef struct {
	Kind ResourceKind
	ID   string
}

// Feature identifies a feature whose availability is edition-dependent.
type Feature string

// Action identifies a feature-level action.
type Action string

const (
	ActionEnable Action = "enable"
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionShare  Action = "share"
)

// Operation identifies an operation on a concrete resource.
type Operation string

// Resource permission masks describe direct resource grants independently of
// feature-role limits. The permission UI uses the same bit layout as the
// resource grant table.
const (
	ResourcePermissionRead int32 = 1 << iota
	ResourcePermissionWrite
	ResourcePermissionManage
	ResourcePermissionOwner
)

const (
	OperationRead          Operation = "read"
	OperationCreate        Operation = "create"
	OperationUpdate        Operation = "update"
	OperationDelete        Operation = "delete"
	OperationDeleteContent Operation = "delete_content"
	OperationShare         Operation = "share"
	OperationRun           Operation = "run"
	OperationUse           Operation = "use"
)

// TenantRequirement describes the tenant role required by a check.
type TenantRequirement string

const (
	TenantMember       TenantRequirement = "member"
	TenantNormalMember TenantRequirement = "normal_member"
	TenantAdmin        TenantRequirement = "admin"
	TenantOwner        TenantRequirement = "owner"
)

// TenantRole is the normalized role in a user-tenant membership.
type TenantRole string

const (
	RoleOwner  TenantRole = "owner"
	RoleAdmin  TenantRole = "admin"
	RoleNormal TenantRole = "normal"
)

// Membership is the normalized active membership fact returned by Source.
type Membership struct {
	ID       string
	UserID   string
	TenantID string
	Role     TenantRole
	Active   bool
}

// Visibility describes how a resource is exposed in the community edition.
type Visibility string

const (
	VisibilityPrivate Visibility = "private"
	VisibilityTenant  Visibility = "tenant"
	VisibilityShared  Visibility = "shared"
)

// Resource contains normalized authorization and attribution facts loaded from
// the persisted business resource. TenantID, CreatedBy, and OwnerUserID are
// independent facts: the resource tenant, creator, and permission owner need
// not be the same identity.
type Resource struct {
	Ref                   ResourceRef
	TenantID              string
	CreatedBy             string
	OwnerUserID           string
	ParentRefs            []ResourceRef
	ParentAccessOperation Operation
	Visibility            Visibility
	TenantRequirement     TenantRequirement
	OwnerOperations       []Operation
	// TenantOperations overrides OwnerOperations for tenant members when set.
	TenantOperations []Operation
	// CreatorOperations grants extra operations to CreatedBy after tenant access is verified.
	CreatorOperations   []Operation
	SharedWithUserIDs   []string
	SharedWithTenantIDs []string
	Active              bool
}

// AccessSource identifies the rule that granted access.
type AccessSource string

const (
	AccessSourceOwner   AccessSource = "owner"
	AccessSourceTenant  AccessSource = "tenant"
	AccessSourceCreator AccessSource = "creator"
	AccessSourceShared  AccessSource = "shared"
)

// Access describes the operations a subject can perform on a resource.
type Access struct {
	Resource       ResourceRef
	TenantID       string
	Source         AccessSource
	PermissionMask int32
	Operations     []Operation
}

func (a Access) Allows(operation Operation) bool {
	for _, allowed := range a.Operations {
		if allowed == operation {
			return true
		}
	}
	return false
}

type scopeMode uint8

const (
	scopeNone scopeMode = iota
	scopeIDs
)

// resourceScope is the internal ID-based fallback used to build QueryScope.
type resourceScope struct {
	Mode        scopeMode
	TenantID    string
	Kind        ResourceKind
	Parent      ResourceRef
	Operation   Operation
	ResourceIDs []string
}

// ScopeQuery describes the candidate resource set and optional execution entry.
type ScopeQuery struct {
	// TenantID optionally narrows the query to one tenant. It does not set or
	// replace the authenticated identity carried by the context.
	TenantID string
	// TenantIDs and OwnerUserIDs are caller-supplied list filters. They can only
	// narrow the authorization scope returned by QueryScope.
	TenantIDs    []string
	OwnerUserIDs []string
	Kind         ResourceKind
	Parent       ResourceRef
	Operation    Operation
	Entry        *ResourceRef
	EntryOp      Operation
}

// Source loads normalized permission facts. GetResources must return the
// requested resources with their tenant, creator, permission owner, active
// state, visibility, operation sets, and share recipients. ListResourceRefs
// returns all candidate IDs within the query boundary, including candidates
// that policy will reject; Checker authorizes them before returning a scope.
type Source interface {
	GetMembership(ctx context.Context, userID, tenantID string) (*Membership, error)
	GetResources(ctx context.Context, refs []ResourceRef) ([]Resource, error)
	ListResourceRefs(ctx context.Context, kind ResourceKind, parent ResourceRef) ([]ResourceRef, error)
}

type policy interface {
	CheckFeature(context.Context, Feature, Action) error
	CheckTenant(context.Context, string, TenantRequirement) error
	CheckResource(context.Context, ResourceRef, Operation) error
	CheckDependency(context.Context, ResourceRef, ResourceRef, Operation, Operation) error
	ResolveAccess(context.Context, ResourceRef) (Access, error)
	scope(context.Context, ScopeQuery) (resourceScope, error)
	FilterResources(context.Context, []ResourceRef, Operation) ([]ResourceRef, error)
}

type queryScopePolicy interface {
	QueryScope(context.Context, ScopeQuery) (QueryScope, bool, error)
}

type accessResolverPolicy interface {
	ResolveAccesses(context.Context, []ResourceRef) (map[ResourceRef]Access, error)
}

type resourceOwnerGranter interface {
	GrantResourceOwner(context.Context, ResourceRef) error
}

// Checker exposes edition-independent permission methods.
type Checker struct {
	policy policy
}

// NewChecker creates a checker backed by normalized membership and resource facts.
func NewChecker(source Source) *Checker {
	if source == nil {
		return &Checker{}
	}
	return &Checker{policy: newPolicy(source)}
}

// GrantResourceOwner assigns the creator's owner grant for policies that use
// explicit resource permissions. Policies without grant rows keep their own
// ownership model.
func (c *Checker) GrantResourceOwner(ctx context.Context, resource ResourceRef) error {
	if c == nil || c.policy == nil {
		return ErrSourceUnavailable
	}
	granter, ok := c.policy.(resourceOwnerGranter)
	if !ok {
		return nil
	}
	return granter.GrantResourceOwner(ctx, resource)
}

// CheckFeature checks feature access for the authenticated identity in ctx.
func (c *Checker) CheckFeature(ctx context.Context, feature Feature, action Action) error {
	if c == nil || c.policy == nil {
		return ErrSourceUnavailable
	}
	return c.policy.CheckFeature(ctx, feature, action)
}

// CheckTenant checks the authenticated user's membership and role in tenantID.
func (c *Checker) CheckTenant(ctx context.Context, tenantID string, requirement TenantRequirement) error {
	if c == nil || c.policy == nil {
		return ErrSourceUnavailable
	}
	return c.policy.CheckTenant(ctx, tenantID, requirement)
}

// CheckResource checks a direct operation on a resource for the identity in ctx.
func (c *Checker) CheckResource(ctx context.Context, resource ResourceRef, operation Operation) error {
	if c == nil || c.policy == nil {
		return ErrSourceUnavailable
	}
	return c.policy.CheckResource(ctx, resource, operation)
}

// CheckDependency checks entry access and the caller's and entry owner's access to a dependency.
func (c *Checker) CheckDependency(ctx context.Context, entry, dependency ResourceRef, entryOperation, dependencyOperation Operation) error {
	if c == nil || c.policy == nil {
		return ErrSourceUnavailable
	}
	return c.policy.CheckDependency(ctx, entry, dependency, entryOperation, dependencyOperation)
}

// ResolveAccess resolves the effective access for the authenticated identity in ctx.
func (c *Checker) ResolveAccess(ctx context.Context, resource ResourceRef) (Access, error) {
	if c == nil || c.policy == nil {
		return Access{}, ErrSourceUnavailable
	}
	return c.policy.ResolveAccess(ctx, resource)
}

func (c *Checker) scope(ctx context.Context, query ScopeQuery) (resourceScope, error) {
	if c == nil || c.policy == nil {
		return resourceScope{}, ErrSourceUnavailable
	}
	return c.policy.scope(ctx, query)
}

// QueryScope returns a database-applied authorization predicate for a resource
// query. Database-backed policies must compile authorization into SQL. Other
// policy sources may fall back to their authorized resource IDs.
func (c *Checker) QueryScope(ctx context.Context, query ScopeQuery) (QueryScope, error) {
	if c == nil || c.policy == nil {
		return QueryScope{}, ErrSourceUnavailable
	}
	contextTenantID := strings.TrimSpace(TenantIDFromContext(ctx))
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		tenantID = contextTenantID
	}
	if contextTenantID != "" && tenantID != contextTenantID {
		return QueryScope{}, ErrIdentityMismatch
	}
	query.TenantID = tenantID
	filters, err := queryFilterScope(query)
	if err != nil {
		return QueryScope{}, err
	}
	if queryPolicy, ok := c.policy.(queryScopePolicy); ok {
		queryScope, supported, err := queryPolicy.QueryScope(ctx, query)
		if err != nil {
			return QueryScope{}, err
		}
		if supported {
			return queryScope.and(filters), nil
		}
	}
	if nativePolicy, ok := c.policy.(interface{ nativeQueryScopeRequired() bool }); ok && nativePolicy.nativeQueryScopeRequired() {
		return QueryScope{}, ErrInvalidPermission
	}

	scope, err := c.policy.scope(ctx, query)
	if err != nil {
		return QueryScope{}, err
	}
	return queryScopeForIDs(query.Kind, scope.ResourceIDs).and(filters), nil
}

// FilterResources returns only candidate resources that allow operation.
func (c *Checker) FilterResources(ctx context.Context, resources []ResourceRef, operation Operation) ([]ResourceRef, error) {
	if c == nil || c.policy == nil {
		return nil, ErrSourceUnavailable
	}
	return c.policy.FilterResources(ctx, resources, operation)
}

// ResolveAccesses resolves effective access for a batch of resources.
// Database-backed policies can load resource facts once for the whole batch.
func (c *Checker) ResolveAccesses(ctx context.Context, resources []ResourceRef) (map[ResourceRef]Access, error) {
	if c == nil || c.policy == nil {
		return nil, ErrSourceUnavailable
	}
	if batchPolicy, ok := c.policy.(accessResolverPolicy); ok {
		return batchPolicy.ResolveAccesses(ctx, resources)
	}

	accesses := make(map[ResourceRef]Access, len(resources))
	for _, resource := range uniqueRefs(resources) {
		access, err := c.policy.ResolveAccess(ctx, resource)
		if err != nil {
			if errorsIsPermissionDenial(err) || errors.Is(err, ErrResourceNotFound) {
				continue
			}
			return nil, err
		}
		accesses[resource] = access
	}
	return accesses, nil
}

// FilterAccesses resolves permissions for a batch of resources and returns the
// effective access for each resource that allows operation.
func (c *Checker) FilterAccesses(ctx context.Context, resources []ResourceRef, operation Operation) (map[ResourceRef]Access, error) {
	if c == nil || c.policy == nil {
		return nil, ErrSourceUnavailable
	}
	if !validOperation(operation) {
		return nil, ErrInvalidPermission
	}
	accesses, err := c.ResolveAccesses(ctx, resources)
	if err != nil {
		return nil, err
	}
	for ref, access := range accesses {
		if !access.Allows(operation) {
			delete(accesses, ref)
		}
	}
	return accesses, nil
}
