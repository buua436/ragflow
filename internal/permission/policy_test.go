//go:build !ee

package permission

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type permissionTestSource struct {
	memberships map[string]*Membership
	resources   map[ResourceRef]Resource
	candidates  []ResourceRef
	queryTenant string
}

func (s *permissionTestSource) GetMembership(_ context.Context, userID, tenantID string) (*Membership, error) {
	return s.memberships[userID+"\x00"+tenantID], nil
}

func (s *permissionTestSource) GetResources(_ context.Context, refs []ResourceRef) ([]Resource, error) {
	resources := make([]Resource, 0, len(refs))
	for _, ref := range refs {
		if resource, ok := s.resources[ref]; ok {
			resources = append(resources, resource)
		}
	}
	return resources, nil
}

func (s *permissionTestSource) ListResourceRefs(ctx context.Context, kind ResourceKind, parent ResourceRef) ([]ResourceRef, error) {
	s.queryTenant = TenantIDFromContext(ctx)
	refs := make([]ResourceRef, 0, len(s.candidates))
	for _, ref := range s.candidates {
		if ref.Kind == kind {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

func TestCommunityPolicyResolvesResourceTenant(t *testing.T) {
	resourceRef := ResourceRef{Kind: "dataset", ID: "dataset-1"}
	source := &permissionTestSource{
		memberships: map[string]*Membership{
			"user-1\x00tenant-resource": {
				UserID: "user-1", TenantID: "tenant-resource", Role: RoleNormal, Active: true,
			},
		},
		resources: map[ResourceRef]Resource{
			resourceRef: {
				Ref: resourceRef, TenantID: "tenant-resource", OwnerUserID: "tenant-owner",
				Visibility: VisibilityTenant, OwnerOperations: []Operation{OperationRead}, Active: true,
			},
		},
	}

	access, err := NewChecker(source).ResolveAccess(WithIdentity(context.Background(), "user-1", ""), resourceRef)
	if err != nil {
		t.Fatalf("ResolveAccess() error = %v", err)
	}
	if access.TenantID != "tenant-resource" {
		t.Fatalf("ResolveAccess() tenant = %q, want resource tenant", access.TenantID)
	}
	if access.Source != AccessSourceTenant || !access.Allows(OperationRead) {
		t.Fatalf("ResolveAccess() = %#v, want tenant read access", access)
	}
	if access.PermissionMask != ResourcePermissionRead {
		t.Fatalf("ResolveAccess() permission mask = %d, want read mask %d", access.PermissionMask, ResourcePermissionRead)
	}
}

func TestCommunityPolicyRejectsResourceOutsideActiveTenant(t *testing.T) {
	resourceRef := ResourceRef{Kind: "dataset", ID: "dataset-1"}
	source := &permissionTestSource{
		memberships: map[string]*Membership{
			"user-1\x00tenant-resource": {
				UserID: "user-1", TenantID: "tenant-resource", Role: RoleNormal, Active: true,
			},
		},
		resources: map[ResourceRef]Resource{
			resourceRef: {
				Ref: resourceRef, TenantID: "tenant-resource", OwnerUserID: "tenant-owner",
				Visibility: VisibilityTenant, OwnerOperations: []Operation{OperationRead}, Active: true,
			},
		},
	}

	checker := NewChecker(source)
	if _, err := checker.ResolveAccess(WithIdentity(context.Background(), "user-1", "another-tenant"), resourceRef); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("ResolveAccess() error = %v, want resource not found outside the active tenant", err)
	}
	access, err := checker.ResolveAccess(WithIdentity(context.Background(), "user-1", "tenant-resource"), resourceRef)
	if err != nil || access.TenantID != "tenant-resource" {
		t.Fatalf("ResolveAccess() = %+v, %v; want access in the active resource tenant", access, err)
	}

	_, err = NewChecker(source).ResolveAccess(WithIdentity(context.Background(), "unrelated-user", "tenant-resource"), resourceRef)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ResolveAccess() error = %v, want %v for a non-member", err, ErrPermissionDenied)
	}
}

func TestCheckerQueryScopeRejectsTenantMismatch(t *testing.T) {
	checker := NewChecker(&permissionTestSource{})
	_, err := checker.QueryScope(WithIdentity(context.Background(), "user-1", "active-tenant"), ScopeQuery{
		Kind:      ResourceKindDataset,
		Operation: OperationRead,
		TenantID:  "other-tenant",
	})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("QueryScope() error = %v, want identity mismatch", err)
	}
}

func TestCheckerQueryScopeKeepsTenantBoundaryOutOfContext(t *testing.T) {
	targetRef := ResourceRef{Kind: ResourceKindDataset, ID: "target-dataset"}
	otherRef := ResourceRef{Kind: ResourceKindDataset, ID: "other-dataset"}
	resource := func(ref ResourceRef, tenantID string) Resource {
		return Resource{
			Ref: ref, TenantID: tenantID, OwnerUserID: "user-1", Visibility: VisibilityPrivate,
			OwnerOperations: []Operation{OperationRead}, Active: true,
		}
	}
	source := &permissionTestSource{
		resources: map[ResourceRef]Resource{
			targetRef: resource(targetRef, "target-tenant"),
			otherRef:  resource(otherRef, "other-tenant"),
		},
		candidates: []ResourceRef{targetRef, otherRef},
	}
	scope, err := NewChecker(source).QueryScope(WithIdentity(context.Background(), "user-1", ""), ScopeQuery{
		TenantID: "target-tenant", Kind: ResourceKindDataset, Operation: OperationRead,
	})
	if err != nil {
		t.Fatalf("QueryScope() error = %v", err)
	}
	if source.queryTenant != "" {
		t.Fatalf("query tenant changed context tenant to %q", source.queryTenant)
	}

	db, err := gorm.Open(sqlite.Open("file:"+url.QueryEscape(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec("CREATE TABLE knowledgebase (id TEXT PRIMARY KEY)").Error; err != nil {
		t.Fatalf("create knowledgebase: %v", err)
	}
	if err := db.Exec("INSERT INTO knowledgebase (id) VALUES (?), (?)", targetRef.ID, otherRef.ID).Error; err != nil {
		t.Fatalf("insert datasets: %v", err)
	}
	var ids []string
	if err := scope.Apply(db.Table("knowledgebase")).Order("id").Pluck("id", &ids).Error; err != nil {
		t.Fatalf("apply QueryScope(): %v", err)
	}
	if len(ids) != 1 || ids[0] != targetRef.ID {
		t.Fatalf("QueryScope() IDs = %v, want only %q", ids, targetRef.ID)
	}
}

func TestCommunityPolicySharedResourceNeedsNoActiveTenant(t *testing.T) {
	resourceRef := ResourceRef{Kind: "agent", ID: "agent-1"}
	source := &permissionTestSource{
		memberships: map[string]*Membership{
			"user-1\x00shared-tenant": {
				UserID: "user-1", TenantID: "shared-tenant", Role: RoleNormal, Active: true,
			},
		},
		resources: map[ResourceRef]Resource{
			resourceRef: {
				Ref: resourceRef, TenantID: "owner-tenant", OwnerUserID: "owner-user",
				Visibility: VisibilityShared, SharedWithTenantIDs: []string{"shared-tenant"},
				OwnerOperations: []Operation{OperationRun}, Active: true,
			},
		},
	}

	access, err := NewChecker(source).ResolveAccess(WithIdentity(context.Background(), "user-1", ""), resourceRef)
	if err != nil {
		t.Fatalf("ResolveAccess() error = %v", err)
	}
	if access.Source != AccessSourceShared || !access.Allows(OperationRun) {
		t.Fatalf("ResolveAccess() = %#v, want shared run access", access)
	}
	if err := NewChecker(source).CheckResource(WithIdentity(context.Background(), "user-1", ""), resourceRef, OperationShare); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CheckResource(share) error = %v, want %v for a shared resource", err, ErrPermissionDenied)
	}
}

func TestCommunityPolicyChecksDependencyForBothUserAndEntryOwner(t *testing.T) {
	entryRef := ResourceRef{Kind: "agent", ID: "agent-1"}
	dependencyRef := ResourceRef{Kind: "dataset", ID: "dataset-1"}
	source := &permissionTestSource{
		resources: map[ResourceRef]Resource{
			entryRef: {
				Ref: entryRef, TenantID: "entry-tenant", OwnerUserID: "entry-owner",
				Visibility: VisibilityShared, SharedWithUserIDs: []string{"caller"},
				OwnerOperations: []Operation{OperationRun}, Active: true,
			},
			dependencyRef: {
				Ref: dependencyRef, TenantID: "dataset-tenant", OwnerUserID: "dataset-owner",
				Visibility: VisibilityShared, SharedWithUserIDs: []string{"caller"},
				OwnerOperations: []Operation{OperationRead}, Active: true,
			},
		},
	}

	err := NewChecker(source).CheckDependency(WithIdentity(context.Background(), "caller", ""), entryRef, dependencyRef, OperationRun, OperationRead)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CheckDependency() error = %v, want %v", err, ErrPermissionDenied)
	}

	dependency := source.resources[dependencyRef]
	dependency.SharedWithUserIDs = []string{"caller", "entry-owner"}
	source.resources[dependencyRef] = dependency
	err = NewChecker(source).CheckDependency(WithIdentity(context.Background(), "caller", ""), entryRef, dependencyRef, OperationRun, OperationRead)
	if err != nil {
		t.Fatalf("CheckDependency() error = %v, want nil when both caller and entry owner can read dependency", err)
	}
}

func TestCommunityPolicyFeatureDoesNotRequireTenantContext(t *testing.T) {
	checker := NewChecker(&permissionTestSource{})
	if err := checker.CheckFeature(WithIdentity(context.Background(), "user-1", ""), "dataset", ActionRead); err != nil {
		t.Fatalf("CheckFeature() error = %v", err)
	}
}

func TestCommunityPolicyScopeUsesParentResourceTenant(t *testing.T) {
	parentRef := ResourceRef{Kind: "dataset", ID: "dataset-1"}
	childRef := ResourceRef{Kind: "document", ID: "document-1"}
	source := &permissionTestSource{
		memberships: map[string]*Membership{
			"user-1\x00dataset-tenant": {
				UserID: "user-1", TenantID: "dataset-tenant", Role: RoleNormal, Active: true,
			},
		},
		resources: map[ResourceRef]Resource{
			parentRef: {
				Ref: parentRef, TenantID: "dataset-tenant", OwnerUserID: "dataset-owner",
				Visibility: VisibilityTenant, OwnerOperations: []Operation{OperationRead}, Active: true,
			},
			childRef: {
				Ref: childRef, TenantID: "dataset-tenant", OwnerUserID: "dataset-owner",
				Visibility: VisibilityTenant, OwnerOperations: []Operation{OperationRead}, Active: true,
			},
		},
		candidates: []ResourceRef{childRef},
	}

	scope, err := NewChecker(source).scope(WithIdentity(context.Background(), "user-1", ""), ScopeQuery{
		Kind: "document", Parent: parentRef, Operation: OperationRead,
	})
	if err != nil {
		t.Fatalf("Scope() error = %v", err)
	}
	if scope.TenantID != "dataset-tenant" {
		t.Fatalf("Scope() tenant = %q, want parent tenant", scope.TenantID)
	}
	if scope.Mode != scopeIDs || len(scope.ResourceIDs) != 1 || scope.ResourceIDs[0] != childRef.ID {
		t.Fatalf("Scope() = %#v, want the accessible child ID", scope)
	}
}

func TestCommunityPolicyRequiresUserIdentity(t *testing.T) {
	resourceRef := ResourceRef{Kind: "dataset", ID: "dataset-1"}
	_, err := NewChecker(&permissionTestSource{}).ResolveAccess(context.Background(), resourceRef)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ResolveAccess() error = %v, want %v", err, ErrUnauthenticated)
	}
}
