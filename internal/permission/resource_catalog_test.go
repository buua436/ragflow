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
	"strings"
	"testing"

	"ragflow/internal/entity"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestResourceDirectoryCoversEveryResourceKind(t *testing.T) {
	kinds := []ResourceKind{
		ResourceKindDataset, ResourceKindDocument, ResourceKindCanvas, ResourceKindAgentSession,
		ResourceKindMemory, ResourceKindFile, ResourceKindFolder, ResourceKindSearchApp,
		ResourceKindChat, ResourceKindChatSession, ResourceKindChatChannel, ResourceKindConnector,
		ResourceKindSyncTask, ResourceKindModelProvider, ResourceKindModelInstance, ResourceKindModel,
		ResourceKindMCPServer, ResourceKindSkillSpace,
	}
	if len(resourceDirectory) != len(kinds) {
		t.Fatalf("resource directory has %d entries, want %d", len(resourceDirectory), len(kinds))
	}
	for _, kind := range kinds {
		definition, ok := resourceDefinitionFor(kind)
		if !ok {
			t.Errorf("resource kind %q has no directory entry", kind)
			continue
		}
		if definition.table == "" || definition.list == nil || definition.build == nil {
			t.Errorf("resource kind %q is missing table, candidate lister, or fact builder", kind)
		}
		if definition.tenantColumn == "" && definition.tenantRelation == nil {
			t.Errorf("resource kind %q is missing tenant mapping", kind)
		}
		if definition.ownerColumn == "" && definition.ownerRelation == nil {
			t.Errorf("resource kind %q is missing owner mapping", kind)
		}
		for _, parent := range definition.parents {
			if parent.kind == "" || parent.column == "" {
				t.Errorf("resource kind %q has incomplete parent metadata: %+v", kind, parent)
			}
		}
	}
}

func TestResourceDirectoryValidatesParentsFromMetadata(t *testing.T) {
	for _, test := range []struct {
		kind   ResourceKind
		parent ResourceRef
		valid  bool
	}{
		{kind: ResourceKindDataset, valid: true},
		{kind: ResourceKindDataset, parent: ResourceRef{Kind: ResourceKindCanvas, ID: "parent"}},
		{kind: ResourceKindDocument},
		{kind: ResourceKindDocument, parent: ResourceRef{Kind: ResourceKindCanvas, ID: "parent"}},
		{kind: ResourceKindDocument, parent: ResourceRef{Kind: ResourceKindDataset, ID: "dataset"}, valid: true},
		{kind: ResourceKindModel, parent: ResourceRef{Kind: ResourceKindModelProvider, ID: "provider"}, valid: true},
		{kind: ResourceKindModel, parent: ResourceRef{Kind: ResourceKindModelInstance, ID: "instance"}, valid: true},
	} {
		definition, ok := resourceDefinitionFor(test.kind)
		if !ok {
			t.Fatalf("resource kind %q is missing", test.kind)
		}
		err := validateResourceParent(test.kind, test.parent, definition)
		if (err == nil) != test.valid {
			t.Errorf("validateResourceParent(%q, %+v) error = %v, want valid=%t", test.kind, test.parent, err, test.valid)
		}
	}
}

func TestResourceParentColumnsComeFromDirectory(t *testing.T) {
	for kind, definition := range resourceDirectory {
		for _, parent := range definition.parents {
			column, ok := resourceParentColumn(definition, parent.kind)
			if !ok || column != parent.column {
				t.Errorf("resource parent column for %q -> %q = %q, %t; want %q", kind, parent.kind, column, ok, parent.column)
			}
		}
	}
}

func TestQueryFilterScopeUsesDerivedResourceIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DryRun: true})
	if err != nil {
		t.Fatalf("open sqlite dry-run database: %v", err)
	}
	scope, err := queryFilterScope(ScopeQuery{
		Kind: ResourceKindDocument, TenantIDs: []string{"tenant-a"}, OwnerUserIDs: []string{"owner-a"},
	})
	if err != nil {
		t.Fatalf("build document filter scope: %v", err)
	}
	statement := scope.Apply(db.Model(&entity.Document{})).Find(&[]entity.Document{}).Statement
	sql := strings.ReplaceAll(strings.ToLower(statement.SQL.String()), "`", "")
	for _, fragment := range []string{"document.kb_id in", "knowledgebase", "tenant_id", "document.user_id"} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("document scope SQL %q does not include %q", statement.SQL.String(), fragment)
		}
	}
	if len(statement.Vars) != 2 || statement.Vars[0] != "tenant-a" || statement.Vars[1] != "owner-a" {
		t.Errorf("document scope vars = %#v, want tenant and owner values", statement.Vars)
	}
}
