//go:build !ee

package permission

import (
	"errors"
	"strings"
	"testing"

	"ragflow/internal/entity"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestCommunityQueryScopeCompilesEveryResourceWithoutCandidateIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&entity.UserTenant{}, &entity.Knowledgebase{}, &entity.Document{}, &entity.UserCanvas{}, &entity.API4Conversation{},
		&entity.Memory{}, &entity.File{}, &entity.File2Document{}, &entity.Search{}, &entity.Chat{}, &entity.ChatSession{},
		&entity.ChatChannel{}, &entity.Connector{}, &entity.Connector2Kb{}, &entity.SyncLogs{},
		&entity.TenantModelProvider{}, &entity.TenantModelInstance{}, &entity.TenantModel{}, &entity.MCPServer{}, &entity.SkillSpace{},
	); err != nil {
		t.Fatalf("migrate query scope tables: %v", err)
	}
	valid := string(entity.StatusValid)
	if err := db.Create(&entity.Knowledgebase{
		ID: "dataset-1", UserID: "user-1", TenantID: "tenant-1", Name: "Dataset", EmbdID: "embedding",
		Permission: string(entity.TenantPermissionMe), Status: &valid,
	}).Error; err != nil {
		t.Fatalf("create document parent dataset: %v", err)
	}
	chat := entity.Chat{
		ID: "chat-1", UserID: "user-1", TenantID: "tenant-1", LLMID: "test-model",
		LLMSetting: entity.JSONMap{}, PromptConfig: entity.JSONMap{}, KBIDs: entity.JSONSlice{}, DoRefer: "1", Status: &valid,
	}
	if err := db.Create(&chat).Error; err != nil {
		t.Fatalf("create chat entry: %v", err)
	}
	connector := entity.Connector{
		ID: "connector-1", UserID: "user-1", TenantID: "tenant-1", Name: "Connector",
		Source: "test", InputType: "test", Config: entity.JSONMap{}, Status: "schedule",
	}
	if err := db.Create(&connector).Error; err != nil {
		t.Fatalf("create connector entry: %v", err)
	}
	checker := newCommunityDatabaseChecker(db)
	queryPolicy := checker.policy.(queryScopePolicy)
	ctx := WithIdentity(t.Context(), "user-1", "tenant-1")
	kinds := []ResourceKind{
		ResourceKindDataset, ResourceKindDocument, ResourceKindCanvas, ResourceKindAgentSession,
		ResourceKindMemory, ResourceKindFile, ResourceKindFolder, ResourceKindSearchApp,
		ResourceKindChat, ResourceKindChatSession, ResourceKindChatChannel, ResourceKindConnector,
		ResourceKindSyncTask, ResourceKindModelProvider, ResourceKindModelInstance, ResourceKindModel,
		ResourceKindMCPServer, ResourceKindSkillSpace,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			query := ScopeQuery{Kind: kind, Operation: OperationRead}
			switch kind {
			case ResourceKindDocument:
				query.Parent = ResourceRef{Kind: ResourceKindDataset, ID: "dataset-1"}
			case ResourceKindFile, ResourceKindFolder:
				query.Parent = ResourceRef{Kind: ResourceKindFolder, ID: "folder-1"}
			case ResourceKindChatSession:
				chatRef := ResourceRef{Kind: ResourceKindChat, ID: chat.ID}
				query.Parent, query.Entry, query.EntryOp = chatRef, &chatRef, OperationRead
			case ResourceKindSyncTask:
				connectorRef := ResourceRef{Kind: ResourceKindConnector, ID: connector.ID}
				query.Parent, query.Entry, query.EntryOp = connectorRef, &connectorRef, OperationRead
			case ResourceKindChat:
				query.Operation = OperationDelete
			}
			scope, supported, err := queryPolicy.QueryScope(ctx, query)
			if err != nil {
				t.Fatalf("QueryScope(%s): %v", kind, err)
			}
			if !supported {
				t.Fatalf("QueryScope(%s) fell back to candidate ID evaluation", kind)
			}
			definition, ok := resourceDefinitionFor(kind)
			if !ok {
				t.Fatalf("resource directory has no %s definition", kind)
			}
			statement := scope.Apply(db.Session(&gorm.Session{DryRun: true}).Table(definition.table)).
				Find(&[]map[string]interface{}{}).Statement
			if statement.SQL.String() == "" {
				t.Fatalf("QueryScope(%s) produced no SQL", kind)
			}
			if strings.Contains(strings.ToUpper(statement.SQL.String()), strings.ToUpper(definition.table+".id IN (?)")) {
				t.Fatalf("QueryScope(%s) materialized resource IDs: %s", kind, statement.SQL.String())
			}
			if len(statement.Vars) > 30 {
				t.Fatalf("QueryScope(%s) has %d fixed bind variables", kind, len(statement.Vars))
			}
		})
	}
}

func TestCommunityDatabaseCheckerRejectsUnsupportedScopeInsteadOfEnumeratingIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	entry := ResourceRef{Kind: ResourceKindDataset, ID: "dataset-1"}
	_, err = NewDatabaseChecker(db).QueryScope(WithIdentity(t.Context(), "reader", "tenant-1"), ScopeQuery{
		Kind: ResourceKindCanvas, Operation: OperationRead, Entry: &entry, EntryOp: OperationRead,
	})
	if !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("QueryScope(unsupported database shape) = %v, want ErrInvalidPermission", err)
	}
}

func TestCommunityDocumentQueryScopeRequiresReadableDataset(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.UserTenant{}, &entity.Knowledgebase{}, &entity.Document{}); err != nil {
		t.Fatalf("migrate permission tables: %v", err)
	}
	valid := string(entity.StatusValid)
	if err := db.Create(&entity.UserTenant{ID: "reader-membership", UserID: "reader", TenantID: "tenant-1", Role: string(RoleNormal), Status: &valid}).Error; err != nil {
		t.Fatalf("create reader membership: %v", err)
	}
	for _, dataset := range []entity.Knowledgebase{
		{ID: "team-dataset", UserID: "dataset-owner", TenantID: "tenant-1", Name: "Team", EmbdID: "embedding", Permission: string(entity.TenantPermissionTeam), Status: &valid},
		{ID: "private-dataset", UserID: "dataset-owner", TenantID: "tenant-1", Name: "Private", EmbdID: "embedding", Permission: string(entity.TenantPermissionMe), Status: &valid},
		{ID: "reader-dataset", UserID: "reader", TenantID: "tenant-1", Name: "Reader", EmbdID: "embedding", Permission: string(entity.TenantPermissionMe), Status: &valid},
	} {
		if err := db.Create(&dataset).Error; err != nil {
			t.Fatalf("create dataset %q: %v", dataset.ID, err)
		}
	}
	inactive := "0"
	for _, document := range []entity.Document{
		{ID: "team-document", UserID: "dataset-owner", KbID: "team-dataset", ParserID: "general", ParserConfig: entity.JSONMap{}, SourceType: "local", Type: "pdf", CreatedBy: "dataset-owner", Suffix: "pdf", Status: &valid},
		{ID: "owned-document", UserID: "reader", KbID: "reader-dataset", ParserID: "general", ParserConfig: entity.JSONMap{}, SourceType: "local", Type: "pdf", CreatedBy: "reader", Suffix: "pdf", Status: &valid},
		{ID: "hidden-parent-document", UserID: "reader", KbID: "private-dataset", ParserID: "general", ParserConfig: entity.JSONMap{}, SourceType: "local", Type: "pdf", CreatedBy: "reader", Suffix: "pdf", Status: &valid},
		{ID: "inactive-document", UserID: "reader", KbID: "team-dataset", ParserID: "general", ParserConfig: entity.JSONMap{}, SourceType: "local", Type: "pdf", CreatedBy: "reader", Suffix: "pdf", Status: &inactive},
	} {
		if err := db.Create(&document).Error; err != nil {
			t.Fatalf("create document %q: %v", document.ID, err)
		}
	}

	checker := newCommunityDatabaseChecker(db)
	ctx := WithIdentity(t.Context(), "reader", "tenant-1")
	scope, err := checker.QueryScope(ctx, ScopeQuery{
		Kind: ResourceKindDocument, Operation: OperationRead,
	})
	if err != nil {
		t.Fatalf("QueryScope(documents): %v", err)
	}
	var visible []string
	if err := scope.Apply(db.Model(&entity.Document{})).Order("document.id").Pluck("document.id", &visible).Error; err != nil {
		t.Fatalf("query readable documents: %v", err)
	}
	want := []string{"owned-document", "team-document"}
	if len(visible) != len(want) || visible[0] != want[0] || visible[1] != want[1] {
		t.Fatalf("visible documents = %v, want %v", visible, want)
	}
	refs := []ResourceRef{
		{Kind: ResourceKindDocument, ID: "owned-document"},
		{Kind: ResourceKindDocument, ID: "team-document"},
		{Kind: ResourceKindDocument, ID: "hidden-parent-document"},
	}
	accesses, err := checker.FilterAccesses(ctx, refs, OperationRead)
	if err != nil {
		t.Fatalf("resolve document access: %v", err)
	}
	if len(accesses) != len(want) {
		t.Fatalf("resolved document access = %v, want only %v", accesses, want)
	}
}

func TestCommunityChatChannelQueryScopeFiltersTenantMembersInSQL(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.UserTenant{}, &entity.ChatChannel{}); err != nil {
		t.Fatalf("migrate chat channel tables: %v", err)
	}
	status := string(entity.StatusValid)
	for _, membership := range []entity.UserTenant{
		{ID: "reader-membership", UserID: "reader", TenantID: "tenant-1", Role: string(RoleNormal), Status: &status},
		{ID: "other-membership", UserID: "other", TenantID: "tenant-2", Role: string(RoleNormal), Status: &status},
	} {
		if err := db.Create(&membership).Error; err != nil {
			t.Fatalf("create membership %q: %v", membership.ID, err)
		}
	}
	for _, channel := range []entity.ChatChannel{
		{ID: "tenant-channel", UserID: "other", TenantID: "tenant-1", Name: "Tenant", Channel: "public", Config: entity.JSONMap{}},
		{ID: "owned-channel", UserID: "reader", TenantID: "tenant-1", Name: "Owned", Channel: "private", Config: entity.JSONMap{}},
		{ID: "other-tenant-channel", UserID: "reader", TenantID: "tenant-2", Name: "Other tenant", Channel: "private", Config: entity.JSONMap{}},
	} {
		if err := db.Create(&channel).Error; err != nil {
			t.Fatalf("create chat channel %q: %v", channel.ID, err)
		}
	}
	scope, err := newCommunityDatabaseChecker(db).QueryScope(WithIdentity(t.Context(), "reader", "tenant-1"), ScopeQuery{
		Kind: ResourceKindChatChannel, Operation: OperationRead,
	})
	if err != nil {
		t.Fatalf("QueryScope(chat channels): %v", err)
	}
	var visible []string
	if err := scope.Apply(db.Model(&entity.ChatChannel{})).Order("chat_channel.id").Pluck("chat_channel.id", &visible).Error; err != nil {
		t.Fatalf("query scoped channels: %v", err)
	}
	if len(visible) != 2 || visible[0] != "owned-channel" || visible[1] != "tenant-channel" {
		t.Fatalf("visible chat channels = %v, want [owned-channel tenant-channel]", visible)
	}
}

func TestCommunityDatasetAndMemoryQueryScopesFilterCanvasEntriesInSQL(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&entity.UserTenant{}, &entity.Knowledgebase{}, &entity.UserCanvas{}, &entity.Memory{}); err != nil {
		t.Fatalf("migrate permission tables: %v", err)
	}
	valid := string(entity.StatusValid)
	for _, membership := range []entity.UserTenant{
		{ID: "reader-membership", UserID: "reader", TenantID: "tenant-1", Role: string(RoleNormal), Status: &valid},
		{ID: "tenant-owner-membership", UserID: "tenant-owner", TenantID: "tenant-1", Role: string(RoleOwner), Status: &valid},
	} {
		if err := db.Create(&membership).Error; err != nil {
			t.Fatalf("create membership %q: %v", membership.ID, err)
		}
	}
	tenantID := "tenant-1"
	if err := db.Create(&entity.UserCanvas{ID: "entry-canvas", UserID: "reader", TenantID: &tenantID, Permission: string(entity.TenantPermissionMe)}).Error; err != nil {
		t.Fatalf("create canvas entry: %v", err)
	}
	for _, dataset := range []entity.Knowledgebase{
		{ID: "team-dataset", UserID: "dataset-owner", TenantID: tenantID, Name: "Team", EmbdID: "embedding", ParserID: "general", ParserConfig: entity.JSONMap{}, Permission: string(entity.TenantPermissionTeam), Status: &valid},
		{ID: "private-dataset", UserID: "dataset-owner", TenantID: tenantID, Name: "Private", EmbdID: "embedding", ParserID: "general", ParserConfig: entity.JSONMap{}, Permission: string(entity.TenantPermissionMe), Status: &valid},
	} {
		if err := db.Create(&dataset).Error; err != nil {
			t.Fatalf("create dataset %q: %v", dataset.ID, err)
		}
	}
	for _, memory := range []entity.Memory{
		{ID: "owned-memory", UserID: "reader", TenantID: tenantID, Name: "Owned", StorageType: "table", EmbdID: "embedding", LLMID: "chat", Permissions: string(entity.TenantPermissionMe), MemorySize: 1024, ForgettingPolicy: "FIFO", Temperature: 0.5},
		{ID: "team-memory", UserID: "memory-owner", TenantID: tenantID, Name: "Team", StorageType: "table", EmbdID: "embedding", LLMID: "chat", Permissions: string(entity.TenantPermissionTeam), MemorySize: 1024, ForgettingPolicy: "FIFO", Temperature: 0.5},
		{ID: "private-memory", UserID: "memory-owner", TenantID: tenantID, Name: "Private", StorageType: "table", EmbdID: "embedding", LLMID: "chat", Permissions: string(entity.TenantPermissionMe), MemorySize: 1024, ForgettingPolicy: "FIFO", Temperature: 0.5},
	} {
		if err := db.Create(&memory).Error; err != nil {
			t.Fatalf("create memory %q: %v", memory.ID, err)
		}
	}
	checker := newCommunityDatabaseChecker(db)
	ctx := WithIdentity(t.Context(), "reader", tenantID)
	entry := ResourceRef{Kind: ResourceKindCanvas, ID: "entry-canvas"}
	datasetScope, err := checker.QueryScope(ctx, ScopeQuery{
		Kind: ResourceKindDataset, Operation: OperationUse, Entry: &entry, EntryOp: OperationRun,
	})
	if err != nil {
		t.Fatalf("QueryScope(datasets via canvas): %v", err)
	}
	var datasetIDs []string
	if err := datasetScope.Apply(db.Model(&entity.Knowledgebase{})).Order("knowledgebase.id").Pluck("knowledgebase.id", &datasetIDs).Error; err != nil {
		t.Fatalf("query datasets via canvas: %v", err)
	}
	if len(datasetIDs) != 1 || datasetIDs[0] != "team-dataset" {
		t.Fatalf("canvas-scoped datasets = %v, want [team-dataset]", datasetIDs)
	}
	memoryScope, err := checker.QueryScope(ctx, ScopeQuery{
		Kind: ResourceKindMemory, Operation: OperationUse, Entry: &entry, EntryOp: OperationRun,
	})
	if err != nil {
		t.Fatalf("QueryScope(memories via canvas): %v", err)
	}
	var memoryIDs []string
	if err := memoryScope.Apply(db.Model(&entity.Memory{})).Order("memory.id").Pluck("memory.id", &memoryIDs).Error; err != nil {
		t.Fatalf("query memories via canvas: %v", err)
	}
	if len(memoryIDs) != 2 || memoryIDs[0] != "owned-memory" || memoryIDs[1] != "team-memory" {
		t.Fatalf("canvas-scoped memories = %v, want [owned-memory team-memory]", memoryIDs)
	}
}
