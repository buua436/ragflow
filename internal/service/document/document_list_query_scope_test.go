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

package document

import (
	"errors"
	"testing"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
	"ragflow/internal/service"
)

func TestDocumentListAppliesDocumentScopeBeforeCountAndRows(t *testing.T) {
	db := setupServiceTestDB(t)
	pushServiceDB(t, db)
	insertTestKB(t, "kb-list", "tenant-1", 2, 0, 0)
	insertTestDoc(t, "visible-doc", "kb-list", 0, 0)
	insertTestDoc(t, "inactive-doc", "kb-list", 0, 0)
	if err := db.Model(&entity.Document{}).Where("id = ?", "inactive-doc").Update("status", "0").Error; err != nil {
		t.Fatalf("deactivate document: %v", err)
	}

	for _, item := range []struct {
		fileID string
		docID  string
	}{
		{fileID: "file-visible", docID: "visible-doc"},
		{fileID: "file-inactive", docID: "inactive-doc"},
	} {
		insertTestFile(t, item.fileID, "kb-list", item.fileID+".txt", sptr(item.fileID+".txt"))
		insertTestFile2Document(t, "f2d-"+item.fileID, item.fileID, item.docID)
	}

	ctx := documentTestContext(t.Context())
	svc := testDocumentService(t)
	opts := dao.DocumentListOptions{KbID: "kb-list", OrderBy: "create_time", Desc: true}
	documents, total, err := svc.ListDocumentsByDatasetIDWithOptions(ctx, opts, 1, 10)
	if err != nil {
		t.Fatalf("list documents: %v", err)
	}
	if total != 1 || len(documents) != 1 || documents[0].ID != "visible-doc" {
		t.Fatalf("list documents = (%v, %d), want [visible-doc], total 1", documents, total)
	}

	ids, err := svc.ListDocumentIDsByDatasetIDWithOptions(ctx, opts)
	if err != nil {
		t.Fatalf("list document IDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "visible-doc" {
		t.Fatalf("document IDs = %v, want [visible-doc]", ids)
	}

	if err := service.CheckDocumentAccess(ctx, "inactive-doc", "kb-list", permission.OperationRead); !errors.Is(err, permission.ErrResourceNotFound) {
		t.Fatalf("CheckDocumentAccess(inactive-doc) = %v, want resource not found", err)
	}
}
