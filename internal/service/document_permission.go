package service

import (
	"context"

	"ragflow/internal/dao"
	"ragflow/internal/permission"
)

// CheckDocumentAccess delegates both the dataset read requirement and the
// requested document operation to the permission resource definition.
func CheckDocumentAccess(ctx context.Context, documentID, datasetID string, operation permission.Operation) error {
	checker := permission.NewDatabaseChecker(dao.DB)
	if err := checker.CheckResource(ctx, permission.ResourceRef{
		Kind: permission.ResourceKindDataset,
		ID:   datasetID,
	}, permission.OperationRead); err != nil {
		return err
	}
	return checker.CheckResource(ctx, permission.ResourceRef{
		Kind: permission.ResourceKindDocument,
		ID:   documentID,
	}, operation)
}
