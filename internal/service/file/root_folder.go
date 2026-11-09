package file

import (
	"context"
	"fmt"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"

	"gorm.io/gorm"
)

// GetOrCreateRootFolder creates the selected tenant's root folder for its
// persisted owner. The folder row and owner grant share a transaction.
func GetOrCreateRootFolder(ctx context.Context, db *gorm.DB) (*entity.File, error) {
	userID := permission.UserIDFromContext(ctx)
	tenantID := permission.TenantIDFromContext(ctx)
	if userID == "" {
		return nil, permission.ErrUnauthenticated
	}
	if tenantID == "" {
		return nil, permission.ErrTenantContextMissing
	}
	owner, err := permission.TenantOwnerMembership(ctx, db, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant root folder owner: %w", err)
	}
	var root *entity.File
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		root, err = dao.NewFileDAO().GetRootFolder(ctx, tx, tenantID, owner.UserID, userID)
		if err != nil {
			return err
		}
		if err := permission.NewDatabaseChecker(tx).GrantResourceOwner(ctx, permission.ResourceRef{Kind: permission.ResourceKindFolder, ID: root.ID}); err != nil {
			return fmt.Errorf("grant root folder owner: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return root, nil
}
