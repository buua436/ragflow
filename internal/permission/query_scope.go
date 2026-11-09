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

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// QueryScope applies an authorization predicate to a database query. It is
// intended for resource listings so authorization, counting, and pagination
// happen in the database query rather than after materializing every resource
// ID.
//
// The zero value denies all rows.
type QueryScope struct {
	apply        func(*gorm.DB) *gorm.DB
	alternatives []QueryScope
}

// Apply adds this authorization predicate to query. A zero-value scope fails
// closed by adding a predicate that matches no rows.
func (s QueryScope) Apply(query *gorm.DB) *gorm.DB {
	if query == nil {
		return nil
	}
	if len(s.alternatives) > 0 {
		scopes := s.alternatives
		if s.apply != nil {
			scopes = append([]QueryScope{{apply: s.apply}}, scopes...)
		}
		conditions := make([]clause.Expression, 0, len(scopes))
		for _, scope := range scopes {
			if scope.apply == nil {
				conditions = append(conditions, clause.Expr{SQL: "1 = 0"})
				continue
			}
			branch := query.Session(&gorm.Session{NewDB: true}).WithContext(query.Statement.Context)
			if query.Statement.Model != nil {
				branch = branch.Model(query.Statement.Model)
			} else if query.Statement.Table != "" {
				branch = branch.Table(query.Statement.Table)
			}
			branch = scope.apply(branch)
			whereClause, ok := branch.Statement.Clauses["WHERE"]
			if !ok {
				conditions = append(conditions, clause.Expr{SQL: "1 = 0"})
				continue
			}
			where, ok := whereClause.Expression.(clause.Where)
			if !ok || len(where.Exprs) == 0 {
				conditions = append(conditions, clause.Expr{SQL: "1 = 0"})
				continue
			}
			conditions = append(conditions, clause.And(where.Exprs...))
		}
		return query.Where(clause.Or(conditions...))
	}
	if s.apply == nil {
		return query.Where("1 = 0")
	}
	return s.apply(query)
}

// Or returns a scope that matches rows authorized by either scope.
func (s QueryScope) Or(other QueryScope) QueryScope {
	scopes := make([]QueryScope, 0, 2+len(s.alternatives)+len(other.alternatives))
	appendScope := func(scope QueryScope) {
		if scope.apply != nil {
			scopes = append(scopes, QueryScope{apply: scope.apply})
		} else if len(scope.alternatives) > 0 {
			scopes = append(scopes, scope.alternatives...)
		} else {
			scopes = append(scopes, QueryScope{})
		}
	}
	appendScope(s)
	appendScope(other)
	return QueryScope{alternatives: scopes}
}

func (s QueryScope) and(other QueryScope) QueryScope {
	if other.apply == nil && len(other.alternatives) == 0 {
		return s
	}
	return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
		return other.Apply(s.Apply(query))
	}}
}

func queryFilterScope(query ScopeQuery) (QueryScope, error) {
	tenantIDs := uniqueFilterValues(query.TenantIDs)
	ownerUserIDs := uniqueFilterValues(query.OwnerUserIDs)
	if len(query.TenantIDs) == 0 && len(query.OwnerUserIDs) == 0 {
		return QueryScope{}, nil
	}
	mapping, ok := resourceDefinitionFor(query.Kind)
	if !ok {
		return QueryScope{}, ErrInvalidPermission
	}
	if (len(query.TenantIDs) > 0 && mapping.tenantColumn == "" && mapping.tenantRelation == nil) ||
		(len(query.OwnerUserIDs) > 0 && mapping.ownerColumn == "" && mapping.ownerRelation == nil) {
		return QueryScope{}, ErrInvalidPermission
	}
	return QueryScope{apply: func(db *gorm.DB) *gorm.DB {
		if len(query.TenantIDs) > 0 {
			if len(tenantIDs) == 0 {
				db = db.Where("1 = 0")
			} else {
				db = applyResourceFieldScope(db, mapping.table, mapping.tenantColumn, mapping.tenantRelation, tenantIDs)
			}
		}
		if len(query.OwnerUserIDs) > 0 {
			if len(ownerUserIDs) == 0 {
				db = db.Where("1 = 0")
			} else {
				db = applyResourceFieldScope(db, mapping.table, mapping.ownerColumn, mapping.ownerRelation, ownerUserIDs)
			}
		}
		return db
	}}, nil
}

func applyResourceFieldScope(query *gorm.DB, table, column string, relation *resourceRelation, values []string) *gorm.DB {
	if relation == nil {
		return query.Where(clause.IN{Column: clause.Column{Table: table, Name: column}, Values: stringValues(values)})
	}
	ids := query.Session(&gorm.Session{NewDB: true}).Table(relation.table).Select(relation.relatedIDColumn).
		Where(clause.IN{Column: clause.Column{Table: relation.table, Name: relation.relatedColumn}, Values: stringValues(values)})
	return query.Where(clause.Expr{
		SQL:  "? IN (?)",
		Vars: []interface{}{clause.Column{Table: table, Name: relation.localColumn}, ids},
	})
}

func uniqueFilterValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func stringValues(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func queryScopeForIDs(kind ResourceKind, ids []string) QueryScope {
	mapping, ok := resourceDefinitionFor(kind)
	if !ok {
		return QueryScope{}
	}
	resourceIDs := append([]string(nil), ids...)
	return QueryScope{apply: func(query *gorm.DB) *gorm.DB {
		if len(resourceIDs) == 0 {
			return query.Where("1 = 0")
		}
		values := make([]interface{}, len(resourceIDs))
		for i, id := range resourceIDs {
			values[i] = id
		}
		return query.Where(clause.IN{
			Column: clause.Column{Table: mapping.table, Name: "id"},
			Values: values,
		})
	}}
}

// QueryScopeForIDs builds a SQL predicate for a policy source that resolves
// authorization to an explicit set of resource IDs.
func QueryScopeForIDs(kind ResourceKind, ids []string) QueryScope {
	return queryScopeForIDs(kind, ids)
}
