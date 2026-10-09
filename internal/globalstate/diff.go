package globalstate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pgplex/pgschema/ir"
)

type Change struct {
	SQL       string
	Type      string
	Operation string
	Path      string
}

func PlanChanges(manifest Manifest, current Snapshot, majorVersion int) ([]Change, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	roles := append([]Role(nil), manifest.Roles...)
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	memberships := append([]Membership(nil), manifest.Memberships...)
	sort.Slice(memberships, func(i, j int) bool {
		if memberships[i].Role == memberships[j].Role {
			return memberships[i].Member < memberships[j].Member
		}
		return memberships[i].Role < memberships[j].Role
	})

	var changes []Change
	available := make(map[string]bool, len(current.Roles)+len(roles))
	for name := range current.Roles {
		available[name] = true
	}
	for _, role := range roles {
		actual, exists := current.Roles[role.Name]
		if role.State == StateExternal {
			if !exists {
				return nil, fmt.Errorf("external role %q does not exist", role.Name)
			}
			continue
		}
		available[role.Name] = true
		operation := "alter"
		if !exists {
			operation = "create"
			changes = append(changes, Change{
				SQL:       "CREATE ROLE " + ir.QuoteIdentifier(role.Name) + " WITH " + roleOptions(role),
				Type:      "role",
				Operation: operation,
				Path:      role.Name,
			})
			continue
		}
		if roleDiffers(role, actual) {
			changes = append(changes, Change{
				SQL:       "ALTER ROLE " + ir.QuoteIdentifier(role.Name) + " WITH " + roleOptions(role),
				Type:      "role",
				Operation: operation,
				Path:      role.Name,
			})
		}
	}

	for _, membership := range memberships {
		if !available[membership.Role] {
			return nil, fmt.Errorf("membership role %q is neither present nor declared", membership.Role)
		}
		if !available[membership.Member] {
			return nil, fmt.Errorf("membership member %q is neither present nor declared", membership.Member)
		}
		if majorVersion < 16 && (!membership.Inherit || !membership.Set) {
			return nil, fmt.Errorf("membership INHERIT and SET options require PostgreSQL 16 or newer")
		}
		key := MembershipKey(membership.Role, membership.Member)
		actual, exists := current.Memberships[key]
		if membership.State == StateAbsent {
			if exists {
				changes = append(changes, Change{
					SQL:       fmt.Sprintf("REVOKE %s FROM %s", ir.QuoteIdentifier(membership.Role), ir.QuoteIdentifier(membership.Member)),
					Type:      "role_membership",
					Operation: "drop",
					Path:      key,
				})
			}
			continue
		}
		if !exists {
			changes = append(changes, Change{
				SQL:       grantMembershipSQL(membership, majorVersion),
				Type:      "role_membership",
				Operation: "create",
				Path:      key,
			})
			continue
		}
		if membership.Admin == actual.Admin && membership.Inherit == actual.Inherit && membership.Set == actual.Set {
			continue
		}
		if majorVersion < 16 && actual.Admin && !membership.Admin {
			changes = append(changes, Change{
				SQL:       fmt.Sprintf("REVOKE ADMIN OPTION FOR %s FROM %s", ir.QuoteIdentifier(membership.Role), ir.QuoteIdentifier(membership.Member)),
				Type:      "role_membership",
				Operation: "alter",
				Path:      key,
			})
			continue
		}
		changes = append(changes, Change{
			SQL:       grantMembershipSQL(membership, majorVersion),
			Type:      "role_membership",
			Operation: "alter",
			Path:      key,
		})
	}
	return changes, nil
}

func roleDiffers(desired Role, actual RoleState) bool {
	return desired.Login != actual.Login || desired.Inherit != actual.Inherit ||
		desired.CreateDB != actual.CreateDB || desired.CreateRole != actual.CreateRole ||
		desired.Replication != actual.Replication || desired.BypassRLS != actual.BypassRLS ||
		desired.ConnectionLimit != actual.ConnectionLimit
}

func roleOptions(role Role) string {
	return strings.Join([]string{
		boolOption(role.Login, "LOGIN", "NOLOGIN"),
		boolOption(role.Inherit, "INHERIT", "NOINHERIT"),
		boolOption(role.CreateDB, "CREATEDB", "NOCREATEDB"),
		boolOption(role.CreateRole, "CREATEROLE", "NOCREATEROLE"),
		boolOption(role.Replication, "REPLICATION", "NOREPLICATION"),
		boolOption(role.BypassRLS, "BYPASSRLS", "NOBYPASSRLS"),
		fmt.Sprintf("CONNECTION LIMIT %d", role.ConnectionLimit),
	}, " ")
}

func boolOption(value bool, enabled, disabled string) string {
	if value {
		return enabled
	}
	return disabled
}

func grantMembershipSQL(membership Membership, majorVersion int) string {
	sql := fmt.Sprintf("GRANT %s TO %s", ir.QuoteIdentifier(membership.Role), ir.QuoteIdentifier(membership.Member))
	if majorVersion >= 16 {
		return fmt.Sprintf("%s WITH ADMIN %s, INHERIT %s, SET %s", sql,
			boolKeyword(membership.Admin), boolKeyword(membership.Inherit), boolKeyword(membership.Set))
	}
	if membership.Admin {
		return sql + " WITH ADMIN OPTION"
	}
	return sql
}

func boolKeyword(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}
