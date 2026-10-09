package globalstate

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pgplex/pgschema/ir"
)

type Change struct {
	SQL       string
	Type      string
	Operation string
	Path      string
	Phase     string
}

func PlanChanges(manifest Manifest, current Snapshot, majorVersion int) ([]Change, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	roles := append([]Role(nil), manifest.Roles...)
	for i := range roles {
		if roles[i].ValidUntil == "" {
			roles[i].ValidUntil = "infinity"
		}
	}
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
	createdRoles := make(map[string]bool)
	for name := range current.Roles {
		available[name] = true
	}
	for _, role := range roles {
		actual, exists := current.Roles[role.Name]
		if role.State == StateAbsent {
			if !exists {
				continue
			}
			if role.Name == current.SessionRole.Name || strings.HasPrefix(role.Name, "pg_") {
				return nil, fmt.Errorf("refusing to drop protected role %q", role.Name)
			}
			changes = append(changes, Change{
				SQL: "DROP ROLE " + ir.QuoteIdentifier(role.Name), Type: "role", Operation: "drop",
				Path: role.Name, Phase: "post",
			})
			continue
		}
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
			createdRoles[role.Name] = true
			changes = append(changes, Change{
				SQL:       roleChangeSQL("CREATE ROLE", role, false),
				Type:      "role",
				Operation: operation,
				Path:      role.Name,
			})
			continue
		}
		if roleDiffers(role, actual) {
			changes = append(changes, Change{
				SQL:       roleChangeSQL("ALTER ROLE", role, true),
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
		omitAdmin := membership.Member == current.SessionRole.Name && membership.Admin &&
			(current.SessionAdminRoles[membership.Role] ||
				(majorVersion >= 16 && createdRoles[membership.Role] && !current.SessionRole.Superuser))
		if membership.Member == current.SessionRole.Name && !membership.Admin &&
			(current.SessionAdminRoles[membership.Role] ||
				(majorVersion >= 16 && createdRoles[membership.Role] && !current.SessionRole.Superuser)) {
			return nil, fmt.Errorf("cannot converge ADMIN false for session role %q on role %q because PostgreSQL owns the creator ADMIN grant", membership.Member, membership.Role)
		}
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
				SQL:       grantMembershipSQL(membership, majorVersion, omitAdmin),
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
			SQL:       grantMembershipSQL(membership, majorVersion, omitAdmin),
			Type:      "role_membership",
			Operation: "alter",
			Path:      key,
		})
	}
	for _, object := range manifest.Ownership {
		if !available[object.Owner] {
			return nil, fmt.Errorf("ownership role %q is neither present nor declared", object.Owner)
		}
		actual, exists := current.Ownership[ownershipKey(object.Kind, object.Name)]
		if exists && actual.ExtensionOwned {
			return nil, fmt.Errorf("refusing to manage ownership of extension member %s %q", object.Kind, object.Name)
		}
		if !exists || actual.Owner != object.Owner {
			sql, err := ownershipSQL(object)
			if err != nil {
				return nil, err
			}
			changes = append(changes, Change{SQL: sql, Type: "ownership", Operation: "alter", Path: ownershipKey(object.Kind, object.Name), Phase: "post"})
		}
	}
	for _, privilege := range manifest.DefaultPrivileges {
		if privilege.ObjectType == "schemas" && majorVersion < 15 {
			return nil, fmt.Errorf("global default privileges on schemas require PostgreSQL 15 or newer")
		}
		if privilege.ObjectType == "tables" && majorVersion < 17 && slices.Contains(privilege.Privileges, "MAINTAIN") {
			return nil, fmt.Errorf("MAINTAIN default privileges require PostgreSQL 17 or newer")
		}
		if !available[privilege.Owner] || (privilege.Grantee != "PUBLIC" && !available[privilege.Grantee]) {
			return nil, fmt.Errorf("default privilege roles must be present or declared")
		}
		actual := current.DefaultPrivileges[defaultPrivilegeKey(privilege.Owner, privilege.ObjectType, privilege.Grantee)]
		if defaultPrivilegeMatches(privilege, actual) {
			continue
		}
		operation := "alter"
		if privilege.State == StateAbsent {
			operation = "drop"
		}
		changes = append(changes, Change{
			SQL:  defaultPrivilegeSQL(privilege, current.SessionRole.Name, !current.SessionRole.Superuser),
			Type: "global_default_privilege", Operation: operation,
			Path: defaultPrivilegeKey(privilege.Owner, privilege.ObjectType, privilege.Grantee), Phase: "post",
		})
	}
	if err := preflightRoleAuthority(manifest, current, changes, majorVersion); err != nil {
		return nil, err
	}
	return changes, nil
}

func preflightRoleAuthority(manifest Manifest, current Snapshot, changes []Change, majorVersion int) error {
	if current.SessionRole.Name == "" || current.SessionRole.Superuser {
		return nil
	}
	created := make(map[string]bool)
	plannedSet := make(map[string]bool)
	for _, role := range manifest.Roles {
		if role.State == StatePresent {
			if _, exists := current.Roles[role.Name]; !exists {
				created[role.Name] = true
			}
		}
	}
	for _, membership := range manifest.Memberships {
		if membership.State == StatePresent && membership.Member == current.SessionRole.Name &&
			(majorVersion < 16 || membership.Set) {
			plannedSet[membership.Role] = true
		}
	}
	for _, change := range changes {
		switch change.Type {
		case "role", "role_membership":
			if !current.SessionRole.CreateRole {
				return fmt.Errorf("session role %q lacks CREATEROLE required by the planned role changes", current.SessionRole.Name)
			}
			if majorVersion < 16 {
				continue
			}
			authorityRole := change.Path
			if change.Type == "role_membership" {
				authorityRole, _, _ = strings.Cut(change.Path, "/")
			} else if change.Operation == "create" {
				continue
			}
			if !created[authorityRole] && !current.SessionAdminRoles[authorityRole] {
				return fmt.Errorf("session role %q lacks ADMIN OPTION on role %q required by the planned %s", current.SessionRole.Name, authorityRole, change.Type)
			}
		case "ownership":
			object := ownershipForPath(manifest, change.Path)
			actual, exists := current.Ownership[change.Path]
			if exists && actual.Owner != current.SessionRole.Name && !current.SessionSetRoles[actual.Owner] {
				return fmt.Errorf("session role %q cannot assume current owner role %q for %s", current.SessionRole.Name, actual.Owner, change.Path)
			}
			if object.Owner != current.SessionRole.Name && !current.SessionSetRoles[object.Owner] && !plannedSet[object.Owner] {
				return fmt.Errorf("session role %q lacks SET authority on new owner role %q for %s; declare a SET-enabled membership", current.SessionRole.Name, object.Owner, change.Path)
			}
			if object.Kind == "database" && !current.SessionRole.CreateDB {
				return fmt.Errorf("session role %q lacks CREATEDB required to change database ownership", current.SessionRole.Name)
			}
		case "global_default_privilege":
			privilege := defaultPrivilegeForPath(manifest, change.Path)
			if privilege.Owner != current.SessionRole.Name && !current.SessionSetRoles[privilege.Owner] && !plannedSet[privilege.Owner] {
				return fmt.Errorf("session role %q lacks SET authority on default-privilege owner role %q; declare a SET-enabled membership", current.SessionRole.Name, privilege.Owner)
			}
		}
	}
	for _, role := range manifest.Roles {
		actual, exists := current.Roles[role.Name]
		if role.State != StatePresent || (!exists && !role.Replication && !role.BypassRLS) {
			continue
		}
		if (!exists && (role.Replication || role.BypassRLS)) || (exists && (actual.Superuser || role.Replication != actual.Replication || role.BypassRLS != actual.BypassRLS)) {
			return fmt.Errorf("session role %q must be superuser to change SUPERUSER, REPLICATION, or BYPASSRLS on role %q", current.SessionRole.Name, role.Name)
		}
	}
	return nil
}

func ownershipForPath(manifest Manifest, path string) Ownership {
	for _, object := range manifest.Ownership {
		if ownershipKey(object.Kind, object.Name) == path {
			return object
		}
	}
	return Ownership{}
}

func defaultPrivilegeForPath(manifest Manifest, path string) DefaultPrivilege {
	for _, privilege := range manifest.DefaultPrivileges {
		if defaultPrivilegeKey(privilege.Owner, privilege.ObjectType, privilege.Grantee) == path {
			return privilege
		}
	}
	return DefaultPrivilege{}
}

func roleDiffers(desired Role, actual RoleState) bool {
	return desired.Login != actual.Login || desired.Inherit != actual.Inherit ||
		desired.CreateDB != actual.CreateDB || desired.CreateRole != actual.CreateRole ||
		desired.Replication != actual.Replication || desired.BypassRLS != actual.BypassRLS ||
		actual.Superuser || desired.ConnectionLimit != actual.ConnectionLimit || !validUntilMatches(desired.ValidUntil, actual.ValidUntil) ||
		!maps.Equal(desired.Configuration, actual.Configuration)
}

func roleOptions(role Role) string {
	return strings.Join([]string{
		"NOSUPERUSER",
		boolOption(role.Login, "LOGIN", "NOLOGIN"),
		boolOption(role.Inherit, "INHERIT", "NOINHERIT"),
		boolOption(role.CreateDB, "CREATEDB", "NOCREATEDB"),
		boolOption(role.CreateRole, "CREATEROLE", "NOCREATEROLE"),
		boolOption(role.Replication, "REPLICATION", "NOREPLICATION"),
		boolOption(role.BypassRLS, "BYPASSRLS", "NOBYPASSRLS"),
		fmt.Sprintf("CONNECTION LIMIT %d", role.ConnectionLimit),
		"VALID UNTIL " + quoteLiteral(role.ValidUntil),
	}, " ")
}

func roleChangeSQL(command string, role Role, resetConfiguration bool) string {
	name := ir.QuoteIdentifier(role.Name)
	statements := []string{command + " " + name + " WITH " + roleOptions(role)}
	if resetConfiguration {
		statements = append(statements, "ALTER ROLE "+name+" RESET ALL")
	}
	keys := make([]string, 0, len(role.Configuration))
	for key := range role.Configuration {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		statements = append(statements, "ALTER ROLE "+name+" SET "+key+" TO "+quoteLiteral(role.Configuration[key]))
	}
	return strings.Join(statements, "; ")
}

func validUntilMatches(desired, actual string) bool {
	if desired == "infinity" {
		return actual == "infinity"
	}
	parsed, err := time.Parse(time.RFC3339, desired)
	return err == nil && fmt.Sprintf("%d", parsed.UnixMicro()) == actual
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func ownershipSQL(object Ownership) (string, error) {
	owner := ir.QuoteIdentifier(object.Owner)
	if object.Kind == "database" || object.Kind == "schema" {
		return fmt.Sprintf("ALTER %s %s OWNER TO %s", strings.ToUpper(object.Kind), ir.QuoteIdentifier(object.Name), owner), nil
	}
	if object.Kind == "function" || object.Kind == "procedure" {
		routine, err := renderRoutineName(object.Name)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ALTER %s %s OWNER TO %s", strings.ToUpper(object.Kind), routine, owner), nil
	}
	schema, name, err := splitQualifiedName(object.Name)
	if err != nil {
		return "", err
	}
	kind := strings.ToUpper(strings.ReplaceAll(object.Kind, "_", " "))
	return fmt.Sprintf("ALTER %s %s.%s OWNER TO %s", kind, ir.QuoteIdentifier(schema), ir.QuoteIdentifier(name), owner), nil
}

func renderRoutineName(name string) (string, error) {
	open := strings.IndexByte(name, '(')
	if open < 0 || !strings.HasSuffix(name, ")") || strings.ContainsAny(name, ";\n\r") || strings.Contains(name, "--") || strings.Contains(name, "/*") {
		return "", fmt.Errorf("routine name %q must be a safe schema-qualified identity signature", name)
	}
	schema, routine, err := splitQualifiedName(name[:open])
	if err != nil {
		return "", err
	}
	return ir.QuoteIdentifier(schema) + "." + ir.QuoteIdentifier(routine) + name[open:], nil
}

func defaultPrivilegeMatches(desired DefaultPrivilege, actual DefaultPrivilegeState) bool {
	if desired.State == StateAbsent {
		return len(actual.Privileges) == 0
	}
	if len(desired.Privileges) != len(actual.Privileges) {
		return false
	}
	for _, privilege := range desired.Privileges {
		if grantable, exists := actual.Privileges[privilege]; !exists || grantable != desired.GrantOption {
			return false
		}
	}
	return true
}

func defaultPrivilegeSQL(privilege DefaultPrivilege, sessionRole string, assumeOwner bool) string {
	base := "ALTER DEFAULT PRIVILEGES FOR ROLE " + ir.QuoteIdentifier(privilege.Owner)
	grantee := privilege.Grantee
	if grantee != "PUBLIC" {
		grantee = ir.QuoteIdentifier(grantee)
	}
	revoke := base + " REVOKE ALL ON " + strings.ToUpper(privilege.ObjectType) + " FROM " + grantee
	if privilege.State == StateAbsent {
		return defaultPrivilegeAsOwner(revoke, privilege.Owner, sessionRole, assumeOwner)
	}
	grant := base + " GRANT " + strings.Join(privilege.Privileges, ", ") + " ON " + strings.ToUpper(privilege.ObjectType) + " TO " + grantee
	if privilege.GrantOption {
		grant += " WITH GRANT OPTION"
	}
	return defaultPrivilegeAsOwner(revoke+"; "+grant, privilege.Owner, sessionRole, assumeOwner)
}

func defaultPrivilegeAsOwner(sql, owner, sessionRole string, assumeOwner bool) string {
	if !assumeOwner || owner == sessionRole || sessionRole == "" {
		return sql
	}
	return "SET ROLE " + ir.QuoteIdentifier(owner) + "; " + sql + "; RESET ROLE"
}

func boolOption(value bool, enabled, disabled string) string {
	if value {
		return enabled
	}
	return disabled
}

func grantMembershipSQL(membership Membership, majorVersion int, omitAdmin bool) string {
	sql := fmt.Sprintf("GRANT %s TO %s", ir.QuoteIdentifier(membership.Role), ir.QuoteIdentifier(membership.Member))
	if majorVersion >= 16 {
		options := make([]string, 0, 3)
		if !omitAdmin {
			options = append(options, "ADMIN "+boolKeyword(membership.Admin))
		}
		options = append(options, "INHERIT "+boolKeyword(membership.Inherit), "SET "+boolKeyword(membership.Set))
		return sql + " WITH " + strings.Join(options, ", ")
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
