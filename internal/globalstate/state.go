package globalstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lib/pq"
)

type RoleState struct {
	Name            string            `json:"name"`
	Superuser       bool              `json:"superuser"`
	Login           bool              `json:"login"`
	Inherit         bool              `json:"inherit"`
	CreateDB        bool              `json:"createdb"`
	CreateRole      bool              `json:"createrole"`
	Replication     bool              `json:"replication"`
	BypassRLS       bool              `json:"bypassrls"`
	ConnectionLimit int               `json:"connection_limit"`
	ValidUntil      string            `json:"valid_until"`
	Configuration   map[string]string `json:"configuration,omitempty"`
}

type MembershipState struct {
	Role    string `json:"role"`
	Member  string `json:"member"`
	Admin   bool   `json:"admin"`
	Inherit bool   `json:"inherit"`
	Set     bool   `json:"set"`
}

type Snapshot struct {
	Roles             map[string]RoleState
	Memberships       map[string]MembershipState
	Ownership         map[string]OwnershipState
	DefaultPrivileges map[string]DefaultPrivilegeState
	SessionRole       RoleState
	SessionAdminRoles map[string]bool
	SessionSetRoles   map[string]bool
}

type OwnershipState struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Owner          string `json:"owner"`
	ExtensionOwned bool   `json:"extension_owned,omitempty"`
}

type DefaultPrivilegeState struct {
	Owner      string          `json:"owner"`
	ObjectType string          `json:"object_type"`
	Grantee    string          `json:"grantee"`
	Privileges map[string]bool `json:"privileges"`
}

type MembershipRef struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

type Selection struct {
	Roles             []string              `json:"roles"`
	Memberships       []MembershipRef       `json:"memberships"`
	Ownership         []Ownership           `json:"ownership"`
	DefaultPrivileges []DefaultPrivilegeRef `json:"default_privileges"`
}

type DefaultPrivilegeRef struct {
	Owner      string `json:"owner"`
	ObjectType string `json:"object_type"`
	Grantee    string `json:"grantee"`
}

type Fingerprint struct {
	Hash      string    `json:"hash"`
	Selection Selection `json:"selection"`
}

func SelectionFor(manifest Manifest) Selection {
	roleNames := make(map[string]struct{})
	for _, role := range manifest.Roles {
		roleNames[role.Name] = struct{}{}
	}
	selection := Selection{}
	for _, membership := range manifest.Memberships {
		roleNames[membership.Role] = struct{}{}
		roleNames[membership.Member] = struct{}{}
		selection.Memberships = append(selection.Memberships, MembershipRef{Role: membership.Role, Member: membership.Member})
	}
	for _, object := range manifest.Ownership {
		roleNames[object.Owner] = struct{}{}
		selection.Ownership = append(selection.Ownership, object)
	}
	for _, privilege := range manifest.DefaultPrivileges {
		roleNames[privilege.Owner] = struct{}{}
		if privilege.Grantee != "PUBLIC" {
			roleNames[privilege.Grantee] = struct{}{}
		}
		selection.DefaultPrivileges = append(selection.DefaultPrivileges, DefaultPrivilegeRef{
			Owner: privilege.Owner, ObjectType: privilege.ObjectType, Grantee: privilege.Grantee,
		})
	}
	for role := range roleNames {
		selection.Roles = append(selection.Roles, role)
	}
	normalizeSelection(&selection)
	return selection
}

func Inspect(ctx context.Context, db *sql.DB, selection Selection, majorVersion int) (Snapshot, error) {
	normalizeSelection(&selection)
	snapshot := Snapshot{
		Roles:             make(map[string]RoleState),
		Memberships:       make(map[string]MembershipState),
		Ownership:         make(map[string]OwnershipState),
		DefaultPrivileges: make(map[string]DefaultPrivilegeState),
		SessionAdminRoles: make(map[string]bool),
		SessionSetRoles:   make(map[string]bool),
	}
	var sessionConfig pq.StringArray
	if err := db.QueryRowContext(ctx, `
SELECT rolname, rolsuper, rolcanlogin, rolinherit, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls, rolconnlimit,
       CASE WHEN rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz THEN 'infinity'
            ELSE ((extract(epoch FROM rolvaliduntil) * 1000000)::bigint)::text END,
       COALESCE(rolconfig, '{}'::text[])
FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(
		&snapshot.SessionRole.Name, &snapshot.SessionRole.Superuser, &snapshot.SessionRole.Login,
		&snapshot.SessionRole.Inherit, &snapshot.SessionRole.CreateDB, &snapshot.SessionRole.CreateRole,
		&snapshot.SessionRole.Replication, &snapshot.SessionRole.BypassRLS,
		&snapshot.SessionRole.ConnectionLimit, &snapshot.SessionRole.ValidUntil,
		&sessionConfig,
	); err != nil {
		return Snapshot{}, fmt.Errorf("inspect session role: %w", err)
	}
	snapshot.SessionRole.Configuration = parseRoleConfiguration(sessionConfig)
	adminRows, err := db.QueryContext(ctx, `
SELECT granted.rolname
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
JOIN pg_catalog.pg_roles member ON member.oid = m.member
WHERE member.rolname = current_user AND m.admin_option`)
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect session role authority: %w", err)
	}
	for adminRows.Next() {
		var role string
		if err := adminRows.Scan(&role); err != nil {
			adminRows.Close()
			return Snapshot{}, fmt.Errorf("scan session role authority: %w", err)
		}
		snapshot.SessionAdminRoles[role] = true
	}
	if err := adminRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("inspect session role authority: %w", err)
	}
	setPrivilege := "MEMBER"
	if majorVersion >= 16 {
		setPrivilege = "SET"
	}
	setRows, err := db.QueryContext(ctx, `SELECT rolname, pg_has_role(current_user, oid, $1) FROM pg_catalog.pg_roles`, setPrivilege)
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect session SET authority: %w", err)
	}
	for setRows.Next() {
		var role string
		var canSet bool
		if err := setRows.Scan(&role, &canSet); err != nil {
			setRows.Close()
			return Snapshot{}, fmt.Errorf("scan session SET authority: %w", err)
		}
		if canSet {
			snapshot.SessionSetRoles[role] = true
		}
	}
	if err := setRows.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("inspect session SET authority: %w", err)
	}
	if len(selection.Roles) > 0 {
		rows, err := db.QueryContext(ctx, `
SELECT rolname, rolsuper, rolcanlogin, rolinherit, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls, rolconnlimit,
       CASE WHEN rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz THEN 'infinity'
            ELSE ((extract(epoch FROM rolvaliduntil) * 1000000)::bigint)::text END,
       COALESCE(rolconfig, '{}'::text[])
FROM pg_catalog.pg_roles
WHERE rolname = ANY($1)
ORDER BY rolname`, pq.Array(selection.Roles))
		if err != nil {
			return Snapshot{}, fmt.Errorf("inspect global roles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var role RoleState
			var configEntries pq.StringArray
			if err := rows.Scan(&role.Name, &role.Superuser, &role.Login, &role.Inherit, &role.CreateDB, &role.CreateRole, &role.Replication, &role.BypassRLS, &role.ConnectionLimit, &role.ValidUntil, &configEntries); err != nil {
				return Snapshot{}, fmt.Errorf("scan global role: %w", err)
			}
			role.Configuration = parseRoleConfiguration(configEntries)
			snapshot.Roles[role.Name] = role
		}
		if err := rows.Err(); err != nil {
			return Snapshot{}, fmt.Errorf("inspect global roles: %w", err)
		}
	}

	if len(selection.Memberships) > 0 {
		options := "bool_or(m.admin_option), true AS inherit_option, true AS set_option"
		if majorVersion >= 16 {
			options = "bool_or(m.admin_option), bool_or(m.inherit_option), bool_or(m.set_option)"
		}
		rows, err := db.QueryContext(ctx, fmt.Sprintf(`
SELECT granted.rolname, member.rolname, %s
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
JOIN pg_catalog.pg_roles member ON member.oid = m.member
GROUP BY granted.rolname, member.rolname
ORDER BY granted.rolname, member.rolname`, options))
		if err != nil {
			return Snapshot{}, fmt.Errorf("inspect role memberships: %w", err)
		}
		defer rows.Close()
		wanted := make(map[string]struct{}, len(selection.Memberships))
		for _, membership := range selection.Memberships {
			wanted[MembershipKey(membership.Role, membership.Member)] = struct{}{}
		}
		for rows.Next() {
			var membership MembershipState
			if err := rows.Scan(&membership.Role, &membership.Member, &membership.Admin, &membership.Inherit, &membership.Set); err != nil {
				return Snapshot{}, fmt.Errorf("scan role membership: %w", err)
			}
			key := MembershipKey(membership.Role, membership.Member)
			if _, ok := wanted[key]; ok {
				snapshot.Memberships[key] = membership
			}
		}
		if err := rows.Err(); err != nil {
			return Snapshot{}, fmt.Errorf("inspect role memberships: %w", err)
		}
	}
	for _, object := range selection.Ownership {
		state, exists, err := inspectOwnership(ctx, db, object)
		if err != nil {
			return Snapshot{}, err
		}
		if exists {
			snapshot.Ownership[ownershipKey(object.Kind, object.Name)] = state
		}
	}
	if len(selection.DefaultPrivileges) > 0 {
		if err := inspectDefaultPrivileges(ctx, db, selection.DefaultPrivileges, snapshot.DefaultPrivileges); err != nil {
			return Snapshot{}, err
		}
		for _, ref := range selection.DefaultPrivileges {
			if _, exists := snapshot.Roles[ref.Owner]; exists || ref.Grantee != "PUBLIC" {
				continue
			}
			implicit := implicitPublicDefaultPrivileges(ref.ObjectType)
			if len(implicit) > 0 {
				snapshot.DefaultPrivileges[defaultPrivilegeKey(ref.Owner, ref.ObjectType, ref.Grantee)] = DefaultPrivilegeState{
					Owner: ref.Owner, ObjectType: ref.ObjectType, Grantee: ref.Grantee, Privileges: implicit,
				}
			}
		}
	}
	return snapshot, nil
}

func implicitPublicDefaultPrivileges(objectType string) map[string]bool {
	switch objectType {
	case "functions":
		return map[string]bool{"EXECUTE": false}
	case "types":
		return map[string]bool{"USAGE": false}
	default:
		return nil
	}
}

func ComputeFingerprint(snapshot Snapshot, selection Selection) (*Fingerprint, error) {
	normalizeSelection(&selection)
	type fingerprintState struct {
		Roles             []*RoleState             `json:"roles"`
		Memberships       []*MembershipState       `json:"memberships"`
		Ownership         []*OwnershipState        `json:"ownership"`
		DefaultPrivileges []*DefaultPrivilegeState `json:"default_privileges"`
		Authority         authorityState           `json:"authority"`
	}
	authority := authorityState{
		Name: snapshot.SessionRole.Name, Superuser: snapshot.SessionRole.Superuser,
		CreateRole: snapshot.SessionRole.CreateRole, CreateDB: snapshot.SessionRole.CreateDB,
	}
	relevantAuthorityRoles := make(map[string]struct{}, len(selection.Roles)+len(selection.Ownership))
	for _, name := range selection.Roles {
		relevantAuthorityRoles[name] = struct{}{}
	}
	for _, object := range selection.Ownership {
		if actual, exists := snapshot.Ownership[ownershipKey(object.Kind, object.Name)]; exists {
			relevantAuthorityRoles[actual.Owner] = struct{}{}
		}
	}
	for name := range snapshot.SessionAdminRoles {
		if _, relevant := relevantAuthorityRoles[name]; relevant {
			authority.AdminRoles = append(authority.AdminRoles, name)
		}
	}
	for name := range snapshot.SessionSetRoles {
		if _, relevant := relevantAuthorityRoles[name]; relevant {
			authority.SetRoles = append(authority.SetRoles, name)
		}
	}
	sort.Strings(authority.AdminRoles)
	sort.Strings(authority.SetRoles)
	state := fingerprintState{Authority: authority}
	for _, object := range selection.Ownership {
		if stateValue, exists := snapshot.Ownership[ownershipKey(object.Kind, object.Name)]; exists {
			copy := stateValue
			state.Ownership = append(state.Ownership, &copy)
		} else {
			state.Ownership = append(state.Ownership, nil)
		}
	}
	for _, ref := range selection.DefaultPrivileges {
		if stateValue, exists := snapshot.DefaultPrivileges[defaultPrivilegeKey(ref.Owner, ref.ObjectType, ref.Grantee)]; exists {
			copy := stateValue
			state.DefaultPrivileges = append(state.DefaultPrivileges, &copy)
		} else {
			state.DefaultPrivileges = append(state.DefaultPrivileges, nil)
		}
	}
	for _, name := range selection.Roles {
		if role, exists := snapshot.Roles[name]; exists {
			roleCopy := role
			state.Roles = append(state.Roles, &roleCopy)
		} else {
			state.Roles = append(state.Roles, nil)
		}
	}
	for _, ref := range selection.Memberships {
		if membership, exists := snapshot.Memberships[MembershipKey(ref.Role, ref.Member)]; exists {
			membershipCopy := membership
			state.Memberships = append(state.Memberships, &membershipCopy)
		} else {
			state.Memberships = append(state.Memberships, nil)
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode global state fingerprint: %w", err)
	}
	hash := sha256.Sum256(encoded)
	return &Fingerprint{Hash: fmt.Sprintf("%x", hash), Selection: selection}, nil
}

type authorityState struct {
	Name       string   `json:"name"`
	Superuser  bool     `json:"superuser"`
	CreateRole bool     `json:"createrole"`
	CreateDB   bool     `json:"createdb"`
	AdminRoles []string `json:"admin_roles,omitempty"`
	SetRoles   []string `json:"set_roles,omitempty"`
}

func normalizeSelection(selection *Selection) {
	sort.Strings(selection.Roles)
	sort.Slice(selection.Memberships, func(i, j int) bool {
		if selection.Memberships[i].Role == selection.Memberships[j].Role {
			return selection.Memberships[i].Member < selection.Memberships[j].Member
		}
		return selection.Memberships[i].Role < selection.Memberships[j].Role
	})
	sort.Slice(selection.Ownership, func(i, j int) bool {
		return ownershipKey(selection.Ownership[i].Kind, selection.Ownership[i].Name) < ownershipKey(selection.Ownership[j].Kind, selection.Ownership[j].Name)
	})
	sort.Slice(selection.DefaultPrivileges, func(i, j int) bool {
		return defaultPrivilegeKey(selection.DefaultPrivileges[i].Owner, selection.DefaultPrivileges[i].ObjectType, selection.DefaultPrivileges[i].Grantee) < defaultPrivilegeKey(selection.DefaultPrivileges[j].Owner, selection.DefaultPrivileges[j].ObjectType, selection.DefaultPrivileges[j].Grantee)
	})
}

func MembershipKey(role, member string) string {
	return role + "/" + member
}

func ownershipKey(kind, name string) string {
	return kind + "/" + name
}

func defaultPrivilegeKey(owner, objectType, grantee string) string {
	return owner + "/" + objectType + "/" + grantee
}

func parseRoleConfiguration(entries []string) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	configuration := make(map[string]string, len(entries))
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			configuration[name] = value
		}
	}
	return configuration
}

func inspectOwnership(ctx context.Context, db *sql.DB, object Ownership) (OwnershipState, bool, error) {
	query, args, err := ownershipQuery(object)
	if err != nil {
		return OwnershipState{}, false, err
	}
	state := OwnershipState{Kind: object.Kind, Name: object.Name}
	err = db.QueryRowContext(ctx, query, args...).Scan(&state.Owner, &state.ExtensionOwned)
	if err == sql.ErrNoRows {
		return OwnershipState{}, false, nil
	}
	if err != nil {
		return OwnershipState{}, false, fmt.Errorf("inspect ownership %s: %w", ownershipKey(object.Kind, object.Name), err)
	}
	return state, true, nil
}

func ownershipQuery(object Ownership) (string, []any, error) {
	switch object.Kind {
	case "database":
		return `SELECT pg_get_userbyid(datdba), false FROM pg_catalog.pg_database WHERE datname = $1`, []any{object.Name}, nil
	case "schema":
		return `SELECT pg_get_userbyid(n.nspowner), EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_namespace'::regclass AND d.objid = n.oid AND d.deptype = 'e') FROM pg_catalog.pg_namespace n WHERE n.nspname = $1`, []any{object.Name}, nil
	case "table", "view", "materialized_view", "sequence":
		schema, name, err := splitQualifiedName(object.Name)
		if err != nil {
			return "", nil, err
		}
		kinds := map[string]string{"table": "ARRAY['r','p']", "view": "ARRAY['v']", "materialized_view": "ARRAY['m']", "sequence": "ARRAY['S']"}
		return fmt.Sprintf(`SELECT pg_get_userbyid(c.relowner), EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = ANY(%s)`, kinds[object.Kind]), []any{schema, name}, nil
	case "type":
		schema, name, err := splitQualifiedName(object.Name)
		if err != nil {
			return "", nil, err
		}
		return `SELECT pg_get_userbyid(t.typowner), EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e') FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = $1 AND t.typname = $2`, []any{schema, name}, nil
	case "function", "procedure":
		kind := "f"
		if object.Kind == "procedure" {
			kind = "p"
		}
		return `SELECT pg_get_userbyid(p.proowner), EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' = $1 AND p.prokind = $2`, []any{object.Name, kind}, nil
	default:
		return "", nil, fmt.Errorf("unsupported ownership kind %q", object.Kind)
	}
}

func splitQualifiedName(name string) (string, string, error) {
	schema, object, ok := strings.Cut(name, ".")
	if !ok || schema == "" || object == "" || strings.Contains(object, ".") {
		return "", "", fmt.Errorf("object name %q must be schema-qualified", name)
	}
	return schema, object, nil
}

func inspectDefaultPrivileges(ctx context.Context, db *sql.DB, refs []DefaultPrivilegeRef, destination map[string]DefaultPrivilegeState) error {
	for _, ref := range refs {
		code := map[string]string{"tables": "r", "sequences": "S", "functions": "f", "types": "T", "schemas": "n"}[ref.ObjectType]
		rows, err := db.QueryContext(ctx, `
SELECT x.privilege_type, x.is_grantable
FROM pg_catalog.pg_roles owner_role
LEFT JOIN pg_catalog.pg_default_acl d
  ON d.defaclrole = owner_role.oid AND d.defaclnamespace = 0 AND d.defaclobjtype = $2::"char"
CROSS JOIN LATERAL aclexplode(COALESCE(d.defaclacl, acldefault($2::"char", owner_role.oid))) x
WHERE owner_role.rolname = $1
  AND CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END = $3
ORDER BY x.privilege_type`, ref.Owner, code, ref.Grantee)
		if err != nil {
			return fmt.Errorf("inspect global default privilege %s: %w", defaultPrivilegeKey(ref.Owner, ref.ObjectType, ref.Grantee), err)
		}
		state := DefaultPrivilegeState{Owner: ref.Owner, ObjectType: ref.ObjectType, Grantee: ref.Grantee, Privileges: make(map[string]bool)}
		for rows.Next() {
			var privilege string
			var grantable bool
			if err := rows.Scan(&privilege, &grantable); err != nil {
				rows.Close()
				return fmt.Errorf("scan global default privilege: %w", err)
			}
			state.Privileges[privilege] = grantable
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("inspect global default privilege: %w", err)
		}
		if len(state.Privileges) > 0 {
			destination[defaultPrivilegeKey(ref.Owner, ref.ObjectType, ref.Grantee)] = state
		}
	}
	return nil
}
