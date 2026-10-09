package globalstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/lib/pq"
)

type RoleState struct {
	Name            string `json:"name"`
	Login           bool   `json:"login"`
	Inherit         bool   `json:"inherit"`
	CreateDB        bool   `json:"createdb"`
	CreateRole      bool   `json:"createrole"`
	Replication     bool   `json:"replication"`
	BypassRLS       bool   `json:"bypassrls"`
	ConnectionLimit int    `json:"connection_limit"`
}

type MembershipState struct {
	Role    string `json:"role"`
	Member  string `json:"member"`
	Admin   bool   `json:"admin"`
	Inherit bool   `json:"inherit"`
	Set     bool   `json:"set"`
}

type Snapshot struct {
	Roles       map[string]RoleState
	Memberships map[string]MembershipState
}

type MembershipRef struct {
	Role   string `json:"role"`
	Member string `json:"member"`
}

type Selection struct {
	Roles       []string        `json:"roles"`
	Memberships []MembershipRef `json:"memberships"`
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
	for role := range roleNames {
		selection.Roles = append(selection.Roles, role)
	}
	for _, membership := range manifest.Memberships {
		roleNames[membership.Role] = struct{}{}
		roleNames[membership.Member] = struct{}{}
		selection.Memberships = append(selection.Memberships, MembershipRef{Role: membership.Role, Member: membership.Member})
	}
	normalizeSelection(&selection)
	return selection
}

func Inspect(ctx context.Context, db *sql.DB, selection Selection, majorVersion int) (Snapshot, error) {
	normalizeSelection(&selection)
	snapshot := Snapshot{
		Roles:       make(map[string]RoleState),
		Memberships: make(map[string]MembershipState),
	}
	if len(selection.Roles) > 0 {
		rows, err := db.QueryContext(ctx, `
SELECT rolname, rolcanlogin, rolinherit, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls, rolconnlimit
FROM pg_catalog.pg_roles
WHERE rolname = ANY($1)
ORDER BY rolname`, pq.Array(selection.Roles))
		if err != nil {
			return Snapshot{}, fmt.Errorf("inspect global roles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var role RoleState
			if err := rows.Scan(&role.Name, &role.Login, &role.Inherit, &role.CreateDB, &role.CreateRole, &role.Replication, &role.BypassRLS, &role.ConnectionLimit); err != nil {
				return Snapshot{}, fmt.Errorf("scan global role: %w", err)
			}
			snapshot.Roles[role.Name] = role
		}
		if err := rows.Err(); err != nil {
			return Snapshot{}, fmt.Errorf("inspect global roles: %w", err)
		}
	}

	if len(selection.Memberships) == 0 {
		return snapshot, nil
	}
	options := "m.admin_option, true AS inherit_option, true AS set_option"
	if majorVersion >= 16 {
		options = "m.admin_option, m.inherit_option, m.set_option"
	}
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
SELECT granted.rolname, member.rolname, %s
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
JOIN pg_catalog.pg_roles member ON member.oid = m.member
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
	return snapshot, nil
}

func ComputeFingerprint(snapshot Snapshot, selection Selection) (*Fingerprint, error) {
	normalizeSelection(&selection)
	type fingerprintState struct {
		Roles       []*RoleState       `json:"roles"`
		Memberships []*MembershipState `json:"memberships"`
	}
	state := fingerprintState{}
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

func normalizeSelection(selection *Selection) {
	sort.Strings(selection.Roles)
	sort.Slice(selection.Memberships, func(i, j int) bool {
		if selection.Memberships[i].Role == selection.Memberships[j].Role {
			return selection.Memberships[i].Member < selection.Memberships[j].Member
		}
		return selection.Memberships[i].Role < selection.Memberships[j].Role
	})
}

func MembershipKey(role, member string) string {
	return role + "/" + member
}
