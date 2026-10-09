package globalstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReviewSelfAuthorityRevocationRunsAfterDependentOwnership(t *testing.T) {
	manifest := Manifest{
		Version: 1,
		Roles: []Role{
			{Name: "app_owner", State: StateExternal},
			{
				Name: "deployer", State: StatePresent, Login: true, Inherit: true,
				ConnectionLimit: -1,
			},
		},
		Memberships: []Membership{{Role: "app_owner", Member: "deployer", State: StateAbsent, Inherit: true, Set: true}},
		Ownership:   []Ownership{{Kind: "table", Name: "public.documents", Owner: "app_owner"}},
	}
	current := Snapshot{
		SessionRole: RoleState{Name: "deployer", CreateRole: true},
		SessionAdminRoles: map[string]bool{
			"app_owner": true,
			"deployer":  true,
		},
		SessionSetRoles: map[string]bool{"app_owner": true},
		Roles: map[string]RoleState{
			"app_owner": {Name: "app_owner"},
			"deployer": {
				Name: "deployer", Login: true, Inherit: true, CreateRole: true,
				ConnectionLimit: -1, ValidUntil: "infinity",
			},
		},
		Memberships: map[MembershipRef]MembershipState{
			MembershipKey("app_owner", "deployer"): {Role: "app_owner", Member: "deployer", Admin: false, Inherit: true, Set: true},
		},
		Ownership: map[OwnershipRef]OwnershipState{
			ownershipKey("table", "public.documents"): {Kind: "table", Name: "public.documents", Owner: "deployer"},
		},
	}

	changes, err := PlanChanges(manifest, current, 18)
	require.NoError(t, err)
	require.Len(t, changes, 3)
	require.Equal(t, "ownership", changes[0].Type)
	require.Equal(t, "role_membership", changes[1].Type)
	require.Equal(t, "role", changes[2].Type)
}

func TestReviewRoleLiteralsAreIndependentOfStandardConformingStrings(t *testing.T) {
	manifest := Manifest{Version: 1, Roles: []Role{{
		Name: "app", State: StatePresent, Inherit: true, ConnectionLimit: -1,
		Configuration: map[string]string{"application_name": `path\with'quote`},
	}}}
	current := Snapshot{SessionRole: RoleState{Name: "postgres", Superuser: true}, Roles: map[string]RoleState{}}

	changes, err := PlanChanges(manifest, current, 18)
	require.NoError(t, err)
	require.Contains(t, changes[0].SQL, `E'path\\with''quote'`)
}

func TestReviewManifestRejectsDuplicatePrivileges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
version = 1

[[roles]]
name = "owner"
state = "external"

[[roles]]
name = "reader"
state = "external"

[[default_privileges]]
owner = "owner"
object_type = "tables"
grantee = "reader"
privileges = ["select", "SELECT"]
`), 0o600))

	_, err := LoadManifest(path)
	require.ErrorContains(t, err, "duplicate privilege")
}

func TestReviewManifestRejectsReferencesToAbsentRoles(t *testing.T) {
	tests := map[string]string{
		"ownership": `
version = 1

[[roles]]
name = "retired"
state = "absent"

[[ownership]]
kind = "schema"
name = "public"
owner = "retired"
`,
		"membership": `
version = 1

[[roles]]
name = "retired"
state = "absent"

[[roles]]
name = "active"
state = "external"

[[memberships]]
role = "retired"
member = "active"
`,
		"default privilege": `
version = 1

[[roles]]
name = "retired"
state = "absent"

[[default_privileges]]
owner = "retired"
object_type = "functions"
grantee = "PUBLIC"
state = "absent"
`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "global.toml")
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
			_, err := LoadManifest(path)
			require.ErrorContains(t, err, `role "retired" is declared absent`)
		})
	}
}

func TestReviewAuthorityLookupSupportsSlashInRoleNames(t *testing.T) {
	manifest := Manifest{
		Version: 1,
		Roles: []Role{
			{Name: "owner/with/slash", State: StateExternal},
			{Name: "member", State: StateExternal},
		},
		Memberships: []Membership{{
			Role: "owner/with/slash", Member: "member", State: StatePresent,
			Admin: true, Inherit: true, Set: true,
		}},
	}
	current := Snapshot{
		SessionRole:       RoleState{Name: "deployer", CreateRole: true},
		SessionAdminRoles: map[string]bool{"owner/with/slash": true},
		Roles: map[string]RoleState{
			"owner/with/slash": {Name: "owner/with/slash"},
			"member":           {Name: "member"},
		},
		Memberships: map[MembershipRef]MembershipState{},
	}

	changes, err := PlanChanges(manifest, current, 18)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Contains(t, changes[0].SQL, `"owner/with/slash"`)
}

func TestReviewCompositeKeysDoNotCollideOnSlash(t *testing.T) {
	require.NotEqual(t, MembershipKey("a/b", "c"), MembershipKey("a", "b/c"))
	require.NotEqual(t, ownershipKey("table/a", "b"), ownershipKey("table", "a/b"))
	require.NotEqual(t,
		defaultPrivilegeKey("a/b", "tables", "c"),
		defaultPrivilegeKey("a", "b/tables", "c"),
	)
}
