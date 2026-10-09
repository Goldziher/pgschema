package globalstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadManifestDefaultsAndRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
version = 1

[[roles]]
name = "app_login"
login = true

[[roles]]
name = "provider_admin"
state = "external"

[[memberships]]
role = "app_group"
member = "app_login"
`), 0o600))

	manifest, err := LoadManifest(path)
	require.NoError(t, err)
	require.Equal(t, Manifest{
		Version: 1,
		Roles: []Role{
			{Name: "app_login", State: StatePresent, Login: true, Inherit: true, ConnectionLimit: -1},
			{Name: "provider_admin", State: StateExternal, Inherit: true, ConnectionLimit: -1},
		},
		Memberships: []Membership{{
			Role: "app_group", Member: "app_login", State: StatePresent, Inherit: true, Set: true,
		}},
	}, manifest)

	require.NoError(t, os.WriteFile(path, []byte("version = 1\nunknown = true\n"), 0o600))
	_, err = LoadManifest(path)
	require.ErrorContains(t, err, "unknown field")
}

func TestPlanChangesCreatesAndAltersRolesBeforeMemberships(t *testing.T) {
	manifest := Manifest{
		Version: 1,
		Roles: []Role{
			{Name: "app_group", State: StatePresent, Inherit: true, ConnectionLimit: -1},
			{Name: "app_login", State: StatePresent, Login: true, Inherit: true, ConnectionLimit: 12},
			{Name: "provider_admin", State: StateExternal, Inherit: true, ConnectionLimit: -1},
		},
		Memberships: []Membership{{
			Role: "app_group", Member: "app_login", State: StatePresent, Admin: false, Inherit: false, Set: true,
		}},
	}
	current := Snapshot{
		Roles: map[string]RoleState{
			"app_login":      {Name: "app_login", Inherit: true, ConnectionLimit: -1},
			"provider_admin": {Name: "provider_admin", Inherit: true, ConnectionLimit: -1},
		},
		Memberships: map[string]MembershipState{},
	}

	changes, err := PlanChanges(manifest, current, 16)
	require.NoError(t, err)
	require.Equal(t, []Change{
		{
			SQL:       `CREATE ROLE app_group WITH NOLOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1`,
			Type:      "role",
			Operation: "create",
			Path:      "app_group",
		},
		{
			SQL:       `ALTER ROLE app_login WITH LOGIN INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 12`,
			Type:      "role",
			Operation: "alter",
			Path:      "app_login",
		},
		{
			SQL:       `GRANT app_group TO app_login WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`,
			Type:      "role_membership",
			Operation: "create",
			Path:      "app_group/app_login",
		},
	}, changes)
}

func TestPlanChangesPostgres15MembershipOptions(t *testing.T) {
	manifest := Manifest{
		Version: 1,
		Roles: []Role{
			{Name: "app_group", State: StateExternal, Inherit: true, ConnectionLimit: -1},
			{Name: "app_login", State: StateExternal, Inherit: true, ConnectionLimit: -1},
		},
		Memberships: []Membership{{
			Role: "app_group", Member: "app_login", State: StatePresent, Admin: false, Inherit: false, Set: true,
		}},
	}
	current := Snapshot{Roles: map[string]RoleState{
		"app_group": {Name: "app_group"},
		"app_login": {Name: "app_login"},
	}}

	_, err := PlanChanges(manifest, current, 15)
	require.ErrorContains(t, err, "PostgreSQL 16 or newer")

	manifest.Memberships[0].Inherit = true
	current.Memberships = map[string]MembershipState{
		MembershipKey("app_group", "app_login"): {Role: "app_group", Member: "app_login", Admin: true, Inherit: true, Set: true},
	}
	changes, err := PlanChanges(manifest, current, 15)
	require.NoError(t, err)
	require.Equal(t, `REVOKE ADMIN OPTION FOR app_group FROM app_login`, changes[0].SQL)
}

func TestPlanChangesValidatesExternalRolesAndLeavesUnmanagedRolesAlone(t *testing.T) {
	manifest := Manifest{
		Version: 1,
		Roles:   []Role{{Name: "provider_admin", State: StateExternal, Inherit: true, ConnectionLimit: -1}},
	}
	current := Snapshot{Roles: map[string]RoleState{
		"unmanaged": {Name: "unmanaged", Login: true},
	}}

	_, err := PlanChanges(manifest, current, 18)
	require.ErrorContains(t, err, `external role "provider_admin" does not exist`)

	current.Roles["provider_admin"] = RoleState{Name: "provider_admin", Login: true}
	changes, err := PlanChanges(manifest, current, 18)
	require.NoError(t, err)
	require.Empty(t, changes)
}

func TestFingerprintIsDeterministicAndScoped(t *testing.T) {
	selection := Selection{
		Roles:       []string{"app_login", "provider_admin"},
		Memberships: []MembershipRef{{Role: "app_group", Member: "app_login"}},
	}
	one := Snapshot{Roles: map[string]RoleState{
		"provider_admin": {Name: "provider_admin", Login: true},
		"app_login":      {Name: "app_login", Login: true},
	}}
	two := Snapshot{Roles: map[string]RoleState{
		"app_login":      {Name: "app_login", Login: true},
		"provider_admin": {Name: "provider_admin", Login: true},
		"unmanaged":      {Name: "unmanaged", Login: false},
	}}

	fingerprintOne, err := ComputeFingerprint(one, selection)
	require.NoError(t, err)
	fingerprintTwo, err := ComputeFingerprint(two, selection)
	require.NoError(t, err)
	require.Equal(t, fingerprintOne, fingerprintTwo)
}
