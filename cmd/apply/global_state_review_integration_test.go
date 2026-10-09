package apply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	planCmd "github.com/pgplex/pgschema/cmd/plan"
	"github.com/pgplex/pgschema/cmd/util"
	"github.com/pgplex/pgschema/internal/globalstate"
	"github.com/pgplex/pgschema/ir"
	"github.com/pgplex/pgschema/testutil"
	"github.com/stretchr/testify/require"
)

func TestReviewPlanCanAddSetAuthorityForExistingSchemaOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	target := testutil.SetupPostgres(t)
	defer target.Stop()
	admin, host, port, database, _, _ := testutil.ConnectToPostgres(t, target)
	defer admin.Close()

	_, err := admin.ExecContext(ctx, `
CREATE ROLE deployer LOGIN CREATEROLE PASSWORD 'deployer-pass';
SET ROLE deployer;
CREATE ROLE app_owner;
RESET ROLE;
CREATE SCHEMA managed AUTHORIZATION app_owner;
CREATE TABLE managed.documents (id bigint PRIMARY KEY);
ALTER TABLE managed.documents OWNER TO app_owner;
REVOKE ALL ON SCHEMA managed FROM PUBLIC;
`)
	require.NoError(t, err)
	deployer, err := util.Connect(&util.ConnectionConfig{
		Host: host, Port: port, Database: database, User: "deployer", Password: "deployer-pass",
		SSLMode: "disable", ApplicationName: "pgschema-review-schema-owner-test",
	})
	require.NoError(t, err)
	defer deployer.Close()

	majorVersion, err := detectPostgresMajorVersion(deployer)
	require.NoError(t, err)
	dir := t.TempDir()
	schemaFile := filepath.Join(dir, "schema.sql")
	require.NoError(t, os.WriteFile(schemaFile, []byte("CREATE TABLE documents (id bigint PRIMARY KEY, title text);\n"), 0o600))
	options := "admin = true\n"
	if majorVersion >= 16 {
		options += "inherit = false\nset = true\n"
	}
	globalFile := filepath.Join(dir, "global.toml")
	require.NoError(t, os.WriteFile(globalFile, []byte(`
version = 1

[[roles]]
name = "app_owner"
state = "external"

[[roles]]
name = "deployer"
state = "external"

[[memberships]]
role = "app_owner"
member = "deployer"
`+options+`
[[ownership]]
kind = "schema"
name = "managed"
owner = "app_owner"
`), 0o600))

	config := &planCmd.PlanConfig{
		Host: host, Port: port, DB: database, User: "deployer", Password: "deployer-pass",
		Schema: "managed", File: schemaFile, GlobalFile: globalFile,
		ApplicationName: "pgschema-review-schema-owner-test", SSLMode: "disable",
	}
	unauthorizedGlobalFile := filepath.Join(dir, "global-unauthorized.toml")
	require.NoError(t, os.WriteFile(unauthorizedGlobalFile, []byte(`
version = 1

[[roles]]
name = "app_owner"
state = "external"

[[roles]]
name = "deployer"
state = "external"

[[ownership]]
kind = "schema"
name = "managed"
owner = "app_owner"
`), 0o600))
	unauthorizedConfig := *config
	unauthorizedConfig.GlobalFile = unauthorizedGlobalFile
	_, err = planCmd.GeneratePlan(&unauthorizedConfig, sharedEmbeddedPG)
	require.ErrorContains(t, err, `lacks SET authority on schema execution role "app_owner"`)

	migrationPlan, err := planCmd.GeneratePlan(config, sharedEmbeddedPG)
	require.NoError(t, err)
	var titleExists bool
	require.NoError(t, admin.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'managed' AND c.relname = 'documents' AND a.attname = 'title'
)`).Scan(&titleExists))
	require.False(t, titleExists, "planning must not mutate the target")
	require.NoError(t, ApplyMigration(&ApplyConfig{
		Host: host, Port: port, DB: database, User: "deployer", Password: "deployer-pass",
		Schema: "managed", Plan: migrationPlan, AutoApprove: true, Quiet: true,
		ApplicationName: "pgschema-review-schema-owner-test", SSLMode: "disable",
	}, nil))
	require.NoError(t, admin.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'managed' AND c.relname = 'documents' AND a.attname = 'title'
)`).Scan(&titleExists))
	require.True(t, titleExists)
	replan, err := planCmd.GeneratePlan(config, sharedEmbeddedPG)
	require.NoError(t, err)
	require.False(t, replan.HasAnyChanges(), "replan must converge after applying the planned SET relationship and schema DDL:\n%s", replan.HumanColored(false))
}

func TestReviewOwnershipTransferUsesOldOwnerAuthority(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	target := testutil.SetupPostgres(t)
	defer target.Stop()
	admin, host, port, database, _, _ := testutil.ConnectToPostgres(t, target)
	defer admin.Close()
	majorVersion, err := detectPostgresMajorVersion(admin)
	require.NoError(t, err)

	_, err = admin.ExecContext(ctx, `
CREATE ROLE deployer LOGIN NOINHERIT CREATEROLE PASSWORD 'deployer-pass';
CREATE ROLE old_owner;
CREATE ROLE new_owner;
GRANT CREATE ON SCHEMA public TO old_owner;
CREATE TABLE public.documents (id bigint PRIMARY KEY);
ALTER TABLE public.documents OWNER TO old_owner;
`)
	require.NoError(t, err)
	grantOldOwner := "GRANT old_owner TO deployer"
	grantNewOwner := "GRANT new_owner TO deployer WITH ADMIN OPTION"
	if majorVersion >= 16 {
		grantOldOwner += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
		grantNewOwner = "GRANT new_owner TO deployer WITH ADMIN TRUE, INHERIT FALSE, SET TRUE"
	}
	_, err = admin.ExecContext(ctx, fmt.Sprintf("%s;\n%s;", grantOldOwner, grantNewOwner))
	require.NoError(t, err)
	deployer, err := util.Connect(&util.ConnectionConfig{
		Host: host, Port: port, Database: database, User: "deployer", Password: "deployer-pass",
		SSLMode: "disable", ApplicationName: "pgschema-review-owner-transfer-test",
	})
	require.NoError(t, err)
	defer deployer.Close()

	selection := globalstate.Selection{
		Roles:     []string{"deployer", "old_owner", "new_owner"},
		Ownership: []globalstate.Ownership{{Kind: "table", Name: "public.documents", Owner: "new_owner"}},
	}
	snapshot, err := globalstate.Inspect(ctx, deployer, selection, majorVersion)
	require.NoError(t, err)
	manifest := globalstate.Manifest{
		Version: 1,
		Roles: []globalstate.Role{
			{Name: "deployer", State: globalstate.StateExternal},
			{Name: "old_owner", State: globalstate.StateExternal},
			{Name: "new_owner", State: globalstate.StateExternal},
		},
		Memberships: []globalstate.Membership{{
			Role: "new_owner", Member: "old_owner", State: globalstate.StatePresent,
			Admin: false, Inherit: majorVersion < 16, Set: true,
		}},
		Ownership: selection.Ownership,
	}
	_, err = globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.ErrorContains(t, err, `new owner role "new_owner" lacks required CREATE authority`)

	_, err = admin.ExecContext(ctx, `GRANT CREATE ON SCHEMA public TO new_owner`)
	require.NoError(t, err)
	snapshot, err = globalstate.Inspect(ctx, deployer, selection, majorVersion)
	require.NoError(t, err)
	changes, err := globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.NoError(t, err)
	require.Len(t, changes, 2)
	for _, change := range changes {
		_, err = deployer.ExecContext(ctx, change.SQL)
		require.NoError(t, err)
	}
}

func TestReviewPostgres16MultiGrantorMembershipFailsBeforeMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	target := testutil.SetupPostgres(t)
	defer target.Stop()
	admin, _, _, _, _, _ := testutil.ConnectToPostgres(t, target)
	defer admin.Close()
	majorVersion, err := detectPostgresMajorVersion(admin)
	require.NoError(t, err)
	if majorVersion < 16 {
		t.Skip("multiple membership grantors require PostgreSQL 16 or newer")
	}

	_, err = admin.ExecContext(ctx, `
CREATE ROLE app_group;
CREATE ROLE app_login;
CREATE ROLE grantor_one;
CREATE ROLE grantor_two;
GRANT app_group TO grantor_one, grantor_two WITH ADMIN OPTION;
SET ROLE grantor_one;
GRANT app_group TO app_login WITH INHERIT TRUE, SET TRUE;
RESET ROLE;
SET ROLE grantor_two;
GRANT app_group TO app_login WITH INHERIT TRUE, SET TRUE;
RESET ROLE;
`)
	require.NoError(t, err)
	selection := globalstate.Selection{
		Roles:       []string{"app_group", "app_login"},
		Memberships: []globalstate.MembershipRef{{Role: "app_group", Member: "app_login"}},
	}
	snapshot, err := globalstate.Inspect(ctx, admin, selection, majorVersion)
	require.NoError(t, err)
	manifest := globalstate.Manifest{
		Version: 1,
		Roles: []globalstate.Role{
			{Name: "app_group", State: globalstate.StateExternal},
			{Name: "app_login", State: globalstate.StateExternal},
		},
		Memberships: []globalstate.Membership{{
			Role: "app_group", Member: "app_login", State: globalstate.StatePresent,
			Admin: false, Inherit: false, Set: true,
		}},
	}

	_, err = globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.ErrorContains(t, err, "multiple grantors")

	_, err = admin.ExecContext(ctx, `REVOKE app_group FROM app_login GRANTED BY grantor_two`)
	require.NoError(t, err)
	snapshot, err = globalstate.Inspect(ctx, admin, selection, majorVersion)
	require.NoError(t, err)
	manifest.Memberships[0].State = globalstate.StateAbsent
	_, err = globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.ErrorContains(t, err, `foreign grantor "grantor_one"`)
}

func TestReviewDatabaseOwnershipTransferValidatesEffectiveExecutor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	target := testutil.SetupPostgres(t)
	defer target.Stop()
	admin, host, port, database, _, _ := testutil.ConnectToPostgres(t, target)
	defer admin.Close()
	majorVersion, err := detectPostgresMajorVersion(admin)
	require.NoError(t, err)

	_, err = admin.ExecContext(ctx, `
CREATE ROLE deployer LOGIN CREATEDB CREATEROLE PASSWORD 'deployer-pass';
CREATE ROLE old_owner;
CREATE ROLE new_owner CREATEDB;
`)
	require.NoError(t, err)
	grantOldOwner := "GRANT old_owner TO deployer"
	grantNewOwner := "GRANT new_owner TO deployer WITH ADMIN OPTION"
	grantTransition := "GRANT new_owner TO old_owner"
	if majorVersion >= 16 {
		grantOldOwner += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
		grantNewOwner = "GRANT new_owner TO deployer WITH ADMIN TRUE, INHERIT FALSE, SET TRUE"
		grantTransition += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
	}
	_, err = admin.ExecContext(ctx, fmt.Sprintf("%s;\n%s;\n%s;", grantOldOwner, grantNewOwner, grantTransition))
	require.NoError(t, err)
	_, err = admin.ExecContext(ctx, `CREATE DATABASE review_owned_db OWNER old_owner`)
	require.NoError(t, err)

	deployer, err := util.Connect(&util.ConnectionConfig{
		Host: host, Port: port, Database: database, User: "deployer", Password: "deployer-pass",
		SSLMode: "disable", ApplicationName: "pgschema-review-database-owner-test",
	})
	require.NoError(t, err)
	defer deployer.Close()
	selection := globalstate.Selection{
		Roles: []string{"deployer", "old_owner", "new_owner"},
		Ownership: []globalstate.Ownership{{
			Kind: "database", Name: "review_owned_db", Owner: "new_owner",
		}},
	}
	manifest := globalstate.Manifest{
		Version: 1,
		Roles: []globalstate.Role{
			{Name: "deployer", State: globalstate.StateExternal},
			{Name: "old_owner", State: globalstate.StateExternal},
			{Name: "new_owner", State: globalstate.StateExternal},
		},
		Ownership: selection.Ownership,
	}
	snapshot, err := globalstate.Inspect(ctx, deployer, selection, majorVersion)
	require.NoError(t, err)
	_, err = globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.ErrorContains(t, err, `current owner role "old_owner" lacks CREATEDB`)

	_, err = admin.ExecContext(ctx, `ALTER ROLE old_owner CREATEDB`)
	require.NoError(t, err)
	snapshot, err = globalstate.Inspect(ctx, deployer, selection, majorVersion)
	require.NoError(t, err)
	changes, err := globalstate.PlanChanges(manifest, snapshot, majorVersion)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Contains(t, changes[0].SQL, `SET ROLE old_owner; ALTER DATABASE review_owned_db OWNER TO new_owner; RESET ROLE`)
}

func TestReviewSchemaOwnershipTransferUsesEffectiveExecutorCreateAuthority(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	tests := []struct {
		name              string
		createRole        string
		wantPlanningError bool
	}{
		{name: "current owner has CREATE", createRole: "old_owner"},
		{name: "only new owner has CREATE", createRole: "new_owner", wantPlanningError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			target := testutil.SetupPostgres(t)
			defer target.Stop()
			admin, host, port, database, _, _ := testutil.ConnectToPostgres(t, target)
			defer admin.Close()
			majorVersion, err := detectPostgresMajorVersion(admin)
			require.NoError(t, err)

			_, err = admin.ExecContext(ctx, `
CREATE ROLE deployer LOGIN NOINHERIT CREATEROLE PASSWORD 'deployer-pass';
CREATE ROLE old_owner NOINHERIT;
CREATE ROLE new_owner NOINHERIT;
CREATE SCHEMA managed AUTHORIZATION old_owner;
CREATE TABLE managed.documents (id bigint PRIMARY KEY);
ALTER TABLE managed.documents OWNER TO old_owner;
`)
			require.NoError(t, err)
			_, err = admin.ExecContext(ctx, fmt.Sprintf(
				"REVOKE CREATE ON DATABASE %s FROM PUBLIC, old_owner, new_owner; GRANT CREATE ON DATABASE %s TO %s",
				ir.QuoteIdentifier(database), ir.QuoteIdentifier(database), ir.QuoteIdentifier(tt.createRole),
			))
			require.NoError(t, err)
			grantOldOwner := "GRANT old_owner TO deployer"
			grantNewOwner := "GRANT new_owner TO deployer"
			grantTransition := "GRANT new_owner TO old_owner"
			if majorVersion >= 16 {
				grantOldOwner += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
				grantNewOwner += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
				grantTransition += " WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
			}
			_, err = admin.ExecContext(ctx, fmt.Sprintf("%s;\n%s;\n%s;", grantOldOwner, grantNewOwner, grantTransition))
			require.NoError(t, err)

			dir := t.TempDir()
			schemaFile := filepath.Join(dir, "schema.sql")
			require.NoError(t, os.WriteFile(schemaFile, []byte("CREATE TABLE documents (id bigint PRIMARY KEY);\n"), 0o600))
			globalFile := filepath.Join(dir, "global.toml")
			membershipOptions := ""
			if majorVersion >= 16 {
				membershipOptions = "inherit = false\nset = true\n"
			}
			require.NoError(t, os.WriteFile(globalFile, []byte(fmt.Sprintf(`
version = 1

[[roles]]
name = "deployer"
state = "external"

[[roles]]
name = "old_owner"
state = "external"

[[roles]]
name = "new_owner"
state = "external"

[[memberships]]
role = "old_owner"
member = "deployer"
%s
[[memberships]]
role = "new_owner"
member = "deployer"
%s
[[memberships]]
role = "new_owner"
member = "old_owner"
%s
[[ownership]]
kind = "schema"
name = "managed"
owner = "new_owner"
`, membershipOptions, membershipOptions, membershipOptions)), 0o600))
			config := &planCmd.PlanConfig{
				Host: host, Port: port, DB: database, User: "deployer", Password: "deployer-pass",
				Schema: "managed", File: schemaFile, GlobalFile: globalFile,
				ApplicationName: "pgschema-review-schema-create-authority-test", SSLMode: "disable",
			}
			migrationPlan, err := planCmd.GeneratePlan(config, sharedEmbeddedPG)
			if tt.wantPlanningError {
				require.ErrorContains(t, err, `current owner role "old_owner" lacks required CREATE authority`)
				var owner string
				require.NoError(t, admin.QueryRowContext(ctx,
					`SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname = 'managed'`,
				).Scan(&owner))
				require.Equal(t, "old_owner", owner)
				return
			}
			require.NoError(t, err)
			require.NoError(t, ApplyMigration(&ApplyConfig{
				Host: host, Port: port, DB: database, User: "deployer", Password: "deployer-pass",
				Schema: "managed", Plan: migrationPlan, AutoApprove: true, Quiet: true,
				ApplicationName: "pgschema-review-schema-create-authority-test", SSLMode: "disable",
			}, nil))
			var owner string
			require.NoError(t, admin.QueryRowContext(ctx,
				`SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname = 'managed'`,
			).Scan(&owner))
			require.Equal(t, "new_owner", owner)
		})
	}
}
