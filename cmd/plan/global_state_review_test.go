package plan

import (
	"testing"

	"github.com/pgplex/pgschema/internal/globalstate"
	"github.com/stretchr/testify/require"
)

func TestReviewSuperuserKeepsSchemaExecutionAuthority(t *testing.T) {
	current := globalstate.Snapshot{
		SessionRole: globalstate.RoleState{Name: "postgres", Superuser: true},
		Ownership: map[globalstate.OwnershipRef]globalstate.OwnershipState{
			{Kind: "schema", Name: "managed"}: {Kind: "schema", Name: "managed", Owner: "app_owner"},
		},
	}
	require.Empty(t, schemaExecutionRole(current, "managed"))
}
