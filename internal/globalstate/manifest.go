package globalstate

import (
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

type State string

const (
	StatePresent  State = "present"
	StateAbsent   State = "absent"
	StateExternal State = "external"
)

type Manifest struct {
	Version     int          `toml:"version"`
	Roles       []Role       `toml:"roles"`
	Memberships []Membership `toml:"memberships"`
}

type Role struct {
	Name            string `toml:"name"`
	State           State  `toml:"state"`
	Login           bool   `toml:"login"`
	Inherit         bool   `toml:"inherit"`
	CreateDB        bool   `toml:"createdb"`
	CreateRole      bool   `toml:"createrole"`
	Replication     bool   `toml:"replication"`
	BypassRLS       bool   `toml:"bypassrls"`
	ConnectionLimit int    `toml:"connection_limit"`
}

type Membership struct {
	Role    string `toml:"role"`
	Member  string `toml:"member"`
	State   State  `toml:"state"`
	Admin   bool   `toml:"admin"`
	Inherit bool   `toml:"inherit"`
	Set     bool   `toml:"set"`
}

type rawManifest struct {
	Version     int             `toml:"version"`
	Roles       []rawRole       `toml:"roles"`
	Memberships []rawMembership `toml:"memberships"`
}

type rawRole struct {
	Name            string `toml:"name"`
	State           State  `toml:"state"`
	Login           *bool  `toml:"login"`
	Inherit         *bool  `toml:"inherit"`
	CreateDB        *bool  `toml:"createdb"`
	CreateRole      *bool  `toml:"createrole"`
	Replication     *bool  `toml:"replication"`
	BypassRLS       *bool  `toml:"bypassrls"`
	ConnectionLimit *int   `toml:"connection_limit"`
}

type rawMembership struct {
	Role    string `toml:"role"`
	Member  string `toml:"member"`
	State   State  `toml:"state"`
	Admin   *bool  `toml:"admin"`
	Inherit *bool  `toml:"inherit"`
	Set     *bool  `toml:"set"`
}

func LoadManifest(path string) (Manifest, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read global state file: %w", err)
	}

	var raw rawManifest
	metadata, err := toml.Decode(string(contents), &raw)
	if err != nil {
		return Manifest{}, fmt.Errorf("decode global state file: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return Manifest{}, fmt.Errorf("unknown field in global state file: %s", undecoded[0])
	}
	if raw.Version != 1 {
		return Manifest{}, fmt.Errorf("unsupported global state version %d: expected 1", raw.Version)
	}

	manifest := Manifest{Version: raw.Version}
	for _, rawRole := range raw.Roles {
		state := rawRole.State
		if state == "" {
			state = StatePresent
		}
		role := Role{
			Name:            rawRole.Name,
			State:           state,
			Inherit:         valueOr(rawRole.Inherit, true),
			ConnectionLimit: valueOr(rawRole.ConnectionLimit, -1),
			Login:           valueOr(rawRole.Login, false),
			CreateDB:        valueOr(rawRole.CreateDB, false),
			CreateRole:      valueOr(rawRole.CreateRole, false),
			Replication:     valueOr(rawRole.Replication, false),
			BypassRLS:       valueOr(rawRole.BypassRLS, false),
		}
		manifest.Roles = append(manifest.Roles, role)
	}
	for _, rawMembership := range raw.Memberships {
		state := rawMembership.State
		if state == "" {
			state = StatePresent
		}
		manifest.Memberships = append(manifest.Memberships, Membership{
			Role:    rawMembership.Role,
			Member:  rawMembership.Member,
			State:   state,
			Admin:   valueOr(rawMembership.Admin, false),
			Inherit: valueOr(rawMembership.Inherit, true),
			Set:     valueOr(rawMembership.Set, true),
		})
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}

	sort.Slice(manifest.Roles, func(i, j int) bool { return manifest.Roles[i].Name < manifest.Roles[j].Name })
	sort.Slice(manifest.Memberships, func(i, j int) bool {
		if manifest.Memberships[i].Role == manifest.Memberships[j].Role {
			return manifest.Memberships[i].Member < manifest.Memberships[j].Member
		}
		return manifest.Memberships[i].Role < manifest.Memberships[j].Role
	})
	return manifest, nil
}

func valueOr[T any](value *T, fallback T) T {
	if value == nil {
		return fallback
	}
	return *value
}

func validateManifest(manifest Manifest) error {
	roles := make(map[string]struct{}, len(manifest.Roles))
	for _, role := range manifest.Roles {
		if role.Name == "" {
			return fmt.Errorf("global role name must not be empty")
		}
		if role.State != StatePresent && role.State != StateExternal {
			return fmt.Errorf("role %q has unsupported state %q: expected present or external", role.Name, role.State)
		}
		if _, exists := roles[role.Name]; exists {
			return fmt.Errorf("global role %q is declared more than once", role.Name)
		}
		roles[role.Name] = struct{}{}
		if role.ConnectionLimit < -1 {
			return fmt.Errorf("role %q has invalid connection_limit %d", role.Name, role.ConnectionLimit)
		}
	}

	memberships := make(map[string]struct{}, len(manifest.Memberships))
	for _, membership := range manifest.Memberships {
		if membership.Role == "" || membership.Member == "" {
			return fmt.Errorf("membership role and member must not be empty")
		}
		if membership.State != StatePresent && membership.State != StateAbsent {
			return fmt.Errorf("membership %q has unsupported state %q: expected present or absent", MembershipKey(membership.Role, membership.Member), membership.State)
		}
		key := MembershipKey(membership.Role, membership.Member)
		if _, exists := memberships[key]; exists {
			return fmt.Errorf("membership %q is declared more than once", key)
		}
		memberships[key] = struct{}{}
	}
	return nil
}
