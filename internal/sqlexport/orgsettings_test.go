package sqlexport

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// TestOrgSettingsView: org_settings has one row per org with the same
// settings as the report's Org settings table; a setting the token could not
// read, or that was not collected, reads 'unknown'. Loading twice keeps one
// row per org (CREATE VIEW IF NOT EXISTS).
func TestOrgSettingsView(t *testing.T) {
	g, err := graph.LoadFile("../../testdata/hardening/graph.json")
	if err != nil {
		t.Fatal(err)
	}
	delete(g.Nodes[1].Attrs, graph.AttrMembers) // acme-app: members not collected
	db := filepath.Join(t.TempDir(), "gop.db")
	load(t, db, g)
	load(t, db, g)
	rows := query(t, db, "SELECT org, sso, two_factor, ip_allow_list, ip_allow_list_entries, ip_allow_list_apps, "+
		"default_perm, members_create, change_visibility, delete_repos, private_forks, members FROM org_settings ORDER BY org")
	want := []map[string]any{
		{"org": "org:acme-actions", "sso": "configured", "two_factor": "not_required", "ip_allow_list": "off", "ip_allow_list_entries": "0",
			"ip_allow_list_apps": "off", "default_perm": "write", "members_create": "true", "change_visibility": "true",
			"delete_repos": "true", "private_forks": "true", "members": "20"},
		{"org": "org:acme-app", "sso": "enforced", "two_factor": "required", "ip_allow_list": "on", "ip_allow_list_entries": "2",
			"ip_allow_list_apps": "on", "default_perm": "read", "members_create": "false", "change_visibility": "false",
			"delete_repos": "false", "private_forks": "false", "members": "unknown"},
		{"org": "org:acme-legacy", "sso": "none", "two_factor": "not_required", "ip_allow_list": "unknown", "ip_allow_list_entries": "unknown",
			"ip_allow_list_apps": "unknown", "default_perm": "write", "members_create": "true", "change_visibility": "false",
			"delete_repos": "true", "private_forks": "false", "members": "5"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("org_settings =\n%v\nwant\n%v", rows, want)
	}
}
