package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/peleduri/gop/internal/collect"
)

// exitWarn is gop doctor's exit code when checks warn but none fail.
const exitWarn = 3

// cmdDoctor runs the read-only preflight: token mode, scopes, SSO gaps, rate
// limit, a collect estimate and the predicted not_visible areas.
func (a *app) cmdDoctor(args []string) error {
	fs := a.flags("doctor")
	ent := fs.String("enterprise", "", "enterprise slug, e.g. acme")
	ghURL := fs.String("github-url", "", "REST API root (default https://api.github.com; GHES: https://HOST/api/v3)")
	orgs := fs.String("orgs", "", "comma-separated org logins, as for collect --orgs")
	format := fs.String("format", "text", "text or json")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("doctor", "enterprise", *ent); err != nil {
		return err
	}
	f := strings.ToLower(*format)
	if f != "text" && f != "json" {
		return usagef("doctor: --format must be text or json, got %q", *format)
	}
	token := a.getenv("GITHUB_TOKEN")
	if token == "" {
		token = a.getenv("GH_TOKEN")
	}
	if token == "" {
		return usagef("doctor: set GITHUB_TOKEN (or GH_TOKEN); gop never takes a token as a flag")
	}
	now := a.now
	if now == nil {
		now = time.Now
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := collect.Doctor(ctx, collect.DoctorConfig{
		Enterprise: *ent,
		Token:      token,
		Orgs:       splitList(*orgs),
		BaseURL:    *ghURL,
		GraphQLURL: graphQLURL(*ghURL),
		Now:        now,
	})
	if err != nil {
		return errors.New(scrub(err.Error(), token))
	}
	if f == "json" {
		err = writeJSON(a.stdout, rep)
	} else {
		err = collect.WriteDoctor(a.stdout, rep)
	}
	if err != nil {
		return err
	}
	switch fails, warns := rep.Counts(); {
	case fails > 0:
		return codeError{exitRuntime, fmt.Errorf("%d checks failed, %d warnings", fails, warns)}
	case warns > 0:
		return codeError{exitWarn, fmt.Errorf("%d warnings", warns)}
	}
	return nil
}

// graphQLURL derives the GraphQL endpoint from a REST root: GHES serves it at
// /api/graphql next to /api/v3. Empty means the client default (REST root + /graphql).
func graphQLURL(rest string) string {
	r := strings.TrimRight(rest, "/")
	if strings.HasSuffix(r, "/api/v3") {
		return strings.TrimSuffix(r, "/v3") + "/graphql"
	}
	return ""
}
