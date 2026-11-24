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
	orgs := fs.String("orgs", "", "comma-separated org logins, as for collect --orgs")
	format := fs.String("format", "text", "text or json")
	af := addAppFlags(fs)
	uf := addURLFlags(fs, "doctor")
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
	ep, err := uf.resolve(a.getenv)
	if err != nil {
		return err
	}
	cr, err := a.resolveCreds("doctor", af, *uf.useGH, ghHost(ep, a.getenv))
	if err != nil {
		return err
	}
	now := a.now
	if now == nil {
		now = time.Now
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := collect.Doctor(ctx, collect.DoctorConfig{
		Enterprise:       *ent,
		Token:            cr.token,
		AppID:            cr.appID,
		AppPrivateKeyPEM: cr.appKey,
		Orgs:             splitList(*orgs),
		BaseURL:          ep.rest,
		GraphQLURL:       ep.graphql,
		Now:              now,
	})
	if err != nil {
		return errors.New(cr.redact(err.Error()))
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
