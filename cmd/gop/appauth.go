package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// creds is the authentication collect and doctor run with: a token, or GitHub
// App credentials. The App key is read once into memory and never printed.
type creds struct {
	token  string
	appID  int64
	appKey []byte
}

// appFlags registers --app-id and --app-key-file.
type appFlags struct {
	id      *string
	keyFile *string
}

func addAppFlags(fs *flag.FlagSet) appFlags {
	return appFlags{
		id: fs.String("app-id", "", "GitHub App ID for App mode (or GOP_APP_ID); gop mints a read-only installation token per org"),
		keyFile: fs.String("app-key-file", "", "path to the GitHub App private key PEM (or GOP_APP_PRIVATE_KEY with the PEM contents); "+
			"keep it mode 0600"),
	}
}

// resolveCreds picks the token or the App credentials for cmd. Flags win over
// environment variables. A token and App credentials together are a usage
// error, as is half of the App credentials. useGH (--use-gh-auth) and host
// pick the gh login token; see resolveToken for the order.
func (a *app) resolveCreds(cmd string, f appFlags, useGH bool, host string) (creds, error) {
	idText := strings.TrimSpace(*f.id)
	if idText == "" {
		idText = strings.TrimSpace(a.getenv("GOP_APP_ID"))
	}
	keyFile := strings.TrimSpace(*f.keyFile)
	keyEnv := a.getenv("GOP_APP_PRIVATE_KEY")
	if idText == "" && keyFile == "" && keyEnv == "" {
		token, err := a.resolveToken(cmd, useGH, host)
		if err != nil {
			return creds{}, err
		}
		if token == "" {
			return creds{}, usagef("%s: set GITHUB_TOKEN (or GH_TOKEN) to a read-only token, pass --use-gh-auth to use the gh login, "+
				"or use GitHub App mode (--app-id and --app-key-file, or GOP_APP_ID and GOP_APP_PRIVATE_KEY); gop never takes a token as a flag", cmd)
		}
		return creds{token: token}, nil
	}
	if useGH {
		return creds{}, usagef("%s: --use-gh-auth and GitHub App credentials are mutually exclusive; drop one", cmd)
	}
	if a.getenv("GITHUB_TOKEN") != "" || a.getenv("GH_TOKEN") != "" {
		return creds{}, usagef("%s: GITHUB_TOKEN (or GH_TOKEN) and GitHub App credentials are mutually exclusive; unset one", cmd)
	}
	if idText == "" {
		return creds{}, usagef("%s: GitHub App mode needs the App ID: --app-id or GOP_APP_ID", cmd)
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		return creds{}, usagef("%s: the GitHub App ID must be a positive integer", cmd)
	}
	var key []byte
	switch {
	case keyFile != "":
		if key, err = a.readKeyFile(cmd, keyFile); err != nil {
			return creds{}, err
		}
	case keyEnv != "":
		key = []byte(keyEnv)
	default:
		return creds{}, usagef("%s: GitHub App mode needs the private key: --app-key-file or GOP_APP_PRIVATE_KEY", cmd)
	}
	return creds{appID: id, appKey: key}, nil
}

// readKeyFile reads the App key once and warns when group or others can
// read it. Errors name the path only, never the contents.
func (a *app) readKeyFile(cmd, path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading the GitHub App private key file %s: %w", path, unwrapPathErr(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("the GitHub App private key file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&^0o600 != 0 && runtime.GOOS != "windows" {
		fmt.Fprintf(a.stderr, "gop %s: warning: the GitHub App private key file %s has mode %04o, wider than 0600; run chmod 600 %s\n",
			cmd, path, perm, path)
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the GitHub App private key file %s: %w", path, unwrapPathErr(err))
	}
	return key, nil
}

// unwrapPathErr drops the path an *os.PathError repeats.
func unwrapPathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// redact removes the token and every line of the App key from a message,
// defensively: the collector's errors never carry them.
func (c creds) redact(msg string) string {
	msg = scrub(msg, c.token)
	if len(c.appKey) == 0 {
		return msg
	}
	msg = scrub(msg, string(c.appKey))
	for _, line := range strings.Split(string(c.appKey), "\n") {
		if line = strings.TrimSpace(line); len(line) >= 16 {
			msg = scrub(msg, line)
		}
	}
	return msg
}
