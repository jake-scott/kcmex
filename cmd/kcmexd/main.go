// Command kcmexd is a single-user KCM (Kerberos Credential Manager)
// daemon compatible with the MIT krb5 client's "KCM:" credential cache
// type. It loads an existing FILE credential cache containing the
// user's TGT, then answers KCM listing queries and RETRIEVE requests
// (performing a real TGS-REQ against the KDC on a cache miss, ignoring
// the client's cache-only flag) over a Unix domain socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jake-scott/kcmex/internal/krb5c"
	"github.com/jake-scott/kcmex/internal/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	uid := os.Getuid()

	var (
		ccachePath = flag.String("ccache", "", "source FILE credential cache to load the TGT from (default: $KRB5CCNAME, or /tmp/krb5cc_<uid>)")
		socketPath = flag.String("socket", defaultSocketPath(uid), "KCM Unix domain socket path to listen on")
		logLevel   = flag.String("log-level", "info", "log level: debug, info, warn, error")
		minLife    = flag.Duration("min-ticket-life", 5*time.Minute, "never hand out a service ticket with less than this much lifetime left; fetch a fresh one instead")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	src, err := resolveCcachePath(*ccachePath, uid)
	if err != nil {
		log.Error("could not determine source ccache", "error", err)
		return 1
	}

	if err := checkOwnedByUID(src, uid); err != nil {
		log.Error("refusing to start", "ccache", src, "error", err)
		return 1
	}

	krb, err := krb5c.Open(src, krb5c.Options{
		MinTicketLife: *minLife,
		OwnerUID:      uid,
		Log:           log,
	})
	if err != nil {
		log.Error("failed to load source ccache", "ccache", src, "error", err)
		return 1
	}
	defer krb.Close()

	if principal, err := krb.DefaultPrincipal(); err == nil {
		attrs := []any{"ccache", src, "principal", principal.UnparseName()}
		if st := krb.TGT(); st.OK {
			attrs = append(attrs, "tgt_expires", st.Expires)
			if !st.RenewUntil.IsZero() {
				attrs = append(attrs, "renew_until", st.RenewUntil)
			}
		}
		log.Info("loaded credentials", attrs...)
	}

	// Background TGT renewal / source-ccache watching. It must be
	// stopped before krb.Close() (deferred above) tears down the context.
	maintCtx, stopMaint := context.WithCancel(context.Background())
	maintDone := make(chan struct{})
	go func() {
		defer close(maintDone)
		krb.Run(maintCtx)
	}()
	defer func() {
		stopMaint()
		<-maintDone
	}()

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o700); err != nil {
		log.Error("failed to create socket directory", "error", err)
		return 1
	}

	l, err := server.Listen(*socketPath)
	if err != nil {
		log.Error("failed to listen", "socket", *socketPath, "error", err)
		return 1
	}
	log.Info("listening", "socket", *socketPath, "uid", uid)

	srv := server.New(krb, strconv.Itoa(uid), uint32(uid), log)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info("shutting down", "signal", sig.String())
		l.Close()
	}()

	if err := srv.Serve(l); err != nil && !isClosedErr(err) {
		log.Error("server exited", "error", err)
		return 1
	}
	return 0
}

func isClosedErr(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && strings.Contains(opErr.Err.Error(), "use of closed network connection")
}

// defaultSocketPath picks a socket location that will not collide with
// any system KCM daemon that might already be running at the
// conventional /var/run/.heim_org.h5l.kcm-socket / MIT default path.
// Point krb5.conf's libdefaults.kcm_socket at this path explicitly to
// use it.
func defaultSocketPath(uid int) string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "kcmex", "kcm.socket")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("kcmex-%d", uid), "kcm.socket")
}

// resolveCcachePath figures out which FILE ccache to load: the -ccache
// flag if given, else $KRB5CCNAME (stripping a "FILE:" prefix if
// present, and rejecting other ccache types since kcmex only reads
// FILE ccaches), else /tmp/krb5cc_<uid>.
func resolveCcachePath(flagVal string, uid int) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("KRB5CCNAME"); env != "" {
		if rest, ok := strings.CutPrefix(env, "FILE:"); ok {
			return rest, nil
		}
		if strings.Contains(env, ":") {
			return "", fmt.Errorf("KRB5CCNAME %q is not a FILE ccache; pass -ccache explicitly", env)
		}
		return env, nil
	}
	return fmt.Sprintf("/tmp/krb5cc_%d", uid), nil
}

// checkOwnedByUID refuses to load a ccache file kcmex's own user does
// not own: kcmex is single-user, and this is a cheap sanity check
// against pointing it at someone else's credentials by mistake.
func checkOwnedByUID(path string, uid int) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // can't verify on this platform; proceed
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("ccache is owned by uid %d, not %d", st.Uid, uid)
	}
	return nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
