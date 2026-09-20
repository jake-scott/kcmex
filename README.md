# kcmex

> [!WARNING]
> This code is purely experimental and was largely coded by an agent.
> DO NOT USE FOR ANY PRODUCTION USE CASE!

`kcmex` is a small, single-user [KCM](https://web.mit.edu/kerberos/krb5-latest/doc/basic/ccache_def.html#ccache-types)
(Kerberos Credential Manager) daemon written in Go. It speaks the KCM protocol
that the MIT krb5 client library uses for its `KCM:` credential cache type, but
instead of acting as a passive credential store it holds your TGT itself and
obtains service tickets on demand.

Any MIT-krb5-linked program pointed at the `kcmex` socket can be issued
Kerberos service tickets without ever having access to the TGT.

## How it works

1. At startup, `kcmexd` reads an existing `FILE:` credential cache (the one
   `kinit` produced) and copies its credentials into a private in-memory cache
   owned by the daemon process.
2. It listens on a Unix domain socket, using the same wire protocol as MIT's
   `KCM:` ccache type. Every connecting peer is checked via `SO_PEERCRED` and
   must run as the same UID as the daemon.
3. When a client asks for a service ticket (`KCM_OP_RETRIEVE`) and the daemon
   does not already have one, it performs a real TGS-REQ against the KDC using
   the TGT it holds, caches the result, and returns the new ticket to the
   client.
4. It keeps the credentials it holds usable over time: service tickets close
   to expiry are discarded and re-fetched rather than handed out, and the TGT
   is renewed before it expires, or replaced by a newer one from the source
   file after the next `kinit`. See [Ticket lifetimes](#ticket-lifetimes).

The key behavioural difference from a normal KCM store is in step 3. MIT's
client sends `RETRIEVE` requests with a "cache only, do not contact the KDC"
flag, expecting to fall back to its own TGT on a miss. `kcmex` deliberately
ignores that flag: the client has no TGT of its own, so the daemon must be the
one to talk to the KDC.

So that this fallback can never happen, the daemon also keeps the TGT out of
reach: it appears in listings (so `klist` shows it) but is handed out without
its session key, and a `RETRIEVE` targeting it is refused. A client therefore
cannot obtain the TGT and drive its own TGS-REQ; it can only ask the daemon for
service tickets. See [Security model](#security-model) for details.

All Kerberos protocol work (parsing the ccache, the TGS exchange, marshalling
credentials) is done by the system's MIT libkrb5 via cgo. `kcmex` implements
only the KCM socket framing and the few small structural encodings MIT does
not expose publicly. No third-party Kerberos implementation is used.

## Requirements

- Linux (the peer-credential check uses `SO_PEERCRED`)
- Go 1.24 or newer, with cgo enabled
- MIT Kerberos 5 development headers and library, discoverable via
  `pkg-config mit-krb5` (`krb5-devel` on Fedora/RHEL, `libkrb5-dev` on
  Debian/Ubuntu)
- A working `krb5.conf` that can reach your KDC

## Building

```sh
go build ./cmd/kcmexd
```

Run the unit tests with:

```sh
go test ./...
```

## Usage

First obtain a TGT into a normal file cache:

```sh
kinit user@EXAMPLE.COM
```

Then start the daemon. With no flags it loads `$KRB5CCNAME` (or
`/tmp/krb5cc_<uid>`) and listens on `$XDG_RUNTIME_DIR/kcmex/kcm.socket`:

```sh
./kcmexd
```

Next, tell the MIT client library where the socket is. MIT krb5 has no
environment variable for this, so it goes in the `[libdefaults]` section of
`krb5.conf` (adjust the UID in the path to your own):

```ini
[libdefaults]
    kcm_socket = /run/user/1000/kcmex/kcm.socket
```

Finally, point the processes that should use the daemon at the `KCM:` cache
type instead of a file:

```sh
export KRB5CCNAME=KCM:
```

You can then verify the setup with the standard tools:

```sh
KRB5CCNAME=KCM: klist
KRB5CCNAME=KCM: kvno host/server.example.com
```

`klist` should list the TGT held by the daemon, and `kvno` should cause the
daemon to fetch and return a new service ticket, which then appears in
subsequent `klist` output.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-ccache` | `$KRB5CCNAME`, else `/tmp/krb5cc_<uid>` | Source `FILE:` credential cache to load the TGT from. A `FILE:` prefix is accepted; other cache types are rejected. |
| `-socket` | `$XDG_RUNTIME_DIR/kcmex/kcm.socket`, else `$TMPDIR/kcmex-<uid>/kcm.socket` | Unix domain socket to listen on. Any stale socket file is removed first, and the new one is created with mode `0600`. |
| `-log-level` | `info` | One of `debug`, `info`, `warn`, `error`. Logs go to stderr. |
| `-min-ticket-life` | `5m` | Never hand a client a service ticket with less than this much lifetime left; discard it and fetch a fresh one instead. Also the point at which the source file is consulted for a newer TGT. |
| `-max-concurrent` | `16` | How many client requests may be served at the same time. Requests beyond this wait for a slot. See [Concurrency](#concurrency). |

The daemon shuts down cleanly on `SIGINT` or `SIGTERM`.

The default socket path is intentionally *not* the conventional
`/var/run/.heim_org.h5l.kcm-socket`, so `kcmex` will not collide with a
system-wide KCM daemon (such as `sssd-kcm`) that may already be running.

## Ticket lifetimes

Service tickets are requested with no explicit end time, so the KDC gives them
the TGT's remaining lifetime (capped by its own maximum). Before answering any
listing or `RETRIEVE` request, and periodically in the background, the daemon
sweeps its working cache and removes service tickets that have expired or have
less than `-min-ticket-life` left, provided the TGT outlives them. The next
request for that service then misses the cache and a fresh ticket is fetched.
A ticket that is short only because the TGT itself is about to expire is kept,
since re-fetching it could not produce a longer one.

The TGT is kept usable in two ways:

1. **A newer TGT from the source file.** Whenever the held TGT needs attention
   (it is due for renewal, within `-min-ticket-life` of expiry, or there is
   none), the daemon re-reads the source `FILE:` cache, re-checks its
   ownership, and adopts its contents if they hold an unexpired TGT that
   outlives the one held. The file is not watched or polled: it is read on
   demand, as requests arrive, and at most once every 5 seconds. Adopting the
   file is treated as a new login session: the working cache is reinitialised
   for the file's principal and service tickets obtained under the old TGT are
   dropped. A file whose TGT is older than, or the same as, the one held (for
   example after the daemon has renewed its own) is left alone.
2. **Renewal.** If the TGT is renewable and its renewable lifetime extends past
   its end time, the daemon renews it at its half-life (the point sssd and
   k5start also use). Renewing early costs nothing, because the renewed ticket
   gets a full new lifetime capped at `renew until`, and it leaves a long
   window to retry if the KDC is unreachable. Failed attempts are retried with
   exponential backoff, from 30 seconds up to 10 minutes, until the TGT
   expires. Renewal is driven by a background loop, not only by requests, so a
   TGT nobody happens to ask about still gets renewed. The renewed TGT replaces
   the old one in place; cached service tickets are kept.

The daemon never writes to the source file, so after a restart it starts from
whatever `kinit` left there, not from a TGT it had renewed itself.

If neither yields a usable TGT, `RETRIEVE` fails with
`KRB5KRB_AP_ERR_TKT_EXPIRED` ("Ticket expired"), the same error a client sees
from an ordinary expired credential cache, and the fix is to run `kinit` again;
the next request picks it up. Listings keep working, so `klist` shows the
expired TGT.

Running `kinit` directly into the `KCM:` cache also works: the client's
`INITIALIZE` clears the working cache and the `STORE` of the new TGT is adopted
by the daemon under the same rules as one loaded from a file.

## Concurrency

Every client connection is served by its own goroutine, and requests from
different clients proceed in parallel: a client waiting on a slow KDC does
not hold up `klist` in another terminal, or a second client asking for a
different service.

Two properties of MIT libkrb5 make this work:

- A `krb5_context` must only be used by one thread at a time, so the daemon
  keeps a pool of them (up to `-max-concurrent`) and each request borrows one.
  Creating a context is cheap (the parsed `krb5.conf` is cached process-wide),
  so the pool fills lazily on demand.
- `MEMORY:` credential caches are process-global, keyed by name, and lock
  each individual operation internally. All the pooled contexts resolve the
  same working cache, so a ticket one request fetches is immediately visible
  to every other, and lookups, stores and iteration from different contexts
  may overlap safely.

A read/write lock on top of that covers only what libkrb5 does not: the
daemon's own bookkeeping, and the few multi-step cache changes whose
half-done state must never be observed (swapping in a renewed or freshly
loaded TGT re-initialises or rewrites the cache). Requests hold it for
reading, including across the TGS exchange, and only those changes take it
for writing. TGT renewal talks to the KDC without holding the lock at all.

Concurrent requests for the same service ticket are coalesced: one TGS-REQ
is sent and every waiting client receives its result, which also keeps the
cache free of duplicate entries (a `MEMORY:` cache appends on store without
looking for an existing match).

## Security model

`kcmex` is single-user by design:

- It refuses to start if the source ccache file is not owned by the UID it
  runs as.
- The socket is created with `0600` permissions.
- Every connection's peer UID is checked with `SO_PEERCRED` and must match the
  daemon's own UID. Connections from any other UID are dropped before a single
  byte of protocol is read.

Cache names sent by clients are accepted without validation, since there is
only one cache; the peer-UID check is the real access boundary.

The TGT's session key never leaves the daemon process. The TGT itself is still
visible to clients so that `klist` and similar tools show it, but it is exposed
without its session key, and any attempt to `RETRIEVE` it (including a
cross-realm TGT) is refused with `KRB5_FCC_PERM`. A ticket-granting ticket is
only useful to whoever holds its session key, since that key is what builds the
authenticator inside a TGS-REQ, so a keyless, non-retrievable TGT cannot be
used by a client to obtain service tickets on its own. Instead, clients receive
only the service tickets they ask for, each fetched by the daemon on their
behalf.

Service tickets are requested as non-renewable. `krb5_get_credentials` copies
the TGT's renewable flag into every TGS request it makes, and a renewable
service ticket can be renewed by whoever holds it and its session key, without
a TGT, until its `renew until` time, which would let a client extend its own
access to a service for days without going through the daemon. The daemon's
working copy of the TGT therefore has the renewable flag cleared, so libkrb5
asks for non-renewable service tickets; the real TGT (with its real flags) is
kept separately for the daemon's own renewals, and listings show the real
flags.

This isolates the TGT from client *processes*, not from the user: a process
running as the same UID can still ask the daemon to retrieve tickets for any
service, and can read the daemon's memory directly (for example via `ptrace` or
`/proc`), so the boundary is enforced at the protocol surface rather than
against a hostile same-UID process.

## Supported KCM operations

| Operation | Behaviour |
| --- | --- |
| `NOOP` | Success. |
| `GEN_NEW`, `GET_DEFAULT_CACHE` | Return the single cache name (the daemon's UID, matching MIT's `KCM:%{uid}` convention). |
| `SET_DEFAULT_CACHE` | Accepted and ignored. |
| `GET_CACHE_UUID_LIST`, `GET_CACHE_BY_UUID` | Report the one cache. |
| `GET_PRINCIPAL` | Return the cache's client principal. |
| `GET_CRED_UUID_LIST`, `GET_CRED_BY_UUID`, `GET_CRED_LIST` | List credentials held in the working cache. UUIDs are derived from a hash of each credential's wire encoding. The TGT is listed, but its session key is stripped from the returned credential (its enctype is kept, so `klist -e` still shows it). |
| `RETRIEVE` | Return a matching credential, performing a TGS-REQ on a miss regardless of the `KCM_GC_CACHED` flag. Stale service tickets are swept first (see [Ticket lifetimes](#ticket-lifetimes)). A request whose target is a ticket-granting ticket (`krbtgt/...`) is refused with `KRB5_FCC_PERM`; one for a ccache config pseudo-entry (`krbtgt/X-CACHECONF:/...`) gets `KRB5_CC_NOTFOUND` without contacting the KDC. Fails with `KRB5KRB_AP_ERR_TKT_EXPIRED` when no valid TGT is held. |
| `STORE` | Store a client-supplied credential into the working cache. A TGT for the cache's own principal becomes the daemon's TGT. |
| `INITIALIZE` | Re-initialise the working cache for a new principal, discarding existing entries, including the TGT. |
| `DESTROY` | Clear all entries (including the TGT) but keep the current principal. A later `STORE` of a TGT, or a TGT in the source ccache, makes the daemon usable again. |
| `REMOVE_CRED` | Remove a matching credential. Match flags are not translated from Heimdal to MIT numbering and are currently ignored. |
| `GET_KDC_OFFSET`, `SET_KDC_OFFSET` | Always report an offset of 0; sets are ignored. |

All other opcodes, including the Heimdal-only NTLM operations and opcodes the
MIT client never sends, are answered with `KRB5_CC_NOSUPP`.

## Known limitations

- Only `FILE:` source caches are supported.
- The in-memory cache is not persisted. Restarting the daemon re-reads the
  source file; tickets obtained, and TGT renewals performed, by the daemon in
  the meantime are lost.
- The source file is only consulted again once the held TGT is due for
  renewal or about to expire. A `kinit` (even as a different principal) while
  the daemon's TGT is still healthy is not picked up until then.
- Address and authdata match hints in `RETRIEVE`/`REMOVE_CRED` requests are
  parsed but not applied.
- `REMOVE_CRED` ignores the request's match flags (see table above).
- Linux only.

## Project layout

```
cmd/kcmexd/         Command-line entry point, flag handling, signal handling
internal/server/    Unix socket listener, peer-UID check, KCM opcode dispatch
internal/kcmproto/  KCM wire protocol: framing, opcodes, principal and
                    match-credential encodings (no Kerberos crypto)
internal/krb5c/     cgo bindings to MIT libkrb5: ccache handling, TGS-REQ,
                    credential marshalling (the only package that touches libkrb5)
```

## References

- MIT krb5 `src/include/kcm.h` and `src/lib/krb5/ccache/cc_kcm.c`, which
  define the KCM protocol as the MIT client implements it.
- MIT krb5 `src/lib/krb5/ccache/ccmarshal.c`, for the credential and
  match-credential encodings.
