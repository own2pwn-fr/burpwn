# Changelog

All notable changes to burpwn are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed — `export session --redact` now scrubs the CAPTURE, not just what burpwn stored
`--redact` used to stop at burpwn's own tables: the auth profiles' tokens and login commands, the
match/replace replacements, an `exec` hook's parameters. Every `Authorization`, `Cookie` and
`Set-Cookie` header the proxy had *recorded*, and every login body it had captured, went into the
bundle in the clear. That was documented, and a test asserted it, so nobody was being lied to — but
"I redacted it" and "I redacted the half you weren't worried about" are not the same sentence in an
operator's head, and the second one is the kind of thing you find out afterwards.

The reason for stopping was that a blob's SHA-256 **is** its deduplication identity, so rewriting a
body invalidates its address, and that `flows_fts` holds a decoded copy of the same text. Both are
true. What re-reading the code changed is the weight of them: redaction has always run on a
**throwaway `VACUUM INTO` copy**, never on the live session, so "this breaks dedup" means "this
breaks dedup in a file we are about to compress and hand away". Restoring the invariant on that copy
is bookkeeping, not surgery — every blob is re-bucketed by the hash of its *scrubbed* bytes, the
lowest id per bucket survives, the references follow, and each surviving row's `sha256` is
recomputed so a later write into the imported session cannot find a hash pointing at different
content. References live in four INTEGER columns and one that is easy to miss:
`ws_messages.payload_blob` stores the blob row id **as TEXT**, and a remap that only walked the
foreign keys would have left websocket payloads resolving to nothing. `flows_fts` is an ordinary
content-carrying fts5 table, so its rows are scrubbed with an `UPDATE` — no rebuild, no dropped
index, `burpwn search` still works on import and no longer finds the token.

One thing had to be measured rather than reasoned about: **deleting a row does not remove its bytes
from the file.** SQLite parks the freed pages on its freelist with the content intact, and zstd
compresses those just as faithfully as the live ones. On a session where 300 request-header blobs
fold onto one, the first token is still literally in the database after redaction, even though no
query returns it. So a redacted export now takes a second `VACUUM INTO` — the file that gets
compressed is rebuilt from the surviving rows only. A test greps the decompressed bundle for the
token rather than querying it, which is the only version of that assertion worth having.

What `--redact` masks now: the value of an `Authorization`, `Proxy-Authorization`, `Cookie`,
`Set-Cookie` or common `X-…-Token` / `X-Api-Key` header, and the value of a `password`-, `token`-,
`api_key`-style parameter in a query string, a form body or a JSON document — in the stored bodies,
in the `requests.path` column and in the search index alike. Plus, on the stored side, the
`burpwn exec` command lines, which carry credentials in their argv exactly like the login commands
already covered.

What it does **not** mask, said plainly because the name invites the opposite assumption: it is a
**shape** matcher, not a secret detector. A token echoed back under a field name nobody would guess,
a session id baked into a URL path segment, a credential inside a binary or compressed body, an
operator's notes and fuzzing payloads — all still in the file. That is a deliberate floor, not an
oversight: a scrubber aggressive enough to catch an unlabelled secret (every long opaque run, which
is what debug reports get) would shred the HTML, JSON and base64 that make a capture worth keeping.
Tests pin both halves — the masked values are grepped for in the bundle bytes *and* in the imported
session, and an unlabelled secret is asserted to survive — so widening or narrowing the claim breaks
a test rather than a promise. The CLI warning, the `--json` envelope and the MCP reply now say all of
this every time, redacted or not; `session_export` used to omit the warning when `redact=true`.

The default is **untouched**: an export is still the session exactly as captured, because that is
what makes it replayable. `--redact` is opt-in, and a redacted bundle is explicitly not a replayable
one — the auth profiles and `exec` hooks are gone by design.

### Added — `export pcap`, and an honest answer to what a pcap of burpwn can even be
`burpwn export pcap` has errored on purpose since 0.2.0. It now writes a **pcapng** that Wireshark,
tshark and tcpdump open: `Follow HTTP stream` works, the HTTP dissector labels the exchanges, and
the websocket dissector lights up after the `101`.

The reason it stayed a stub for four releases is worth stating, because it is the whole design. **A
pcap is a packet format and burpwn has no packets.** The proxy terminates TLS, reassembles the HTTP
layer and stores *messages* — a method, a header block, a decoded body. There is no handshake, no
sequence number, no MTU and no per-packet clock anywhere in the store. So this is not a conversion,
it is a **synthesis**: a plausible wire trace fabricated around the bytes we really have. That is
genuinely useful — it is how a scenario gets handed to Wireshark, to an IDS, to `tshark -z` — and it
is dangerous exactly to the extent that the file can be mistaken for a capture.

**Which is why the format is pcapng and not classic pcap.** Both can hold the same synthetic frames
and both follow a TCP stream. The difference is that a classic pcap has *nowhere to say the file is
manufactured*: its 24-byte header holds a magic, a version, a link type and a snaplen, so the file
simply claims to be a capture and nothing can contradict it. pcapng has options, so the export
stamps the section header with a comment spelling out what was generated, names the interface
`burpwn-synthetic` and describes it as one that was never captured from, and puts a comment on every
fabricated `SYN` — visible in the packet list, not in a README nobody ships alongside the file. The
second reason is the clock: the store keeps **milliseconds**, and pcap's packet header is
microseconds, so a pcap export would pad three zeroes onto every timestamp and imply a precision
that does not exist. pcapng's `if_tsresol` declares millisecond resolution, which is exactly what we
know. The link type is `LINKTYPE_RAW` for the same reason — there was no link layer, so the file
does not invent two MAC addresses for a hop that never existed.

What is real, and what is not:
- **Real**: request and response bytes, websocket payloads and opcodes, client and server addresses
  and ports, and the millisecond timestamps of the request and the response.
- **Invented**: the TCP handshake and teardown, every sequence and acknowledgement number, window
  sizes, IP ids, TTLs, the segmentation (a conventional 1460-byte MSS, 1440 over IPv6) and the
  ordering of packets inside one millisecond.
- **Rewritten**: stored bodies are already decoded — gunzipped, de-chunked — so the captured
  `Content-Length` / `Transfer-Encoding` / `Content-Encoding` headers describe bytes that are not in
  the file. They are dropped and a correct `Content-Length` is written instead. This is the one
  place where the header block on the wire differs from the header block in the store, and without
  it the stream mis-frames and nothing dissects at all.

**What cannot be rendered is left out and counted, never faked.** DNS, raw-TCP and TLS-passthrough
flows have metadata in the store and no bytes; writing invented DNS queries would produce a file
that is worse than no file. They are excluded, and so are flows with no request recorded, with a
per-reason breakdown printed next to the success line and carried in `data.skipped` under `--json`.
HTTP/2 *is* exported — re-encoded as HTTP/1.1, because the HPACK framing was never stored — counted
in `data.h2_as_http1`, and every affected frame carries a comment saying so. Endpoints the store
never recorded are filled from the RFC 5737 documentation ranges, deliberately un-routable so a
placeholder cannot be read as a host that was really contacted, and counted too.

Two smaller decisions. HTTP/1 flows that shared a client socket share one synthetic stream with a
continuous sequence space — `client_addr` is the real client socket, so that grouping is
information, not a guess — while HTTP/2 and websocket flows each get their own, since laying
multiplexed or long-lived traffic on one stream produces interleaved nonsense. And two conversations
are never allowed to collide on one 4-tuple: the loser is given an invented ephemeral port, counted
in `data.synthetic_client_ports`, because a collision is what turns two clean streams into one
broken one in Wireshark.

The command takes the same filters as `export har` (`--workspace`, now by name *or* id, exclusive
with `--group`), plus `--session` and `--force`. Unlike `export har` there is no stdout form — a
pcapng is binary and stdout belongs to the envelope. It defaults to `<session>.pcapng`, is refused
onto an existing file without `--force`, and is refused through a symlink with or without it. No new
dependency: both the pcapng container and the IP/TCP synthesis are written by hand, which is a few
hundred lines for formats this simple. The output is byte-for-byte reproducible for the same input,
which is what makes the tests mean anything — and libpcap itself validates it, via a test that
shells out to `tcpdump` where the machine has it and skips where it does not.

There is deliberately **no `export_pcap` MCP tool**, for the same reason `export har` has none: the
artefact is a binary file for a human's Wireshark, and an agent cannot read it. Archival an agent
*can* act on remains `session_export`.
### Fixed — `exec --json` could write its envelope into an unrelated open file
`write_json_envelope` decided where the `--json` exec envelope goes by asking `fcntl(3, F_GETFD)
>= 0` — *"is descriptor 3 open right now?"* — and, on that answer alone, wrote the envelope there.

That is not the question the fd-3 convention asks. What makes descriptor 3 the envelope channel is
that the CALLER wired one (`burpwn exec --json … 3>envelope.json`, or the pipe the MCP `run_exec`
dup2s into place before exec). Descriptor 3 is also simply the first slot the kernel hands out
after stdio, so in any process that has opened files of its own it is routinely something else
entirely — and burpwn would write a JSON line straight into it. Since SQLite writes with `pwrite`,
its descriptors sit at offset 0, so the envelope landed exactly on page 1: the file stopped being
a database. That is not hypothetical — it is what made two workspace tests look flaky under load.
Any embedder linking `burpwn-cli`, or any caller that keeps a descriptor of its own around, was
exposed to the same thing.

burpwn now records **once, as the first thing `main` does**, whether fd 3 was *inherited*, and only
then treats it as the envelope channel. Nothing else can be mistaken for it later, because the
answer is taken before this process owns a single descriptor. Unprobed — a test binary, an
embedder — means "not ours", and the envelope goes to stderr, exactly as it already did when fd 3
was closed. The documented `3>envelope.json` and the MCP pipe are unaffected: both are inherited.

### Fixed — the auth auto-refresh left a zombie behind on every 401
The daemon spawns `burpwn session auth refresh` when it sees a 401/403 on a host that has an auth
profile, detached with `setsid` so a slow login command can never block the proxy. It then dropped
the child handle and never called `wait()`. `setsid` detaches the child's *session*, not its
parentage: the daemon stays its parent, the kernel keeps the exit status around waiting to be
collected, and the process table gains one `<defunct>` entry per refresh — for the whole life of
the daemon. Against a target that expires tokens on a schedule, that is exactly one zombie per
expiry, forever.

The child is now owned by a task that does an **async** `wait()`, so the property the detachment
buys is untouched: the daemon still never waits on a login command, a task parked on `SIGCHLD`
does. Shutdown is not a race either way — if the runtime goes down first the task is dropped, the
child is reparented to init, and init reaps it. The exit status stops being thrown away too: a
refresh that fails now says so at `WARN` instead of vanishing.

### Fixed — a typo in a match/replace kind made a body rule, silently
`burpwn match-replace add '*.api' heder '^Authorization:.*' 'Authorization: Bearer x'` used to
succeed. `MatchKind::from_db` fell through to `Body` on anything it did not recognise, so the rule
went in — enabled, listed, applied — rewriting *bodies* while the operator believed they had a
header rule. The pattern then never matched anything, and the thing you debug longest is the
rewrite that quietly does nothing.

The kind is now parsed, not guessed. `header|body|url|host` and nothing else, at the point of
entry — the CLI and the MCP `match_replace_add` both refuse an unknown value with `BW-INPUT-001`
and the accepted set in the message, so the correction is in the error. This is the contract
`HookPhase` already had and said so in its doc comment, which named `MatchKind::from_db` as the
counter-example it was deliberately not copying; the two agree now.

On the READ side a stored row is not user input, and refusing to open the store over one is the
wrong trade. A rule whose kind this build cannot decode is **skipped, with a WARN naming its id**,
and every other rule still loads — the same posture the hook refresher takes when it keeps its
previous snapshot rather than applying a half-decoded policy. What it will not do is come back as
a body rule.

`Protocol::from_db` keeps its fallback on purpose: it classifies traffic burpwn *observed*, where
an unknown wire protocol really is best-effort, not a value someone typed.

### Removed — the `intercepts` table, which nothing ever wrote (schema v7)
The schema carried an `intercepts` table since v1, and the store exposed `enqueue_intercept`,
`resolve_intercept`, `list_intercepts` and `pending_intercepts` against it. No production caller
ever touched any of them: the proxy handler parks on a oneshot inside `InterceptController` and
unblocks the instant an operator forwards, edits or drops it. Interception is a **synchronous
decision taken in flight** — nothing about it outlives the flow it belongs to.

So the table was a promise the code never kept. Reading the schema, an intercept history looks
persisted; it never was, and the CLI, the MCP surface and the export bundle all read it exactly
zero times. Nothing wanted it either: an audit trail of "which flows were held" is already
`flows.intercepted`, and replay works off `flows`/`requests`, not off a decision queue. An empty
table sitting in the schema is not neutral — it is where the next feature gets written against a
queue nobody fills.

Schema **v7** drops it. Old files are migrated in place on open; a session bundle exported before
v7 still imports, because staging runs the same migration on the unpacked copy before it is moved
into place.

### Fixed — `flows.intercepted` said "interception was armed", not "this flow was held"
The column was written from `InterceptController::is_enabled()` — the GLOBAL toggle. With a scope
filter set (`intercept scope --host api.target`), every flow captured while interception was on
was flagged as intercepted, including the ones the filter waved straight through untouched. The
one column that is supposed to answer "was this request held?" answered a different question.

It is now written from the actual park decision, enabled **and** in scope, evaluated immediately
before the intercept call — the same condition `intercept()` itself tests.

### Changed — the MCP `compare` tool stops handing over a whole page of diff
`compare` returns the body diff as two lists of lines, one per side. Two HTML pages that differ
share almost no lines, so those lists are routinely thousands of lines long — and unlike every
other reply in the tool surface, that size is set by the *target*, not by anything the caller
asked for. It was the largest remaining token risk in the MCP surface.

The MCP tool now caps them at **200 lines per side**, and never silently: when the cap cuts
anything, the reply carries `body.truncated = { only_in_a: { shown, total }, only_in_b: … }`, with
only the sides that were actually cut, and the object absent entirely when nothing was — like the
`warning` on a raw bundle, a marker that means "there is more" must never appear where there is
not. `max_lines` raises the cap; a **negative** `max_lines` lifts it completely, deliberately not
spelled `0`, so "I did not think about it" and "I want the whole diff" can never be the same
request. The tool description says all of this, because an agent that does not know its diff was
cut will happily conclude things about a body it never saw.

**The `burpwn compare` CLI is untouched**: a human who asked for a diff wants the diff. Capping is
a separate, explicit step applied by the MCP handler, not a change to the diff itself.

### Fixed — a cold cache no longer costs the burst its token
An `exec` hook runs one command at a time for the whole proxy, and the requests that lost that
race were forwarded **un-hooked, immediately**. On a warm TTL cache nobody ever noticed. On a cold
one — the first call of a session, the first call after an expiry — a burst of N concurrent API
requests saw exactly *one* of them get the fresh token and the other N-1 collect a `401`. That is
precisely the scenario the feature exists to cover, and it was the scenario it failed.

A request that loses the claim now **waits for the winner and reads the value out of the cache**
instead of going out bare. It never starts a command of its own, so the single-flight and the
recursion backstop are untouched: still at most one sandbox for the whole proxy, whatever the
arrival rate.

The reason it did not already work this way is real and is preserved. The request doing the
waiting may *be* the running command's own traffic — that is the missing-marker case the backstop
exists for, and the explicit front-end hits it by construction, having no exec id to stamp — in
which case winner and loser block each other. An earlier attempt at an unbounded wait recreated
exactly that deadlock and was caught by the end-to-end test. So the wait is **bounded**:
- at most 5 s, and never more than **half** the hook's own `--timeout` (10 s by default, so the
  ceiling is the full 5 s). Strictly under the winner's budget is the point: a wait that can
  consume the whole timeout starves the winner it is waiting for, and bounds nothing useful.
- waiting is skipped entirely when it provably cannot pay — a hook with `--ttl 0` publishes
  nothing a waiter could read, and a command minting a *different* hook's value is no use either.
  Both fail open on the spot, exactly as before. That is also why the recursion tests still assert
  *milliseconds*, not the bound.
- on expiry the request is forwarded un-hooked and says so at `WARN`, distinguishing "the command
  did not finish in time" from "it finished and cached nothing" (it failed, or its `--extract` did
  not match). Fail-open is still the contract; it just stopped being the *first* answer.

The pathological case therefore degrades from a deadlock to a stall with a ceiling, and the normal
case — which is every burst on a cold cache — now gets what it asked for. Tests: eight concurrent
requests through the live proxy come back with the same token and one command run; the winner
failing makes the losers fail open without re-running anything; and a command whose own re-entrant
traffic waits on itself gives up at the bound with the winner still inside its timeout.

### Changed — output has a shape now, and it depends on who is reading
Every command wrote its output with `println!` and a hard-coded width: 123 of them in
`commands.rs`, thirty-one of which open-coded their own `if json { … } else { … }`. There were two
consequences. A human got columns that only lined up until the first long URL, because `{:>6}` is a
guess and not a measurement. And an **agent** — which reads the same text, since a tool call
captures stdout — paid for column headers, alignment padding, footers and `(no flows)` in tokens,
on every turn it kept the result in context.

The output layer now decides once, at startup, what stdout actually is:
- **A terminal** gets columns measured on the data, headers, semantic colour and a summary footer,
  with the longest column ellipsised so a row never wraps. Colour means something: HTTP status
  classes, the fuzz anomaly gradient, `yes`/`NO` in `doctor`, and the tag colour that has been
  sitting in the `tags` table since v1 colouring precisely nothing.
- **A pipe, a file, or an agent's capture buffer** gets the data and nothing else: one record per
  line, TAB-separated, no header, no footer, no padding, no colour — and no truncation, so the
  value comes out **whole** where a terminal would have cut it. `awk` splits on the tab by default
  and `cut -f` uses it as its delimiter; an empty field is emitted as `-` so column positions never
  shift. An empty listing prints nothing at all rather than `(no flows)`, which is a line a parser
  would otherwise have to know about.
- **`--json` is untouched**: one envelope line on stdout and nothing else. A test now drives the
  real binary to assert exactly that, for both a success and a failure.

This is not "colour when it is a TTY". Colour is the least of it — headers, footers and padding are
comfort a person reads and a program pays for, so what changes between the two modes is the
*structure*. Concretely: `doctor` prints its checks in both modes but keeps the `NOT ready —` line
and the remediation arrows for the terminal (the exit code and the `--json` payload already carry
them); `req replay` drops its `replayed flow 42 -> 200` line and hands over just the response bytes;
`compare` and `decode jwt` come back as rows instead of the re-indented JSON blob they used to print
at a human.
- `NO_COLOR` (present, any value) disables colour; `CLICOLOR_FORCE` (present, not `0`) forces it
  even in a pipe; `COLUMNS` overrides the detected terminal width. Two new direct dependencies,
  `anstyle` and `anstream` — both already in the lockfile via clap, so the build costs nothing.
- The error block on stderr is coloured **only** when stderr is a terminal, and only by adding
  escape codes: piped or redirected it is byte-for-byte the text the README documents and
  `burpwn-error`'s own test asserts.
- Fixed on the way past: the two Intruder tables interpolated `serde_json::Value`s directly, so
  `{:>6}` padded nothing at all (`Display` for a `Value` ignores the formatter width) and a string
  payload printed with its JSON quotes still attached. The ranked results now align, and the
  anomaly score carries the gradient — this is the one listing whose whole point is that the
  outlier is seen before it is read.

### Changed — MCP replies stop charging the agent for nothing
A tool result is not a screen, it is context: whatever comes back is carried for the rest of the
conversation and paid for on every subsequent turn.
- `req_show --raw` sent the request and response **twice** — once decoded, once verbatim. The raw
  form now replaces the decoded `headers`/`body` instead of being added to them, halving the reply
  for the biggest payload in the whole tool surface. The decoded metadata (method, path, status,
  timings) still comes back either way, because that is what the agent branches on without reading
  the bytes.
- Listings drop their `null` members (`req_list`, `group_show`, `fuzz_list`, `fuzz_results`,
  `hook_list`, `tag_list`, `workspace_list`, `match_replace_list`, `session_auth_status`). A null
  costs a key, a colon, four letters and a comma to say exactly what an absent key says; a capture
  full of DNS and raw-TCP flows is mostly nulls, and such a listing shrinks by about a third.
  Nothing is renamed or reshaped — a consumer reading `row.sni` gets `undefined` instead of `null`.
- `fuzz_results` no longer repeats the `attack_id` on every result row: it is the argument the
  caller just passed in.

### Added — hooks: do something to every request, not just rewrite one
Everything burpwn could do to traffic in flight, it did by *substitution*. A match/replace rule
rewrites text that is already in the message, which leaves two holes big enough to walk through.
It cannot **add** — `User-Agent: .*` matches nothing on a client that never sent a User-Agent, and
the session-auth login macro says so in its own source: it can refresh a stale `Authorization`
header but cannot put one on a request that lacks it. And it cannot **run anything**: the one
scenario every authenticated API test needs — mint a token, put it on the request that is waiting,
then let it go — had no expression at all.
- **`burpwn hook add <name> --action <action> [scope] [params]`** installs one action applied by the
  proxy to every message matching its scope, on one phase (`pre-request` or `post-response`). The
  scope is richer than a rule's bare host substring: `--host`, `--method`, `--path` and, on the
  response side, `--status`. The declarative actions are `add-header` (only if absent — the missing
  primitive), `set-header` (add-or-replace), `remove-header`, `set-query-param` and `drop`, and they
  cost exactly what a few string operations cost: no process, no I/O, nothing to schedule.
- **`--action exec`** is the other half: the command runs in the same rootless sandbox as
  `burpwn exec` and the login macro, a one-capture-group `--extract` regex pulls the value out of
  its stdout, and `--inject-header 'Authorization: Bearer {}'` (or `--inject-param`) puts it on the
  waiting request. `--ttl` (default 5 min) reuses the value instead of re-running the command,
  because a sandbox is a whole network namespace and one per request is not a thing anyone wants.
- **A hook can never break the traffic it hooks.** Every `exec` hook has a hard `--timeout` (default
  10 s) and **fails open**: on timeout, on a command that errors, on an `--extract` that does not
  match, the request goes upstream un-hooked and the failure is logged at `WARN`. This is the same
  contract as the blocking intercept's park timeout, and for the same reason — the proxy is on the
  critical path of someone's engagement.
- **The recursion problem is solved twice.** A hook's command talks to the network, so its traffic
  comes back through this proxy and would hit the hook that spawned it. First, the command runs
  under an `exec_id` prefixed `hook:`, which the sandbox front-end stamps into the wire header of
  every connection it opens: any flow carrying it bypasses the engine entirely — every hook, both
  phases. That is a property of the connection, not a timing window, so it cannot be raced. Second,
  as a backstop for the case where the marker is somehow absent, **at most one hook command runs at
  a time for the whole proxy**: a request that would need to start another one never spawns beside
  it — it reads the running command's value or is forwarded un-hooked (see the bounded wait above,
  because waiting *without* a bound is exactly what turns a recursion into a stall). That invariant
  doubles as the single-flight the TTL cache wants — a burst
  of requests on a cold cache mints one value, not one sandbox each. An end-to-end test drives a
  hook whose command makes a real HTTP request through the very proxy running it, and asserts the
  command runs once and the whole thing finishes in milliseconds rather than at the timeout.
- **Response hooks see streamed bodies.** The proxy streams a response straight through whenever
  nothing is in scope to rewrite it, which is what makes SSE and chunked endpoints work; a
  post-response hook now counts as "something in scope", so it actually runs on those instead of
  silently never firing.
- **`burpwn hook test <id> --flow <id>`** replays a hook against a *captured* flow and reports
  `matched` / `changed` / `dropped` with the before and after — no live traffic, no target touched.
  A hook that does not fire is almost always a scope that does not match, and this is how you see
  that instead of inferring it from captures. For an `exec` hook the command really runs, so it also
  answers "does the extraction regex still match what the command prints today".
- **Repeater and Intruder apply the declarative hooks too.** `req replay` and `fuzz` never went
  through the proxy's pipeline, so a hook keeping a token fresh would have been invisible to the two
  commands most likely to be re-sending a request that has gone stale. `exec` hooks are deliberately
  skipped there: those paths have no sandbox, and a 500-request attack must not be 500 commands.
- **Hooks and match/replace coexist, and neither is deprecated.** A rule rewrites what is there; a
  hook does everything else, including putting it there. Hooks run *after* the rules and *before*
  the intercept on both phases, so an operator holding a flow sees exactly what is about to leave.
  The login macro still generates a match/replace rule and is untouched by this change.
- The hook set lives in the daemon as ONE shared engine refreshed every 2 s, so a hook added
  mid-session applies to keep-alive connections that are already open — unlike match/replace rules,
  which are still snapshotted once per connection (now documented where it can be seen).
- **Cost when you have no hooks: one relaxed atomic load.** The whole engine is behind it. Nothing
  allocates, locks, awaits or reads the store on a proxy with no hook configured, and a test pins
  that an empty engine returns without touching the message or reporting a change.
- schema v6: the `hooks` table (phase, host/method/path/status scope, action + JSON parameters,
  order, timeout, TTL). A v5 file migrates in place, touching nothing that was already there. A
  stored hook this build cannot decode fails the whole read (`BW-STORE-006`) instead of being
  skipped: running *part* of a hook set nobody configured is worse than refusing to run it.
- **MCP `hook_add`, `hook_list`, `hook_set_enabled`, `hook_rm`, `hook_test` — 42 tools** now. Their
  descriptions say when to reach for a hook rather than for a one-off edit, and lead with the two
  things a rule cannot do, because that distinction is the whole reason the tool exists.
- New codes `BW-INPUT-013` (no such hook) and `BW-STORE-006` (a stored hook this burpwn cannot
  read). `export session --redact` now also blanks an `exec` hook's command, which carries
  credentials in its argv exactly like a login command does.

### Added — a session fits in one file, and that file opens on another machine
Everything a pentester learns about a target lived in exactly one place: `~/.local/share/burpwn/
sessions/<name>/session.db` on the machine that captured it. There was no way to hand a finished
engagement to a colleague, to archive one before wiping a box, or to pick a session back up on a
different host — short of copying a live SQLite database by hand, which quietly loses whatever the
running daemon has not checkpointed out of the WAL yet. The session was portable in principle (all
the bodies are already inside the store, there is no external payload directory) and unportable in
practice.
- **`burpwn export session [-o <file>] [--redact] [--force]`** writes the whole session to one
  `<name>.burpwn` file: every flow with its bodies, plus the workspaces, groups, tags, notes,
  attacks and match/replace rules. The snapshot is taken with `VACUUM INTO`, so it is
  transactionally consistent and complete **while the daemon keeps writing** — that is the point,
  and it is what a `cp session.db` gets wrong. The file is created `0600` and never overwritten
  without `--force`, and it refuses to be written through a symlink like every other burpwn output.
- **`burpwn session import <file> [--as <name>] [--use]`** opens one as a **new** session. Never a
  merge and never an overwrite: the flow, group, attack and blob ids in a bundle are the bundle's
  own, and renumbering them to fit an existing session is a different and far riskier feature, so a
  name collision comes back as `BW-SESSION-007` telling you to pick `--as <name>`. The name written
  in the bundle is validated like any other untrusted input before it becomes a path. A bundle from
  an older burpwn is migrated on the way in and says so; one from a newer burpwn is refused
  (`BW-STORE-003`) rather than half-read. The `current` pointer only moves if you pass `--use`, and
  the import prints what actually landed — flows, workspaces, groups, tags, notes, attacks.
- **⚠️ A bundle is a credential store, and burpwn says so out loud.** By default the export is RAW:
  it carries `auth_profiles.token`, the `login_cmd` (whose argv routinely holds a password) and
  every `Authorization` / `Cookie` header captured in the traffic — because a session that cannot
  replay identically is not a session you can hand over. Every export prints a warning on stderr
  (in `--json`, the same text rides in the envelope) saying exactly that. `--redact` is opt-in and
  its scope is deliberately narrow and honestly documented: it purges the stored auth tokens, login
  commands and match/replace replacements, and it does **NOT** scrub credentials captured inside
  recorded requests and responses. Scrubbing those would mean rewriting content-addressed,
  deduplicated, compressed blobs — changing the SHA-256 that IS their identity — and rebuilding the
  `flows_fts` rows indexing the same text, to still end up leaking whatever a body happened to
  contain. A narrow promise that holds beats a broad one that holds sometimes. The CA private key is
  never in a bundle.
- **The format is deliberately boring**: `BURPWNBUNDLE` magic, a format byte, then a zstd frame
  containing the SQLite database with one added `bundle_manifest` table (burpwn version, schema
  version, origin session, export time, flow count, a SHA-256 of the exporting install's CA for
  provenance, and the `redacted` flag). No new dependency — the store already compresses blobs with
  zstd — no tar framing, and the payload stays an ordinary database: `zstd -d` and skipping 13 bytes
  is enough to open a bundle by hand. The magic exists so that feeding burpwn a HAR, a tarball or a
  truncated download fails with `BW-SESSION-006` ("this file is not a burpwn session bundle")
  instead of a SQLite parse error much later.
- **MCP `session_export`** (**37 tools** now), so an agent can archive its own work when a piece of
  it is done; its reply is deliberately terse (path, size, flow count, whether it is redacted)
  because every field is context the agent pays for on the next turn. There is intentionally **no
  import tool**: loading a session file that arrived from somewhere else is an operator decision,
  not something an agent should do on its own say-so.
- **New error codes** `BW-SESSION-006` (not a bundle), `BW-SESSION-007` (that session name is
  taken) and `BW-INPUT-012` (the output file exists — pass `--force`), and the symlink guard that
  `export har` had grown is now shared by both exports instead of living in one command.

### Added — flows can be grouped under a name and a description
A session is a flat river of flows. The one thing an agent works hardest to reconstruct — *how
this target authenticates* — had nowhere to live: it ended up as prose in the agent's context,
which the next session does not have, or as a tag, which is a label with no room to say what the
sequence means. The `groups` / `flow_groups` tables have been in the schema since v1, unreachable
from the CLI, the MCP server, or even a public writer method: dead weight nothing could use.
- **`burpwn group new|add|rm-flow|list|show|rm`** — a group is a named, described SUBSET of a
  session's flows, the equivalent of a Burp highlight. `burpwn group new auth-flow --description
  'login form → POST /login → redirect + Set-Cookie session'` then `burpwn group add auth-flow 3 5
  9` pins the reconstructed scenario to a handle; `group show` renders it exactly like `req list`,
  so it can be read back and replayed later. The same move isolates one campaign
  (`xss-fuzz-search-param`) from the thousands of flows around it. Every subcommand takes the
  NAME, supports `--json`, and `group new` is **idempotent** — re-running it returns the same
  group and updates its description, so it is safe to call before every `add` instead of
  branching on existence. Deleting a group deletes the grouping only; the flows stay captured.
- **The group is a first-class filter, not just a view** — `burpwn req list --group auth-flow
  --method POST` composes with every other filter, and `burpwn export har --group auth-flow`
  exports precisely one named scenario (exclusive with `--workspace`, which the group already
  belongs to). That is the point of naming a subset: it becomes the unit you hand to someone else.
- **Five MCP tools** (`group_new`, `group_add`, `group_list`, `group_show`, `group_rm`), bringing
  the server to **36 tools**. Their descriptions tell the model *when* to reach for them — after
  working out an auth sequence, or to fence off a fuzzing campaign — because a tool an agent never
  thinks to call is a tool that does not exist.
- **Schema v5** — `groups` gains `description` and `created_at`, `(workspace_id, name)` becomes
  unique (a name is the handle everything resolves on, so it may not designate two groups in one
  workspace), and `flow_groups` gains the group-side index the membership read needs (its primary
  key is `(flow_id, group_id)`, whose prefix is the wrong way round for "every flow in this
  group"). An existing v4 database migrates in place; because nothing ever enforced uniqueness
  before, same-named groups are folded onto the oldest id — memberships re-pointed — rather than
  failing someone's upgrade.
- **New error code `BW-SESSION-005`** (`no such flow group`), so an unknown group name comes back
  as a branchable code instead of an empty result. Adding a flow id that does not exist fails the
  whole `group add` rather than half-filling the group.

## [0.3.4] - 2026-08-10

### Fixed — an in-place upgrade kept serving traffic from the OLD daemon
`install.sh` replaces the binary on disk, but the `burpwn proxy` daemon started before the upgrade
keeps running from its now-deleted inode (`/proc/<pid>/exe -> … (deleted)`). It answers `Status`
perfectly well, and `ensure_daemon` only ever checked **liveness**, so `exec` adopted it forever:
every request kept being served by the previous build — with the previous build's bugs — under a
`burpwn -V` reporting the new version. Symptom that surfaced this: a freshly installed 0.3.3 still
returned the bare `burpwn: upstream error` that 0.3.3 had just fixed, and the only escape was to
find and kill the process by hand.
- `Status` now carries the **daemon's** version, and `exec` reuses a daemon only on an exact match.
  A mismatched daemon is shut down (under the existing `daemon.lock`, waiting for its control
  socket to stop answering) and respawned from the current binary, with a `WARN` naming both
  versions. A daemon predating the handshake sends no version and reads as stale, so the very
  daemons this bug leaves behind are the ones that get retired.
- The MCP `status` tool reports the daemon version too, so an agent debugging odd behaviour can see
  which build is actually serving its traffic.

## [0.3.3] - 2026-08-06

### Fixed — the proxy's 502 now says WHAT failed
An origin that never answered produced 30 s of silence followed by a bare
`burpwn: upstream error` — indistinguishable, for a human or an agent, from a burpwn bug. The
actual cause (a labelled connect/handshake/header timeout, a TLS error, a refused connection) only
ever reached the daemon's log.
- The synthetic 502 now carries the origin (`host:port`) and the full error chain, e.g.
  `burpwn: upstream error: ipconfig.me:443: upstream connect timed out after 30s`, in the body AND
  in a `burpwn-error` response header (for clients that discard bodies, like `curl -o /dev/null`).
  The header value is sanitised to single-line ASCII and length-bounded, so an origin certificate
  error carrying newlines/UTF-8 cannot break the response.

## [0.3.2] - 2026-08-06

### Fixed — the QUIC fail-fast guard was rejecting the sandbox's own DNS query
`burpwn doctor` went red on **every** host with
`redirect_delivery FAIL — send probe datagram to 192.0.2.1:53: Operation not permitted`, and any
sandbox whose `/etc/resolv.conf` names a **non-loopback** nameserver (WSL's `10.255.255.254`, a
LAN/router resolver, …) resolved nothing and captured ZERO flows. This was misdiagnosed as a WSL
kernel limitation in 0.3.1; it reproduced identically on Fedora 43 / kernel 6.17.
- **Root cause:** the `udpguard` chain (the QUIC/HTTP-3 fail-fast reject) sat at
  `filter hook output priority 0`, i.e. **after** the NAT chain's `dstnat` (-100). By then the
  redirect had rewritten the workload's DNS query to `127.0.0.1:<dns_port>` *while keeping the
  `burp0` output interface*, so `oifname "burp0" udp dport != 53 reject` matched burpwn's own DNS
  traffic and the kernel answered `sendto` with `EPERM`. The ruleset always **loaded** cleanly,
  which is why every string-level test stayed green.
- **Fix:** the guard now runs at `priority -150`, before the redirect, where the packet still
  carries its original `dport 53` — DNS passes, a genuine QUIC datagram to UDP/443 is still
  rejected immediately (verified live). A `udp dport <dns_port> accept` line guards the same
  invariant belt-and-braces.
- **Regression test:** new `--test redirect_delivery_real` (opt-in, `BURPWN_REAL_SANDBOX_TESTS=1`)
  drives the real userns+netns probe end to end. It fails on the 0.3.1 ruleset and passes on this
  one; unit tests additionally pin `udpguard`'s priority below the NAT chain's.

### Fixed — the WSL verdict was printed even when the WSL kernel was fine
`burpwn doctor` and `install.sh` claimed "the Microsoft kernel ships NO loadable modules, so the
`=m` features above can never load … burpwn cannot capture traffic on a stock WSL kernel" under a
report whose `dummy_device`, `nft_redirect` and `nft_reject` steps had all just **passed** — telling
users to rebuild their kernel for a bug that was in burpwn.
- The WSL blurb is now scoped to the steps that actually need a loadable module
  (`dummy_device` / `nft_redirect` / `nft_reject`); other failures get advice matching what broke.
- `install.sh` no longer prints its own blanket WSL verdict (the live doctor report is
  authoritative), and the README now says WSL support depends on the kernel and points at
  `burpwn doctor` instead of declaring WSL unsupported.

## [0.3.1] - 2026-08-05

### Fixed — DNS/redirect delivery inside the sandbox (the "green doctor, ZERO flows" gap)
On some hosts (notably WSL2) `burpwn exec -- curl …` failed with `Could not resolve host` or hung,
then warned `captured ZERO flows`, even though `burpwn doctor` reported everything ready. Root
cause: the sandbox's nftables OUTPUT `redirect` DNATs the workload's traffic to `127.0.0.1` (the
in-netns DNS shim / TCP acceptor), but a freshly-created network namespace defaults
`net.ipv4.conf.*.route_localnet=0` — under which the kernel drops the redirected-to-loopback packet
as *martian*. The ruleset **loaded** (all the diagnostics checked) while it **delivered** nothing.
- **`route_localnet` is now enabled** on the sandbox netns (`all` + `lo`) right after the interface
  setup, so the OUTPUT redirect can actually reach the loopback shim/acceptor. Best-effort with a
  warning on failure; shared with the deep probe so both exercise the identical path.
- **The DNS socket hand-off is no longer silently best-effort.** A failed bind or SCM_RIGHTS
  hand-off of the in-netns DNS socket now surfaces as an explicit `SandboxError::Setup`
  (`dns_bind` / `dns_handoff`) instead of a stderr line swallowed behind the downstream
  "captured ZERO flows" warning.
- **The deep probe now tests end-to-end DELIVERY, not just ruleset loading.** A new required
  `redirect_delivery` step sends a real UDP/53 datagram through the redirect and asserts it lands
  on a loopback listener; on failure `burpwn doctor` now goes red and names the cause
  (missing `nf_nat` runtime / `route_localnet` disabled) instead of printing `=> ready`.

### Notes
- IPv6 destinations inside the sandbox remain v4-only by design (the netns has no v6 route); this
  release does not add v6 egress. It is unrelated to the DNS failure fixed here.

## [0.3.0] - 2026-07-29

### Added — every error is coded, actionable, and leaves a debug report
- **New crate `burpwn-error`**: the error contract. A catalogue of 41 stable
  `BW-<CLASS>-<NNN>` codes, each with a plain-language title and remediation advice; a
  `Diagnostic` type that renders one failure as `code / cause / fix / debug / exit`; and the
  redaction policy for debug reports. All pure logic, unit-tested.
- **Process exit codes by failure class** — `70` sandbox, `71` daemon, `72` store, `73` TLS/CA,
  `74` session, `75` input, `76` agent integration, `77` network, `78` internal. Chosen above
  `0`/`1` and below the shell's reserved `126`/`127`/`128+n`. ⚠️ `burpwn exec` still passes the
  wrapped command's exit code through, so a value in that range from `exec` is disambiguated by
  the `--json` envelope, not by the number alone.
- **Automatic debug reports** (`<data>/debug/<ts>-<code>.json`, last 20 kept), written on every
  failure with the path printed in the message: burpwn version, redacted invocation, kernel /
  distribution / WSL / container detection, sandbox prerequisites, a LIVE sandbox re-probe for
  sandbox failures, and each session's on-disk state. Redacted before writing — env values
  outside an allowlist are dropped and token-shaped strings (JWTs, `Authorization` values, long
  opaque runs) are replaced; captured bodies are never included.
- **`burpwn debug bundle | list | show`** — an on-demand report for bug reports (`-o -` writes it
  to stdout), the reports from past failures, and a printer for one of them.
- **`--json` envelope gains `diagnostic`** — `{code, class, title, message, causes, remediation,
  context, exit_code, debug_report}`. The legacy `error` string is kept and now begins with the
  code, so an existing consumer that only reads that field still shows it.
- **MCP tool errors carry the same diagnostic**: the rendered block as the message and the
  structured object as the error `data`, so an agent branches on `diagnostic.code` instead of
  parsing prose. Previously they were `e.to_string()` — the outermost message only, with the
  cause chain discarded.

### Fixed — failures that were being reported as successes
An exhaustiveness audit of the new error contract found six paths that bypassed it entirely by
printing their own message and returning a success-shaped result:
- **`intercept forward|drop` on an id that names no parked intercept** exited **0** and printed
  "id not found"; in `--json` it came back as `ok: true`. An agent driving `await → forward` had
  no way to notice the forward never happened. Now `BW-INPUT-011` (new code), exit 75.
- **`intercept …` when the daemon answered with an error** exited **0** and printed to stderr;
  in `--json` the daemon's error was wrapped in an `ok: true` envelope. Now `BW-DAEMON-004`.
- **`mcp register` on a config file burpwn cannot edit** reported `action: "Refused"` and exited
  0, leaving the user believing the tools were registered. Now `BW-AGENT-002`.
- **`skill install --agent X` on a file burpwn does not own** likewise reported `Refused` and
  exited 0. Now `BW-AGENT-003` — but only for a single explicit `--agent`, since under `--all` a
  refusal is a legitimate per-target outcome.
- **`exec` when the sandbox preflight fails** and **`export pcap`** printed `error: …` and exited
  1 instead of their class exit code, with no catalogue code and no debug report.
- **A failure to start the async runtime** exited 1 with a bare sentence.

Two regression guards now hold the line: one asserts no command prints `error:` itself instead of
returning an `Err` (the pattern behind five of the six), and one asserts every catalogue code is
actually emitted somewhere — that is what exposed `BW-AGENT-003` as documentation for a failure
that was being reported as a success.

### Changed — no failure reaches the user as a bare sentence
- A single terminal handler in `burpwn-cli` classifies every error chain: an explicit code wins,
  then a typed error from a lower crate that knows its own code (`StoreError`, `TlsError`,
  `SandboxError`, `WrapError`, `SkillError`, `McpRegError` now implement `burpwn_error::Coded`),
  and otherwise `BW-INTERNAL-001`, which the catalogue documents as "this is a bug, report it".
  The fallback is the point: an error nobody annotated still arrives coded, with an exit code and
  a report, rather than degrading to a bare string.
- Every `bail!`/`anyhow!` site across `burpwn-cli` and `burpwn-mcp` (95 of them) now names its
  catalogue code. Sites that discarded a typed error with `map_err(|e| anyhow!("{e}"))` now
  propagate it, so it classifies itself.

### Fixed — a host that cannot sandbox no longer looks like a host that captured nothing
- **`burpwn doctor` now runs a LIVE sandbox probe** (`burpwn-sandbox/probe.rs`): it creates a real
  throwaway userns+netns and executes the production setup sequence inside it (`ip link set lo up`,
  `ip link add burp0 type dummy`, address/route, the nftables REDIRECT ruleset, then `bwrap`),
  reporting which step failed, why, and how to fix it. The previous preflight only checked that
  `ip`/`nft`/`bwrap` were **on PATH**, so it printed `=> ready` on hosts where the kernel cannot
  actually create the sandbox. `--quick` restores the old, binaries-only behaviour.
- **WSL is now diagnosed explicitly.** The WSL2 kernel ships no loadable modules while
  `CONFIG_DUMMY`, `CONFIG_NFT_REDIR` and `CONFIG_NF_REJECT_IPV4` are all `=m` there, so
  `ip link add … type dummy` and the nftables `redirect` expression fail at runtime. Every
  `burpwn exec` then died with an empty `req list` and a misleading "captured ZERO flows —
  is the agent hook rewriting through `burpwn exec`?" warning, which points at the wrong thing.
  `doctor` now detects the WSL kernel and says the sandbox cannot work there, with the two real
  options (custom `=y` kernel via `.wslconfig`, or a real Linux host).
- **`exec` reports sandbox-setup failures as failures** (`SandboxError::Setup`): the in-namespace
  agent now writes a JSON failure record to a host path carried in the `ExecSpec`, so the host
  side can tell "the sandbox never came up" apart from "the command exited non-zero" instead of
  relying on the agent's sentinel exit code. The CLI prints the failing stage, runs the live probe
  for remediation, and states that the command did **not** run captured.

## [0.2.0] - 2026-07-03

This release turns burpwn from a strong capture engine into an offensive
substrate for an AI agent: a native Intruder/fuzzer, Repeater over MCP, response
comparison, encode/decode, session auth handling — plus the engine fixes those
need (streaming bodies, structured WebSocket capture, TLS metadata) and the first
executable evaluation harness for the trained model.

### Added — one-command skill install
- **`burpwn skill install`** (`burpwn-cli`): installs the portable agent skill into each
  framework's **native** format — a skill directory (`SKILL.md`) for Claude Code / Strix, a
  rules file for Cursor (`.cursor/rules/burpwn.mdc`) / Cline (`.clinerules/burpwn.md`), or an
  append into an instructions file (`AGENTS.md` / `GEMINI.md` / `.github/copilot-instructions.md`)
  for Gemini CLI / Codex / Copilot / Antigravity / the generic `agents` fallback. Writes to the
  **project** by default, `--global` for the per-user path, plus `--all`, `--print` and `--force`.
  Idempotent and anti-clobber: re-runs are safe and it only ever rewrites the block it authored.
  `burpwn skill list` / `burpwn skill uninstall --agent <slug>` manage installs.
- **`burpwn mcp register`** (`burpwn-cli`): registers the stdio MCP server in the host's config
  (relative to `HOME`) for the agents that speak MCP — Codex (`~/.codex/config.toml`
  `[mcp_servers.burpwn]`), Copilot CLI (`~/.copilot/mcp-config.json`) and Antigravity
  (`~/.gemini/config/mcp_config.json`); `--global`, `--print`, and `--list` to enumerate hosts.
  Strix (Docker-sandbox shell, no stdio MCP) and HTTP-only cores use the skill + `burpwn exec`
  path instead. The enforced `PreToolUse` auto-capture hook (`burpwn init`) remains a **separate
  opt-in**, not stacked with the skill.

### Added — offensive loop
- **Intruder / `fuzz`** (`burpwn-cli` + `burpwn-mcp`): `fuzz run --flow <id>
  [--position start:end | § markers] [--payload <p> | --payloads <file>] --mode
  sniper|battering-ram|pitchfork|cluster-bomb [--concurrency N] [--delay MS]`
  builds a request template from a stored flow (or `--request <file>`), runs the
  `burpwn-proxy` attack engine through the same replay transport as `req replay`,
  and persists an `attacks` row plus one `attack_results` row per payload. Ctrl-C
  cancels the run. `fuzz list` / `fuzz show <id> [--sort anomaly|status|len]
  [--limit N]` inspect stored attacks. MCP tools `fuzz`, `fuzz_list`,
  `fuzz_results`.
- **Repeater over MCP** (`req_replay`): the CLI `req replay` capability is now an
  MCP tool sharing the same `replay_flow` path (closes the biggest MCP gap).
- **`compare` / diff** (CLI + MCP): structured JSON diff of two flows —
  status-line delta, header add/remove/change, line-based body diff, and a
  reflection check (tokens from flow A's request echoed in flow B's response).
  `--what headers|body|all`.
- **`encode` / `decode`** (CLI + MCP): pure byte transforms — `base64`,
  `base64url`, `url`, `hex`, and `jwt` (decode-only; splits header.payload.
  signature and decodes to JSON without verifying the signature).
- **MCP server** gains 7 offensive tools here — `req_replay`, `fuzz`,
  `fuzz_list`, `fuzz_results`, `compare`, `encode`, `decode` — and 5 more from
  the session-robustness work below, for **31 tools** total (was 19).

### Added — session robustness / integration hardening
- **Intercept scope** (CLI `intercept scope <pattern> [--path P] [--method M]` /
  `intercept scope --clear`; MCP `intercept_scope`): narrows blocking
  interception to a host/path/method so not every flow parks. Wires the proxy's
  previously-dead `InterceptController::set_scope` through a new
  `InterceptSetScope` control-plane message. MCP `intercept_forward` now also
  reaches CLI parity — it can change the parked request's `method`/`path`.
- **Session auth handling** (`session auth set|refresh|status`; MCP
  `session_auth_set`/`_refresh`/`_status`): persist a login command + a
  one-capture-group extraction regex + a `Header: … {} …` injection template
  (schema v4 `auth_profiles` table). `refresh` runs the login command in the
  sandbox, extracts the token, and installs/UPDATES a single match/replace rule
  that injects the fresh header into in-scope requests (idempotent). Best-effort
  AUTO-refresh: the proxy's new `AuthWatcher` signals 401/403 hosts (debounced,
  recursion-safe) and the daemon spawns a refresh.
- **`init --check`** (`init --check [--agent <slug>]`): drives a synthetic
  network command through each agent's `wrap-hook` path and asserts the command
  is actually rewritten to route through `burpwn exec`. Per-agent PASS / FAIL /
  ADVISORY (Cursor/Cline are advisory, never FAIL); exits non-zero if any
  rewrite-capable agent fails, de-risking the best-effort envelope dialects.
- **Capture-completeness telemetry** (schema v4 `execs` table; `session stats`,
  MCP `session_stats`): tracks per-session exec count vs captured-flow count and
  emits a `tracing::warn!` + a `warning` in the `exec` result when a clearly
  network-facing command (curl/wget/…) completes with ZERO new flows (traffic
  likely escaped capture). Conservative classifier (program-position only — no
  false alarms on `ls`/`git`/`grep curl`).
- **Store schema v4**: `auth_profiles` + `execs` tables (idempotent migration).

### Changed — capture engine (`burpwn-proxy`)
- **Streaming response bodies.** Bodies were buffered whole before forwarding,
  which stalled Server-Sent Events, chunked streaming and long-poll until EOF or
  the 120 s upstream timeout, and pinned up to 256 MiB per connection. Forwarding
  is now hybrid: when no intercept is active and no match/replace rule targets the
  host, upstream frames are relayed verbatim while a size-capped (8 MiB) copy is
  tee'd to the store; the full buffer path runs only when a rule actually needs
  the body. Streaming APIs now flow incrementally instead of hanging.
- **Structured WebSocket capture.** Replaced the marker-in-blob hack (which
  prepended `ws-c2s:` into the payload and capped at 256 KiB) with a real RFC 6455
  frame parser (FIN/opcode/mask, unmasking, continuation reassembly, control
  frames). Messages are stored structured via the new `ws_messages` table.
- **TLS/connection metadata.** Flows now record the negotiated TLS version,
  cipher and ALPN, plus a SHA-256 of the origin's leaf certificate.
- **HTTP/3 deterministic downgrade.** `Alt-Svc` is stripped from responses so
  clients don't attempt QUIC (blackholed in the sandbox) and stay on h2/h1
  instead of hanging on the h3 handshake.
- **gRPC visibility.** `application/grpc` length-prefixed framing is deframed for
  the stored/searchable copy.

### Changed — sandbox (`burpwn-sandbox`)
- **Fail-fast QUIC egress.** Non-DNS UDP out of the netns egress interface is now
  `reject`ed (was silently blackholed), so a wrapped `curl --http3` gets an
  immediate port-unreachable and falls back to TCP instead of hanging. DNS is
  spared; falls back to `drop` on kernels without `nf_reject`.
- **Resource limits on wrapped commands.** `RLIMIT_AS` (8 GiB), `RLIMIT_NPROC`
  (4096) and `RLIMIT_CPU` (3600 s) bound a fork bomb or memory hog beyond the
  wall-clock timeout. Generous defaults, all overridable via `BURPWN_RLIMIT_*`.

### Changed — storage (`burpwn-store`)
- **Schema v3**: TLS metadata columns, the `ws_messages` table, the `attacks`/
  `attack_results` tables for correlated fuzz runs, and `idx_flows_exec_id`
  (exec attribution was a full scan). Request headers are now indexed in FTS
  (searchable bearer tokens / `X-` headers), and flow queries gained
  time-range / response-size / header-substring filters plus a raw FTS5 variant.

### Added — tooling
- **Executable eval harness** (`training/eval/`): behavioural evaluation, which
  did not exist — the model was judged on validation loss and eyeballed prompts.
  `harness.py` scores predictions on a held-out split (valid command, correct
  tool, envelope shape, negative handling), with an optional `--live` grader that
  spawns real `burpwn`/`burpwn mcp`. `surface.py --check` derives the real
  CLI/MCP surface from the binary and fails on any drift from the dataset's
  hand-maintained sets.

## [0.1.2] - 2026-06-15

### Fixed
- **Claude Code / Copilot `PreToolUse` hook never actually wrapped commands**
  (`burpwn-cli`): `burpwn wrap-hook` rewrote `tool_input.command` and echoed the
  raw modified document back. Claude Code **ignores** a bare `{"tool_input":{…}}`
  on stdout, so it ran the *original* command — traffic was silently never
  captured. The hook now emits the documented envelope
  (`hookSpecificOutput` + `permissionDecision: "allow"` + `updatedInput`), so the
  rewrite is actually applied. The agent slug is now load-bearing (each agent has
  its own response dialect), not advisory.
- **Gemini CLI `BeforeTool` hook**: now emits its rewrite envelope
  (`{"decision":"allow","hookSpecificOutput":{"tool_input":{…}}}`) instead of the
  raw echo, so Gemini also wraps transparently.
- **Cursor `beforeShellExecution` hook**: Cursor's hook API can only allow/deny —
  it *cannot* rewrite a command. The raw echo was a silent no-op there. burpwn now
  emits a valid non-blocking allow with an `agentMessage` nudge to re-run network
  commands through `burpwn exec` (never a hard block). Cursor capture is advisory,
  like Cline.

### Added
- **Claude Code plugin** (`.claude-plugin/`): the repo is now a single-plugin
  marketplace, so the agent **skill** installs in one step —
  `/plugin marketplace add own2pwn-fr/burpwn` then `/plugin install burpwn@burpwn`
  (the `burpwn` binary must be on `PATH`). The plugin ships the **skill only**: the
  enforced `PreToolUse` auto-capture hook stays a separate opt-in via `burpwn init`,
  so the two integration layers are not stacked. The skill is session-aware and
  selective (it creates a session and wraps only target-facing commands); the hook
  is blunt (wraps every command, no session) — pick one.

## [0.1.1] - 2026-06-13

A fourth, exhaustive security pass (5 parallel audits across every crate) plus the
fixes it surfaced. Build, clippy and the full test suite are green; the live
end-to-end path (`burpwn exec -- curl https://…`, MITM capture, match-replace,
intercept, structured errors) was re-validated against a real rootless sandbox.

### Security
- **Sandbox control-plane isolation** (`burpwn-sandbox`): the per-session run dir
  (`proxy.sock` + `control.sock`) is now masked with a `tmpfs` inside bubblewrap.
  A unix-socket `connect()` is not IP traffic, so the nft egress rules never
  covered it — a wrapped command could previously reach `proxy.sock` to forge
  capture-attribution headers or `control.sock` to drive the daemon. Now neither
  is reachable from inside the sandbox (the in-netns acceptor lives in the agent
  process, outside bwrap, and still reaches `proxy.sock`).
- **Host-secret confinement** (`burpwn-cli`): `burpwn exec` no longer forwards the
  operator's full environment into the sandbox. It now ships only an allowlist
  (`PATH`, `HOME`, `TERM`, `LANG`, `LC_*`, proxy vars, `BURPWN_*`, …); secrets
  such as `AWS_*`, `*_TOKEN`, `*_API_KEY`, `SSH_AUTH_SOCK` are dropped so an
  untrusted wrapped tool with proxy egress cannot exfiltrate them.
- **Capture-bypass on bash** (`burpwn-wrap`): `BURPWN_AUTO=1` auto-capture is now
  zsh-only. On bash the DEBUG-trap could not cancel the typed line, so the command
  ran twice — once captured, once outside the sandbox; bash now stays tip-only.
- **Hook-config clobber** (`burpwn-wrap`): burpwn's own hook is matched by an
  anchored `<bin> wrap-hook --agent` signature instead of a bare `wrap-hook`
  substring, so a user hook merely mentioning that string is no longer
  overwritten/deleted on `init`/`uninstall`.
- **Path-traversal hardening** (`burpwn-cli`/`burpwn-mcp`): `burpwn mcp --session`
  and the `current`-pointer read path now validate the session name; control-plane
  header edits reject CR/LF/NUL (no request-line injection upstream).
- Sandbox: `--new-session` (TTY/TIOCSTI injection), size-capped `/tmp` tmpfs,
  `O_CLOEXEC` handshake/capture pipes, `RLIMIT_CORE=0` on the wrapped command.
- TLS: SNI length-capped before minting a leaf, IP-literal SNI now emits an
  `iPAddress` SAN, CA data dir tightened to `0700` and the key mode re-checked on
  load.

### Fixed
- **Proxy DoS bounds** (`burpwn-proxy`): forwarded request/response bodies are now
  capped (`http_body_util::Limited`, 413/502 on overflow) instead of buffered
  unbounded; added header-read / upstream connect+exchange timeouts; the upstream
  driver task is aborted on cancellation; half-open WebSocket/raw-TCP splices are
  torn down after a drain grace instead of leaking a task forever.
- **Store robustness** (`burpwn-store`): zstd blob decompression is bounded
  (decompression-bomb guard), per-body store size is capped, the read pool
  re-asserts `PRAGMA query_only` on every checkout, and status/port reads use
  checked conversions.
- **Structured errors** (`burpwn-cli`): in `--json` mode a top-level error is now
  emitted as the `{ok:false,data:null,error}` envelope on stdout (an agent always
  parses a structured result) instead of a plain-text `burpwn: …` line.
- DNS replies are dropped when their transaction id does not match the query.

## [0.1.0] - 2026-06-13

### Added
- **Rootless transparent sandbox** (`burpwn-sandbox`): each `burpwn exec` runs a command in its own
  user + network namespace; nftables `REDIRECT` forces all TCP (and UDP/53) to the proxy, bubblewrap
  isolates the filesystem. No root / setuid / host `CAP_NET_ADMIN`. The forked child only does
  signal-safe work then `execve`s a clean `__netns-agent` helper (avoids the multithreaded-fork
  allocator hazard); the in-netns acceptor hands connections to the host proxy via SCM_RIGHTS.
- **Proxy core** (`burpwn-proxy`): peek/classify (TLS / cleartext-HTTP / raw-TCP), HTTP/1.1 + H2 +
  WebSocket capture, transparent TLS-MITM, DNS decode/forward, raw-TCP splice, in-flight match/replace
  and a blocking-intercept primitive. Two front-ends: the transparent SCM_RIGHTS receiver and an
  explicit forward proxy (for tests).
- **TLS-MITM** (`burpwn-tls`): per-install root CA (rcgen), per-SNI leaf cache, rustls resolver,
  validating upstream connector, pinned-host passthrough fallback.
- **Per-session storage** (`burpwn-store`): SQLite (WAL + FTS5), single-writer task off the proxy hot
  path, content-addressed body dedup. FTS search treats the query as a literal phrase.
- **CLI** (`burpwn-cli`): `doctor`, `init`, `ca`, `session`, `exec`, `req list/show/search/replay`,
  `intercept`, `match-replace`, `workspace/tag/note`, `export har`; JSON envelope on fd 3; a per-session
  `burpwn proxy` daemon with a JSON control socket reused by the MCP server.
- **Agent integration** (`burpwn-wrap`): rtk-style command-rewrite hooks (Claude Code/Copilot, Cursor,
  Gemini, Cline) + a global shell hook, routing each command through `burpwn exec`.
- **MCP server** (`burpwn-mcp`): 19 tools over stdio (rmcp), including the `await_intercept` long-poll.
- Validated end-to-end: `burpwn exec -- curl https://example.com/` resolves via the proxy (DNS flows
  captured), the HTTPS request is MITM-decrypted and captured, and `burpwn req list/show` surfaces it.

### Known limitations
- `export pcap` is not yet implemented (errors clearly; use `export har`).
- `req replay` is implemented for cleartext HTTP/1.x; HTTPS/H2 replay is pending.
