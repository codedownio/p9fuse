# p9fuse

**Mount a remote 9p filesystem locally, over FUSE, without root.**

`p9fuse` is a userspace [9p2000.L](https://ericvh.github.io/9p-rfc/rfc9p2000.u.html) **client and
FUSE bridge**: point it at any 9p2000.L server (`diod`, `nfs-ganesha`, QEMU virtfs, `unpfs`, …) and
it presents the export as an ordinary directory on your machine. It mounts through FUSE's
unprivileged `fusermount3` helper — **no `CAP_SYS_ADMIN`, no kernel module, no `mount(2)`** — while
still speaking full 9p2000.L, so POSIX metadata (`chmod`, ownership, symlinks, `statfs`) round-trips
faithfully. Attribute/entry/negative-lookup caching and write-back pipelining keep it fast over a
network link.

> **Why this exists.** The Rust ecosystem has good 9p *servers* and protocol libraries (rs9p, p9,
> ninep) but, until now, **no maintained client that mounts a remote 9p server over FUSE** — the
> existing options are the privileged in-kernel v9fs client or aging C/Python FUSE clients. `p9fuse`
> fills that gap.

## Features

- **Unprivileged** — mounts via FUSE, so no `CAP_SYS_ADMIN` and no privileged `mount(2)`.
- **Full 9p2000.L fidelity** — `chmod`/uid/gid/symlinks/`statfs` all work (the reason to prefer 9p
  over, say, WebDAV, which has no notion of a POSIX mode).
- **Pluggable transports** — TCP, Unix socket, or WebSocket out of the box; bring your own by
  implementing one trait.
- **Fast** — kernel attribute/entry caching with tunable TTLs, negative-dentry caching, and
  pipelined write-back turn latency-bound workloads into throughput-bound ones.
- **Out-of-band cache invalidation** — feed it a stream of changed paths and it drops them from the
  kernel cache, so you can cache aggressively *and* stay coherent when the backing store changes.
- **Pure Rust** — `fuser` is built without the libfuse C linkage, so there are no C build inputs.

## Install

```sh
cargo add p9fuse          # library
cargo install p9fuse      # `p9fuse` CLI
```

Requires `fusermount3` (package `fuse3` on most distros) at runtime.

## Quickstart

Start a 9p server — e.g. `diod` exporting a directory over TCP:

```sh
diod -f -e /srv/export -l 0.0.0.0:564 --no-auth
```

Mount it, unprivileged, via FUSE:

```sh
p9fuse mount9p-fuse --connect tcp://127.0.0.1:564 --aname /export /mnt/export
# now /mnt/export is the server's /srv/export -- ls, edit, chmod, all work
```

Other transports select by URL scheme:

```sh
p9fuse mount9p-fuse --connect unix:///run/diod.sock            /mnt/export
p9fuse mount9p-fuse --connect ws://gateway/9p --header "Authorization: Bearer $TOKEN" /mnt/export
```

There's also a `mount9p` subcommand that drives the **kernel** v9fs client over the same transports
(faster, but needs `CAP_SYS_ADMIN` and the `9p` kernel modules) — handy when you have privilege and
want the in-kernel client but still need to tunnel 9p over, say, a websocket.

### As a library

```rust
use std::path::Path;
use p9fuse::{mount, Tuning, TcpTransport};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let transport = Box::new(TcpTransport::connect("127.0.0.1:564").await?);
mount(transport, Path::new("/mnt/export"), 512_000, /*uid*/ 1000, "/export", Tuning::default()).await?;
# Ok(()) }
```

The lower-level [`NineClient`] is a standalone async 9p2000.L client if you only want protocol access
without a mount.

## Tuning

The caching / write-back knobs (all exposed as CLI flags and on [`Tuning`]) trade cache coherence for
throughput. They're safe whenever your process is the **sole** 9p client of the export; relax them if
multiple clients write concurrently.

| Knob | Default | Effect |
|---|---|---|
| `attr_ttl` | 60s | How long the kernel trusts a cached `getattr`. `0` = round-trip every stat. |
| `entry_ttl` | 60s | How long the kernel trusts a cached name→inode lookup. |
| `negative_ttl` | 5s | Cache "no such file" lookups (skip round-trips on `$PATH`/include probes). |
| `writeback` | on | Pipeline writes via the FUSE writeback cache instead of one round-trip per write. |
| `wb_depth` | 16 | Max in-flight `Twrite`s per open file when write-back is on. |
| `readdirplus` | off | Prefetch entry attrs on `readdir`. Off by default — usually net-negative. |

## Custom transports

A transport is just an ordered, reliable, bidirectional stream of byte chunks (9p is self-framing, so
chunk boundaries don't matter). Implement one method:

```rust
use p9fuse::transport::{ByteSink, ByteStream, NineTransport};

struct MyTransport { /* ... */ }

impl NineTransport for MyTransport {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream) {
        // return a Sink<Vec<u8>> and a Stream<Item = io::Result<Vec<u8>>>
        # unimplemented!()
    }
}
```

## How it works

```
   your process          p9fuse                         9p server
  ┌───────────┐   FUSE  ┌────────────────────────┐  9p2000.L  ┌────────┐
  │  ls / cat │◀──────▶│ Fuse9p  ⇄  NineClient  │◀─────────▶│  diod  │
  │  chmod …  │  kernel │  (cache,   (tag-muxed  │ transport  │  …     │
  └───────────┘         │  writeback) 9p client) │ (tcp/unix/ │        │
                        └────────────────────────┘   ws)      └────────┘
```

`Fuse9p` implements FUSE's `Filesystem` and translates each VFS callback into 9p2000.L requests on a
tag-multiplexed `NineClient`, which rides a pluggable `NineTransport`. Aggressive kernel caching is
made safe by an invalidation channel that evicts stale entries on demand.

## Status

The test suite mounts a real `diod` export over FUSE (POSIX semantics, rename,
write-back) across the TCP/Unix/WebSocket transports and unit-tests the 9p wire
codec; an `unpfs` (rs9p) interop target is on the roadmap.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
