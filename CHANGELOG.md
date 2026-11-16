# Changelog

## 0.2.0

- `mount9p-fuse` ends its session once unmounted from its own mount namespace with no files open,
  even if a copy of the mount in another namespace (a container, a nix build sandbox, `unshare -m`)
  would keep the filesystem alive. It also exits after unmount even while stdin stays open.
- Invalidation requests on stdin can be `inval <id> <percent-encoded path>`, and each one gets a
  reply line on stdout (`ok <id>` or `err <id> <reason>`). Bare paths still work.
- `--writeback` is split into `--writeback-cache` (off by default) and `--write-pipeline` (on by
  default). `--writeback` still sets both.
- `--stall-timeout`: give up and exit when a 9p request goes unanswered this long, instead of
  hanging the mount.
- On 9p transport loss the daemon exits so a supervisor can remount, and with
  `--detach-on-transport-loss` (the default) lazily unmounts first.
- New `fd://N` transport for an already-connected socket.
- New `mount9p-fuse --default-permissions` and `mount9p --cache` options, the `make-shared`
  subcommand, and a short connect retry for local endpoints.
- Fixes: walks of more than 16 names, short `Tread` replies, reuse of in-flight 9p tags, clunking
  fids the server never established, and a deadlock.

## 0.1.0

- Initial release.
