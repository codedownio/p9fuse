# diod 1.1.0 — a userspace 9p2000.L server, used by the integration tests (tests/diod_fuse.rs).
#
# Built from source rather than nixpkgs' `diod` because the pinned nixpkgs is still on 1.0.24, which
# predates `Trenameat`/`Tunlinkat` (a 1.0.24 server answers Trenameat with EOPNOTSUPP, so the rename
# tests can't run against it). 1.1.0 is also foreground-by-default and logs to stderr.
#
# Multiuser stays enabled (links libcap) so the server can `setfsuid` per attach; auth (MUNGE) and the
# Lua config file are disabled to keep the closure small, and mount.diod is dropped (unused here).
{ lib
, stdenv
, fetchFromGitHub
, autoreconfHook
, pkg-config
, perl
, ncurses
, libcap
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "diod";
  version = "1.1.0";

  src = fetchFromGitHub {
    owner = "chaos";
    repo = "diod";
    tag = "v${finalAttrs.version}";
    hash = "sha256-Fz+qvgw5ipyAcZlWBGkmSHuGrZ95i5OorLN3dkdsYKU=";
  };

  postPatch = ''
    sed -i configure.ac -e '/git describe/c ${finalAttrs.version})'
  '';

  nativeBuildInputs = [ autoreconfHook pkg-config perl ];
  buildInputs = [ ncurses libcap ];

  configureFlags = [
    "--disable-auth" # no MUNGE auth (drops munge)
    "--disable-config" # no Lua config file (drops lua)
    "--disable-diodmount" # we use the kernel's v9fs mount / FUSE, not the mount.diod helper
  ];

  enableParallelBuilding = true;

  meta = {
    description = "I/O forwarding server implementing 9P2000.L";
    homepage = "https://github.com/chaos/diod";
    license = lib.licenses.gpl2Plus;
    platforms = lib.platforms.linux;
  };
})
