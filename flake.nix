{
  description = "p9fuse — mount a remote 9p2000.L filesystem locally over FUSE, unprivileged";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    # RustSec security advisories, for the audit check. `nix flake update advisory-db` refreshes it.
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, advisory-db }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # A single toolchain that carries clippy + rustfmt (not in the default nixpkgs cargo/rustc
        # set), so `nix flake check` can run cargoClippy/cargoFmt and `nix develop` has `cargo fmt`
        # / `cargo clippy`.
        rustToolchain = pkgs.symlinkJoin {
          name = "rust-toolchain";
          paths = with pkgs; [ cargo rustc clippy rustfmt ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          # The build is pure Rust: fuser is built without libfuse (it execs `fusermount3`), and
          # tokio-tungstenite is used without TLS -- so there are no C buildInputs.
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        p9fuse = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          # The integration tests (tests/diod_fuse.rs) need /dev/fuse and a real mount, which the nix
          # build sandbox can't provide. They run under `nix develop` in CI instead -- see
          # .github/workflows/ci.yml. (They also skip gracefully when diod/FUSE are unavailable.)
          doCheck = false;
        });

        # Runtime tools the integration tests drive: a 9p2000.L server (diod) and FUSE userspace.
        # diod is built at 1.1.0 (nixpkgs is 1.0.24, which lacks Trenameat -- see nix/diod.nix).
        diod = pkgs.callPackage ./nix/diod.nix { };
        testTools = [ diod pkgs.fuse3 ];
      in
      {
        packages.default = p9fuse;
        packages.p9fuse = p9fuse;

        # `nix flake check` runs all of these: build, clippy (-D warnings), docs (-D warnings),
        # rustfmt, and dependency checks.
        checks = {
          inherit p9fuse;
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings";
          });
          doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
            RUSTDOCFLAGS = "-D warnings";
          });
          fmt = craneLib.cargoFmt { inherit (commonArgs) src; };
          # Licenses, banned crates and crate sources, as configured in deny.toml.
          deny = craneLib.cargoDeny {
            src = ./.;
            cargoDenyChecks = "bans licenses sources";
          };
          # Known security advisories, including unsound ones.
          audit = craneLib.cargoAudit {
            inherit advisory-db;
            src = ./.;
            cargoAuditExtraArgs = "--deny unsound --ignore RUSTSEC-2021-0154";
          };
        };

        devShells.default = craneLib.devShell {
          # Brings in the crate's build inputs + the toolchain (with clippy/rustfmt).
          inputsFrom = [ p9fuse ];
          packages = testTools ++ [ pkgs.rust-analyzer ];
        };

        apps.default = flake-utils.lib.mkApp {
          drv = p9fuse;
          name = "p9fuse";
        };
      });
}
