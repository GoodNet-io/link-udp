# Standalone dev / test / build flake for the goodnet-link-udp
# plugin. See `plugins/security/noise/flake.nix` for the canonical
# pattern; this flake is a copy with plugin-specific knobs swapped in.
#
# goodnet-standalone-plugin: udp
{
  description = "GoodNet link plugin: udp — standalone plugin flake.";

  inputs = {
    goodnet.url     = "git+file:../../..?dir=nix/kernel-only";
    nixpkgs.follows = "goodnet/nixpkgs";
  };

  outputs = { self, nixpkgs, goodnet }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f system (import nixpkgs { inherit system; }));
      helpers = goodnet.lib.plugin-helpers;
    in
    {
      packages = forAllSystems (system: pkgs:
        let goodnet-core = goodnet.packages.${system}.goodnet-core;
        in {
          default = pkgs.callPackage ./default.nix { inherit goodnet-core; };
        });

      devShells = forAllSystems (system: pkgs: {
        default = helpers.mkPluginDevShell pkgs {
          plugin = self.packages.${system}.default;
          welcomeText = ''
  goodnet-link-udp  —  standalone plugin dev shell
    nix run .#build      — Release build (artefacts → ./build/)
    nix run .#test       — Release build with tests + ctest
    nix run .#test-asan  — ASan + UBSan build + ctest
    nix run .#test-tsan  — TSan build + ctest
    nix run .#debug      — Debug build + gdb on test_udp
'';
        };
      });

      apps = forAllSystems (system: pkgs:
        helpers.mkPluginApps pkgs {
          pluginName  = "udp";
          debugBinary = "test_udp";
        });
    };
}
