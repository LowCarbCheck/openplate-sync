{
  description = "openplate-sync development shell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }: let
    # The systems this shell is expected to work on. Add one here rather than
    # hardcoding a single `system`, so a contributor on a Mac gets the same
    # toolchain as one on Linux.
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
  in {
    devShells = forAllSystems (pkgs: {
      # Node 22 and pnpm — the two things `package.json` actually needs.
      default = pkgs.mkShell {
        packages = with pkgs; [
          nodejs_22
          nodePackages.pnpm
        ];

        shellHook = ''
          echo "node `${pkgs.nodejs_22}/bin/node --version`"
        '';
      };
    });
  };
}
