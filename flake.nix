{
  description = "awesome-cvelabs scraper environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
    python = pkgs.python313;
    pythonEnv = python.withPackages (ps: [
      ps.pydantic
      ps.pyyaml
      ps.requests
      ps.beautifulsoup4
      ps.playwright
    ]);
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = [ pythonEnv pkgs.just ];
    };
  };
}
