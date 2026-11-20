{
  description = "Rain: provision Slurm users from Misty staging";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      forLinux = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      inherit (builtins.fromTOML (builtins.readFile ./pyproject.toml)) project;
    in
    {
      packages = forLinux (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python3;
          pythonSources = pkgs.lib.fileset.fileFilter (file: file.hasExt "py");
          rain = python.pkgs.buildPythonApplication {
            pname = project.name;
            inherit (project) version;
            pyproject = true;
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./pyproject.toml
                ./README.md
                (pythonSources ./src)
                (pythonSources ./tests)
              ];
            };
            build-system = [ python.pkgs.uv-build ];
            pythonImportsCheck = [ "rain" ];
            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              PYTHONPATH="$out/${python.sitePackages}" ${python.interpreter} -m unittest discover -s tests -v
              "$out/bin/rain" --help
              runHook postInstallCheck
            '';
            meta.mainProgram = "rain";
          };
        in { inherit rain; default = rain; });

      checks = forLinux (system: { inherit (self.packages.${system}) rain; });

      devShells = forLinux (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in { default = pkgs.mkShell { packages = [ pkgs.python3 pkgs.uv ]; }; });
    };
}
