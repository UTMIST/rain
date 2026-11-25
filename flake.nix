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
                ./src/rain/ultrasonic-cleaner.png
                (pythonSources ./tests)
              ];
            };
            build-system = [ python.pkgs.uv-build ];
            dependencies = with python.pkgs; [ fastapi pydantic python-multipart uvicorn ];
            pythonImportsCheck = [ "rain" "rain.web" ];
            doInstallCheck = true;
            nativeInstallCheckInputs = with python.pkgs; [ pytestCheckHook httpx ];
            disabledTestPaths = [ "tests/test_contract.py" ];
            postCheck = ''
              "$out/bin/rain" --help
              "$out/bin/rain-web" --help
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
