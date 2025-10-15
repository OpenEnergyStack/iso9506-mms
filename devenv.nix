{ pkgs, lib, config, inputs, ... }:

{

  # https://devenv.sh/binary-caching/
  cachix.enable = true;
  cachix.pull = [ "pre-commit-hooks" ];

  # https://devenv.sh/integrations/codespaces-devcontainer/
  devcontainer.enable = true;

  # https://devenv.sh/basics/
  env.RUSTC_ICE = "0";

  # https://devenv.sh/packages/
  packages = [
    pkgs.actionlint
    pkgs.cargo
    pkgs.cargo-nextest
    pkgs.git
    pkgs.markdownlint-cli
    pkgs.rustup
  ];

  # https://devenv.sh/languages/
  languages.rust = {
   enable = true;
   channel = "stable";
   components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ];
  };

  # https://devenv.sh/tests/
  # Note: Tests are a way to ensure that your development environment is working as expected.
  # Running 'devenv test' will build your environment and run the tests defined in enterTest.
  enterTest = ''
    echo "Running tests"
    actionlint --version | grep --color=auto "${pkgs.actionlint.version}"
    git --version | grep --color=auto "${pkgs.git.version}"
    markdownlint --version | grep --color=auto "${pkgs.markdownlint-cli.version}"
  '';

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    actionlint = {
        enable = true;
        entry = "actionlint";
    };
    clippy = {
        enable = true;
        entry = "cargo clippy --workspace --all-targets --all-features --fix --allow-staged";
        args = ["--" "-D warnings"];
    };
    markdownlint = {
        enable = true;
        entry = "markdownlint --disable MD013";
        args = [ "**/*.md" "--fix" ];
    };
    rustfmt.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
