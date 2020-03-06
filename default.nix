# Run like this:
#   nix-build /path/to/this/directory
# ... and the files are produced in ./result/bin/snabb

{ pkgs ? (import <nixpkgs> {})
, source ? ./.
, version ? "dev"
, test ? false
}:

with pkgs;

stdenv.mkDerivation rec {
  name = "vita-${version}";
  inherit version;
  src = lib.cleanSource source;

  buildInputs = [ makeWrapper ];

  RECIPE = if test then "Makefile.vita-test" else "Makefile.vita";

  preBuild = ''
    make clean
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp src/snabb $out/bin
    ln -s snabb $out/bin/vita
  '';

  enableParallelBuilding = true;
}
