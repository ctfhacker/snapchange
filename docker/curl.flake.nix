{
  description = "Build the curl harness";

  inputs = {
    # Bring in the default nixpkgs repo
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # For building for all default systems (x86_64 and aarch64)
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Set the current system for nixpkgs
        pkgs = import nixpkgs {
          inherit system;
        };

        # Use clang for the compiler
        newCurl = pkgs.curl.override {
          stdenv = pkgs.clangStdenv;
        };

        # Non-ASAN curl, static without brotli
        customCurl = newCurl.overrideAttrs (oldAttrs: {
          configureFlags = oldAttrs.configureFlags ++ [ 
            "--disable-shared" 
            "--enable-static" 
            "--without-brotli"
          ];
        });

        # ASAN curl, static without brotli (using the above configure flags)
        customCurlAsan = customCurl.overrideAttrs (oldAttrs: {
          CFLAGS = "-fsanitize=address -g -O2";
          CXXFLAGS = "-fsanitize=address -g -O2";
        });
      in
      rec
      {
        # Build the harness using the custom built curl
        packages.harness = pkgs.clangStdenv.mkDerivation {
          name = "harness";

          # Look in the current directory for the harness.c file
          src = ./.;

          # Use the following packages to build the harness
          buildInputs = [ 
            customCurl 
            pkgs.clang 
            pkgs.krb5
            pkgs.openssl
            pkgs.brotli
            pkgs.gzip
          ];

          # Modify the buildPhase and installPhase during mkDerivation:
          #     unpackPhase
          #     patchPhase
          #     configurePhase
          # --> buildPhase   <--
          #     checkPhase
          # --> installPhase <--
          #     fixupPhase
          #     installCheckPhase
          #     distPhase
          buildPhase = ''
            clang $PWD/harness.c \
              -o harness_orig \
              -ggdb \
              -I${customCurl.out}/include \
              -L${customCurl.out}/lib \
              -pthread \
              -ldl \
              -lm \
              -lgssapi_krb5 \
              -lcrypto \
              -lnghttp2 \
              -lssl \
              -lidn2 \
              -lzstd \
              -lz \
              -lssh2 \
              -lpsl \
              ${customCurl.out}/lib/libcurl.a 

            clang $PWD/harness.c \
              -o harness_asan \
              -ggdb \
              -fsanitize=address \
              -I${customCurlAsan.out}/include \
              -L${customCurlAsan.out}/lib \
              -pthread \
              -ldl \
              -lm \
              -lgssapi_krb5 \
              -lcrypto \
              -lnghttp2 \
              -lssl \
              -lidn2 \
              -lzstd \
              -lz \
              -lssh2 \
              -lpsl \
              ${customCurlAsan.out}/lib/libcurl.a 
          '';

          installPhase = ''
            mkdir -p $out/bin
            mkdir -p $out/src

            cp harness_orig $out/bin/
            cp harness_asan $out/bin/

            cp -r ${customCurl.src} $out/curl-src.tar.xz

            tar xvf $out/curl-src.tar.xz -C $out/src

            cp ${customCurlAsan.out}/lib/libcurl.a $out/bin/libcurl_asan.a
            cp ${customCurl.out}/lib/libcurl.a $out/bin/libcurl.a
          '';
        };

        packages.docker = pkgs.dockerTools.buildImage {
          name = "curl_harness";
          tag = "latest";

          copyToRoot = pkgs.buildEnv { 
            name = "image-root";
            paths = [ 
              packages.harness 
              pkgs.bashInteractive
            ]; 
            pathsToLink = [
              "/bin"
            ];
          };
        };
      });
}

