# Needle

The basic idea of needle is to hook useful functions and add logging. While reversing a structure this allows for quickly prototyping ideas and acts as a reference implementation. Currently it hooks shn_encrypt and shn_decrypt which are the functions used to encrypt/decrypt SPIRC traffic. It then parses what it can and logs the decrypted traffic to the console.

## Building

#### Injector

The injector uses CMake and FetchContent, so should "just work". To build:

```bash
cd injector
mkdir build
cmake -B build/
cmake --build build/
```

#### Bootstrap script and Frida script

```bash
# Install dependencies
npm install
# Or
yarn install

# Compile Frida script
npm run compile-all
# Or
yarn run compile-all
```

## Usage

#### Linux

The injector requires the path to the `spotify` binary. This can be found using `which spotify` and is likely a symlink. The bootstrap script will launch this process, so make sure it is closed first (`pkill -9 spotify`) then run

```bash
./needle-injector --target linux --exec <path/to/spotify>
```

## Architecture

This project is split into 3 parts, the injector, the launch wrapper, and the frida script.

* The injector is written in C++ using cmake as a build system. Its purpose is to scan/parse binary files to find offsets that we are interested in. Because it is written in C++ implementing binary format parsing is quite simple and fast.

* The launch wrapper is a small Node.js script which uses frida-node to launch the Spotify app and inject the frida script. It then provides the frida-script with the offsets from the injector, acting like a glue between the two.

* The frida script is compiled from TypeScript files and contains all the Spotify-related code. It is split into two parts, the parser and the platform backends. 
    * Platform backends take care of abstracting away the specifics of each platform such as library loading.
    * The parser deals with parsing SPIRC packets, implementing the mercury protocol etc.

The launch wrapper can be replaced by the frida C API and integrated into the injector however this API is undocumented aside from comments in the code and I had issues building it.
