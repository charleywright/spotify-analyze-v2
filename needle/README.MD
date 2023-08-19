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
# Compile Frida script
npm run compile
```

## Usage

#### Linux

The injector requires the path to the `spotify` binary. This can be found using `which spotify` and is likely a symlink. The bootstrap script will launch this process, so make sure it is closed first (`pkill -9 spotify`) then run

```bash
./needle-injector --target linux --exec <path/to/spotify>
```

#### Windows

The injector requires the path to `Spotify.exe` which is usually located at `%APPDATA%\Spotify\Spotify.exe`. The bootstrap script will launch this process, so make sure it is closed first (`Stop-Process -Name Spotify`) then run

```bash
./needle-injector --target windows --exec <path/to/Spotify.exe>
```

#### Android

The injector requires the package name (probably `com.spotify.music`) which can be found using `frida-ps -aiU` and looking for Spotify. It also needs the JNI library which contains the code that we're interested in. This can be found by extracting the APK ([Softpedia](https://mobile.softpedia.com/apk/spotify/) have the best list) or can be pulled from the device with ADB:

```bash
# Get install path
adb shell pm path com.spotify.music
# package:/data/app/~~2Q_dAO-R8knLG0ud6MXnew==/com.spotify.music-msq2fZq3LOLz7NX1CuAUMA==/base.apk

# Check which architecture of library is installed
adb shell ls /data/app/~~2Q_dAO-R8knLG0ud6MXnew==/com.spotify.music-msq2fZq3LOLz7NX1CuAUMA==/lib/

# Pull the APK
adb pull <install path>/lib/<arch>/liborbit-jni-spotify.so
# e.g. for my device (ARM64):
# adb pull /data/app/~~2Q_dAO-R8knLG0ud6MXnew==/com.spotify.music-msq2fZq3LOLz7NX1CuAUMA==/lib/arm64/liborbit-jni-spotify.so
```

There are four architectures shipped with the app, `x86`, `x86_64`, `armeabi-v7a`, `arm64-v8a`. The library will be in a different folder depending on the architecture:
* x86: `/lib/x86/`
* x86_64: `/lib/x86_64/`
* armeabi-v7a: `/lib/arm/`
* arm64-v8a: `/lib/arm64/`

The injector does not need to know the architecture, it will find it automatically. It can be run using

```bash
./needle-injector --target android --exec com.spotify.music --binary <path/to/liborbit-jni-spotify.so>
```

### Options
Additional options can be specified by terminating the injector's arguments using `--` then specifying `key=value` pairs:

```
./needle-injector --target linux --exec /opt/spotify/spotify -- shannonDisableParsing=true
```

A list and description of possible options is available by passing the `--help` flag.

## Architecture

This project is split into 3 parts, the injector, the launch wrapper, and the frida script.

* The injector is written in C++ using cmake as a build system. Its purpose is to scan/parse binary files to find offsets that we are interested in. Because it is written in C++ implementing binary format parsing is quite simple and fast.

* The launch wrapper is a small Node.js script which uses frida-node to launch the Spotify app and inject the Frida script. It then provides the Frida script with the offsets from the injector, acting like a glue between the two.

* The Frida script is compiled from TypeScript files and contains all the Spotify-related code. It is split into two parts, the parser and the platform backends. 
    * Platform backends take care of abstracting away the specifics of each platform such as library loading.
    * The parser deals with parsing SPIRC packets, implementing the mercury protocol etc.

The launch wrapper can be replaced by the Frida C API and integrated into the injector however this API is undocumented aside from comments in the code and I had issues building it.

The injector code is heavily commented to explain how it works on different platforms so for implementation details see those.
