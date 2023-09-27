# Needle

The basic idea of needle is to hook useful functions and add logging using an easily-extendable parser. While reversing a structure this allows for fast prototyping of ideas and acts as a reference implementation. Currently shn_encrypt and shn_decrypt are hooked which are the functions used to encrypt/decrypt SPIRC traffic (the proprietary protocol used by Spotify). It then parses what it can and logs the decrypted traffic to the console.

## Building

The injector uses Rust, so should "just work". To build:

```bash
cd injector
cargo build --release
```

The Frida script must be compiled separately:

```bash
# Install dependencies
npm install
# Compile Frida script
npm run compile
```

## Usage

This tool uses [Frida](https://frida.re) for instrumentation therefore requires frida-server to be running on Android or iOS. Setting that up will not be covered here as there are plenty of amazing resources online already. There are no plans to support frida-gadget however a PR is always welcome.

### Linux

The injector requires the path to the `spotify` binary. This can be found using `which spotify` and is likely a symlink. The bootstrap script will launch this process, so make sure it is closed first (`pkill -9 spotify`) then run

```bash
./needle-injector --target linux --exec <path/to/spotify>
```

### Windows

The injector requires the path to `Spotify.exe` which is usually located at `%APPDATA%\Spotify\Spotify.exe`. The bootstrap script will launch this process, so make sure it is closed first (`Stop-Process -Name Spotify`) then run

```bash
./needle-injector --target windows --exec <path/to/Spotify.exe>
```

### Android

The injector requires the package name (probably `com.spotify.music`) which can be found using `frida-ps -aiU` and looking for Spotify. It also needs the JNI library which contains the code that we're interested in. This can be found by extracting the APK ([Softpedia](https://mobile.softpedia.com/apk/spotify/) have the best list) or can be pulled from the device with ADB:

```bash
# Get install path
adb shell pm path com.spotify.music

# Check which architecture of library is installed
adb shell ls <install path>/lib/

# Pull the APK
adb pull <install path>/lib/<arch>/liborbit-jni-spotify.so
```

There are four architectures shipped with the app, `x86`, `x86_64`, `armeabi-v7a`, `arm64-v8a`. The library will be in a different folder depending on the architecture:

* x86: `/lib/x86/`
* x86_64: `/lib/x86_64/`
* armeabi-v7a: `/lib/arm/`
* arm64-v8a: `/lib/arm64/`

For example to pull the library for an x86_64 device the commands may look like this:

```bash
adb shell pm path com.spotify.music
# package:/data/app/~~BrlrJPhZ8k3d4Le2K8WmTA==/com.spotify.music-Qg8ZuOmtolB45ql5IpvzFA==/base.apk
adb shell ls /data/app/~~BrlrJPhZ8k3d4Le2K8WmTA==/com.spotify.music-Qg8ZuOmtolB45ql5IpvzFA==/lib/
# x86_64
adb pull /data/app/~~BrlrJPhZ8k3d4Le2K8WmTA==/com.spotify.music-Qg8ZuOmtolB45ql5IpvzFA==/lib/x86_64/liborbit-jni-spotify.so
```

The injector does not need to know the architecture, it will determine it automatically. It can be run using

```bash
./needle-injector --target android --exec com.spotify.music --binary <path/to/liborbit-jni-spotify.so>
```

### iOS

iOS uses .ipa files which are similar to APKs in that they are renamed .zip archives. There are two types of IPAs, encrypted and unencrypted. For the injector to function it requires an unencrypted IPA which can be dumped from an iDevice or decrypted using [mremap_encrypted](https://github.com/JohnCoates/flexdecrypt/blob/master/Readme.md) or [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump). The only device that has been tested is an iPhone SE 1st generation running iOS 15.7.8 and Palera1n rootless. These are the steps for that device:

#### Obtaining a decrypted IPA using a rootless jailbreak

1. Install frida-server by either following [miticollo's guide for building Frida](https://gist.github.com/miticollo/6e65b59d83b17bacc00523a0f9d41c11) or adding [their repository for Sileo/Zebra](https://miticollo.github.io/repos/) and installing from there
2. Clone [miticollo's fork of frida-ios-dump](https://github.com/miticollo/frida-ios-dump) and follow the instructions to install dependencies
3. Start the spotify app and run `./dump.py --list`. There should be a process called "Spotify"
4. Dump the app: `python ./dump.py -H <local ip> -u mobile -P <password> Spotify`

Once an unencrypted IPA has been obtained it can be extracted then the injector can be run using

```bash
./needle-injector --target ios --exec com.spotify.client --binary <path/to/extracted/ipa>/Payload/Spotify.app/Spotify
```

### Options

Additional options can be specified by terminating the injector's arguments using `--` then specifying `key=value` pairs:

```
./needle-injector --target linux --exec /opt/spotify/spotify -- shannonDisableParsing=true
```

These options are passed on to the Frida script and control how it will interact with the process. There are additional flags for the injector itself:

**--target** [linux, windows, android, ios] - The target platform the script will be injected into  
This controls how the injector will parse the binary and which entrypoint it will use when injecting the Frida script.

**--exec** &lt;identifier&gt; - The path to the executable or platform-specific identifier  
This is the identifier that will be used when spawning the process. On Windows and Linux it should be the path to the executable. On Android it should be the package ID (e.g. com.spotify.music). On iOS it should be the bundle ID (e.g. com.spotify.client). On both Android and iOS the identifier can be found using `frida-ps -aiU` (list installed apps on USB device)

**--binary** &lt;path&gt; - The path to the binary which will be scanned for offsets  
The binary must contain the spotify library, which is statically linked on desktop and iOS, and a shared JNI library on Android. On Windows and Linux it should be the same as --exec therefore can be omitted and the injector will use that value. On iOS it should be the path to the spotify binary inside the IPA (e.g. Payload/Spotify.app/Spotify). On Android it should be the path to the JNI library (e.g. liborbit-jni-spotify.so)

**--arch** &lt;identifier&gt; - **iOS ONLY** - The architecture to use in a multi-architecture binary  
Mach-O archives ([as Apple call them](https://web.archive.org/web/20140904004108mp_/https://developer.apple.com/library/mac/documentation/developertools/conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF:~:text=Note%3A%C2%A0Binaries%20that%20contain%20object%20files%20for%20more%20than%20one%20architecture%20are%20not%20Mach%2DO%20files.%20They%20archive%20one%20or%20more%20Mach%2DO%20files)) can contain multiple Mach-O files for different architectures. Some .ipa files will contain these archives so by default the injector will quit and list the architectures it found. This option should then be added to specify which architecture to use. The injector uses the same identifiers as macOS's [Lipo](https://ss64.com/osx/lipo.html) and a list of them is defined [here](https://github.com/tpoechtrager/cctools-port/blob/f28fb5e9c31efd3d0552afcce2d2c03cae25c1ca/cctools/libstuff/arch.c#L33-L110) for reference.

**--kill** - On Linux and Windows kill any instances of the executable before spawning

**--enable-debug** - Enable Spotify's inbuilt debug logging on desktop  
Example:
![Debug logging enabled](/assets/needle-debug-log.png)

## Project structure

This project is split into 3 parts, the injector, the launch wrapper, and the frida script.

* The injector was originally written in C++ then ported to Rust. Its purpose is to parse and scan binary files to find offsets that we are interested in. It is separate from the Frida script because signature scanning in Frida can be really slow, and we can optimise by parsing the platform-specific binary format.

* The launch wrapper is a small Node.js script which uses frida-node to launch the Spotify app and inject the Frida script. It then provides the Frida script with the offsets from the injector, acting like a glue between the two.

* The Frida script is compiled from TypeScript files and contains all the Spotify-related code. It is split into two parts, the parser and the platform backends.
    * Platform backends take care of abstracting away the specifics of each platform such as library loading or base addresses.
    * The parser deals with parsing SPIRC packets, implementing the mercury protocol etc.

The launch wrapper can be replaced by the [Frida crate](https://docs.rs/frida/0.4.1/frida/) and integrated into the injector however spawning processes is currently unsupported (there is [an open PR to add support](https://github.com/frida/frida-rust/pull/110)) so this change will happen at a later date.

## Contributing

Contributions are always welcome, please open an issue or a PR if you have any ideas or suggestions. JS and TS should follow the current code formatting, Rust should be formatted using the provided rust-fmt configuration.

## Development

To work on the codebase you will probably want to recompile the Frida script on every change. This can be done using

```bash
yarn run watch 
# or npm run watch
```

If yarn.lock or package-lock.json are updated, they should be synced using [synp](https://www.npmjs.com/package/synp)

### TODO

* [ ] Integrate the bootstrap script into the injector
