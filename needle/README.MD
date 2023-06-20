# Needle
Spotify originally used SPIRC for a lot more, now it is only used for track events. It is a custom protocol built on top of TCP which after the handshake uses [shannon](../shannon/) for encryption. To intercept messages we can hook `shn_encrypt` and `shn_decrypt` although we do miss out the first few handshake messages. Hooking is done using [SubHook](https://github.com/Zeex/subhook) with a lot of the function locating logic based on the original [spotify-analyze](https://github.com/plietar/spotify-analyze). The project also builds an injector, which acts as a DLL injector on windows and uses [LD_PRELOAD](https://man7.org/linux/man-pages/man8/ld.so.8.html) on mac and linux. The injector also provides access to some of Spotify's built in debugging features. For more detail see the [theory](#theory) section, for build and configuration instructions keep reading.

## Building
This project is based on cmake and builds two targets, `needle` and `needle-injector`. It uses [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) for all dependencies other than protobuf which can be provided by the system package manager or [vcpkg](https://vcpkg.io/).

### Package Manager
```bash
mkdir build
cmake -B build/
cmake --build build/ -j 2 # "-j 2" is the number of threads to use
```

### Vcpkg
```bash
cd <vcpkg root>
./vcpkg install protobuf
cd <needle dir>
mkdir build
cmake "-DCMAKE_TOOLCHAIN_FILE=<vcpkg root>/scripts/buildsystems/vcpkg.cmake" -B build/
cmake --build build/ -j 2 # "-j 2" is the number of threads to use
```

### Configuration
The following options can be used for configuration
```bash
-DNEEDLE_COMPACT_PROTO=1 # Don't add newlines or formatting in protobuf output
-DNEEDLE_COMPACT_PI=1 # Don't add newlines or formatting in specifically ProductInfo
-DNEEDLE_JSON_PI=1 # Convert ProductInfo to JSON (normally XML)
-DNEEDLE_HIDE_PINGS=1 # Disable logging of Ping, Pong and PongAck messages
```

## Theory
To hook a function we need to know where it is in memory so we can place our hook. One way to do this would be finding the addresses for each version and writing them into the code, but thats ridiculous, so we want to be able to find them programmatically. We can do this using signatures (also called patterns), which are a series of bytes and wildcards that can be scanned for in binary data:
```
Pattern: ?? A7 98 52 ?? 32 AD 72

Instructions (ARM64):
4B A7 98 52    movz w11, #0xc53a
CB 32 AD 72    movk w11, #0x6996, lsl #16
```
We can create signatures based on the [function prologues](https://en.wikipedia.org/wiki/Function_prologue_and_epilogue) which are setup code for the function body and very rarely change even between major updates. The problem with this approach is due to the relatively large size of the Spotify executable (30-100MB) the signatures would have to be very long and surpass the function prologue. This defeats the point of using function prologue signatures because the function body can easily change between versions. To solve this, we can copy the approach used by the original spotify-analyze which involves looking for "KONST" (0x6996c53a) which is a constant used in the shannon algorithm. This constant is found in 3 places, `shn_initstate`, `shn_nonce` and `shn_finish`, and if we look at where the encryption functions are located in memory, we find find that `shn_encrypt`, `shn_decrypt` and `shn_finish` are located one after the other, in that order. That means if we find the last instance of the constant (within shn_finish) then we can look backwards and find decrypt then encrypt using short, stable signatures. This is exactly the original method plietar used so full credit to them.

This is all well and good, but before any of this we need to be able to read and write memory. Most modern systems implement [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) however since our code is running inside the process we can use [GetModuleInformation](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation) on windows and [/proc/self/exe](https://man7.org/linux/man-pages/man5/proc.5.html) on mac and linux to find the base address of the executable and it's size. 

Now that we know how to find the functions and hook them (I'm not going to go into the details of hooking here, there are plenty of explanations online) lets move on to the protocol. Every message has a 3 byte header, the first byte is the packet type, the next 2 bytes are the packet length (not including the 3 bytes of the header), encoded in big endian. When messages are encrypted, the header and packet are encrypted in one call. When messages are decrypted, the header is read from the socket then decrypted so the length is known. That packet is then decrypted directly after. I'm yet to check if multiple threads are used for decryption but it doesn't appear so.
