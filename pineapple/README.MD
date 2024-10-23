# Pineapple

Inspired by the [WiFi pineapple](https://shop.hak5.org/products/wifi-pineapple), this tool aims to act like a Spotify server when in reality it is decrypting every message, logging it, then passing it on to the real server. This is known as a [Man In The Middle Attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) as we are eavesdropping on the connection ideally without the client knowing.

### Parts

* [Theory](#theory)
* [Architecture](#architecture)
* [Usage](#usage)
* [Contributing](#contributing)

## Theory

### Bypassing MITM Protection

Spotify have a mitigation in place to protect from this type of attack, every Spotify app contains a public RSA key that is used to verify a signature generated and sent by the server. Since only Spotify know the private key, an eavesdropper couldn't modify the signature without the client rejecting it. This poses an issue for us since we need to modify the signature, however since we are developers we can do whatever we want, including replacing the public key the app uses for verification with one we hold the private key to.

### Redirecting traffic to us

When deciding where to connect to, the Spotify apps first make a request to [apresolve.spotify.com](http://apresolve.spotify.com/) which returns a list of APs (Access Points) with their ports. If that request fails [mobile-ap.spotify.com](http://mobile-ap.spotify.com) or [ap.spotify.com](http://ap.spotify.com) can be used instead using port 4070 then 443 then 80.

All of these options give a list of domain names and ports however sockets cannot be opened to domains therefore they must be resolved using [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) first. If we want to redirect traffic to ourselves, we can modify the response and put in the address of our proxy server, making the client connect to us. On unix the lookup is done using the [getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) function which takes a domain and returns an IP address, so if we hook the function we can see all of the lookups then override the AP server with an IP address we are listening on e.g. a laptop on the local network. Since the app has its own logic for determining which port to use, this is not the only function we need to hook. The actual connection is established using the [connect](https://man7.org/linux/man-pages/man2/connect.2.html) system call, so it is easier to hook this and replace both the IP address and port when this is called, and use a [getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) hook to maintain a mapping of domains to resolved IP addresses.

#### Why not use the app/system proxy settings?

While this would allow us to redirect traffic we would still need to replace the key in the Spotify app so our server signature is verified. The easiest non-permanent way to do this is by injecting Frida and overwriting the key in memory with our own, and if we are already injecting code we may as well redirect traffic to us using hooks instead of requiring the user to set their proxy settings. If pineapple were to be written as a proxy it would have to support HTTP(S) and websockets which would greatly increase the complexity compared to adding more code to the injected script, and it would still require the client's server key to be replaced.

## Architecture

There are a couple of components that make up this tool which have different roles:
* Launcher - Launch the spotify app on the target platform, inject Frida, inject the redirect script, and pass the proxy details to the redirector
* Redirector (Frida script) - Stemming from an entrypoint, replace the server key with ours and hook some functions to redirect SPIRC traffic
* SPIRC Proxy - Accept TCP connections, decrypt data, do whatever with the data, encrypt then pass it to Spotify

The Frida script could be written in a compiled language then injected as a shared library, but it would be massively overcomplicated so lets just use TypeScript. The launcher and proxy could all be written in the same language, C++ could be a candidate, but even the NSA advised against the use of non-memory safe languages. Rust is a strong candidate, a well-designed language with safety so lets go for that.

### Server Key

We need to replace the server key in the app using our own, but what and where is that key going to come from? The easy way would be to generate a pineapple key that all instances of pineapple use but while this is tooling aimed for developers and reverse engineers that is still not a good idea. mitmproxy solves this by generating a set of keys when it is first run, then using that for all subsequent runs. This works for us, and to avoid dealing with platform-specific config directories we can just use the current directory.

NOTE: This is not currently implemented however you could generate your own key and change the code in `src/frida/index.ts` & `src/proxy/proxy_session.rs`

### Multiple Clients and Proxies

Supporting multiple clients in the proxy code itself is fairly trivial, we just need to tie state to each socket. The more challenging part is spawning multiple instances of the app across various devices that target the same proxy, and running multiple instances of the proxy. To keep things simple, multiple instances of the proxy can use the same key pair, stored in the same directory as the executable. To spawn multiple instances of the app we can have subcommands for different operations:
```bash
pineapple listen 0.0.0.0:4070 --write 8.8.82.pcapng
pineapple launch --exec /opt/spotify/spotify
pineapple launch --exec com.spotify.music
pineapple launch --exec Spotify
```

### Persistence and sharing of logs

As seen in the above example, the ability to save and load traffic is a must so users can collaborate, however we probably don't want to be saving auth tokens or stored credentials. The goto format for packet capture is PCAP and PCAP-next-generation, so lets use that. This also means we can make our captures compatible with Wireshark, giving us a very powerful UI without needing to reinvent the wheel.

### UI

The goto tool for inspecting binary protocols is wireshark due to its extensive scripting and powerful UI. While we could design our own UI for pineapple it makes little sense to go to so much effort when a very well supported, well-known tool already exists. To implement the SPIRC-specific parsing we can use a dissector plugin and take advantage of the built-in protobuf dissector instead of rolling our own. Wireshark also supports [reading from named pipes](https://wiki.wireshark.org/CaptureSetup/Pipes) in real-time so we can make use of that to finally have realtime capture.

## Usage

As detailed in [Architecture](#architecture) you would run an instance of the proxy then spawn the Spotify app on the target(s) which would connect to the proxy instead of Spotify's servers. That could look like this:

```bash
# On one machine (192.168.1.10)
cargo run --release -- listen -vv --write spirc.pcapng

# On the target or a machine connected to the target
cargo run --release -- launch -vv --host 192.168.1.10
```

Pretty simple. The proxy can be run on different ports/interfaces using `-host` and optionally written to a file. On supported platforms (Linux & Windows) Wireshark can also open a live stream of decrypted SPIRC messages.

## TODO List

- Support realtime capture in Wireshark on MacOS
- Write wireshark dissector or GUI (Qt maybe?)
- IPC between launcher & proxy
- Generate new keypair on every run

## Contributing

Given how early this project is in development anything other than code improvements will likely not be accepted. Once a significant portion of the code is done I'll be much more open to submission but for now feel free to open an issue or draft pull request with suggestions.
