# Pineapple

Inspired by the [WiFi pineapple](https://shop.hak5.org/products/wifi-pineapple), this tool aims to act like a Spotify server when in reality it is decrypting every message, logging it, then passing it on to the real server. This is known as a [Man In The Middle Attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) as we are eavesdropping on the connection ideally without the client knowing.

### Parts

* [Usage](#usage)
* [Theory](#theory)
* [Architecture](#architecture)
* [Contributing](#contributing)

## Usage

Pineapple is intended to run as multiple processes with one or more proxy processes then a process for each Spotify instance to connect to the proxy.

### Running the proxy

```bash
# On one machine (192.168.1.10) run the proxy with very verbose (TRACE) logs and save captured packets to spirc.pcapng
cargo run --release -- listen -vv --write spirc.pcapng
```

### Launching the app and redirecting traffic to the proxy

```bash
# On the target or a machine connected to the target, launch the app and point it at the proxy
cargo run --release -- launch -vv --host 192.168.1.10

# Launch the app on an Android phone over ADB that is on the same network
cargo run --release -- launch -vv --host 192.168.1.10 --usb

# If you have multiple devices you can specify a Frida device identifier
frida-ls-devices
# Id              Type    Name                   OS
# --------------  ------  ---------------------  ------------
# local           local   Local System           macOS 15.0.1
# emulator-5554   usb     Android Emulator 5554  Android 15
# 33201FDH20070B  usb     Pixel 7                Android 14
# barebone        remote  GDB Remote Stub
# socket          remote  Local Socket

cargo run --release -- launch -vv --host 192.168.1.10 --device 33201FDH20070B # Spawn on Pixel 7
```

### Monitor packets in real time using Wireshark (Linux and Windows only)

When running the proxy on a Linux or Windows host a Wireshark instance can be connected to the proxy to see traffic in real time:

```bash
cargo run --release -- wireshark

# Specify the wireshark install path if required or if multiple versions are installed and the default is incorrect
cargo run --release -- wireshark --dir C:\\Users\\Bee\\Documents\\Wireshark\\bin

# Specify the proxy instance to connect to. Required for non-default hosts or if multiple instances are running
cargo run --release -- wireshark --host 192.168.1.10
```

### Explore previously captured packets

Pineapple includes a simple TUI program to view connections and packets loaded from a `.pcapng` capture file

```bash
cargo run --release -- parse path/to/capture.pcapng
```

There are three main views: connections, packets, and packet details. After parsing the capture you will see all connections in the file, these are individual SPIRC sessions. Move the cursor up and down using the arrow keys then select a connection by pressing `Enter`. Now all packets in that connection are shown. To view more details about a packet again move the cursor to it then press `Enter`. This will show the packet details and a best-effort attempt to parse it. Press `Backspace` at any time to unselect the current packet or connection, or press `q` to quit.

#### Copying

Use `Ctrl + C` to copy the parsed view of a packet or `Alt + C` to copy a packet as hex.

- When viewing packet details, the packet being shown will be copied irrespective of the cursor position
- When no packet is selected, the packet under the cursor will be copied

## Theory

### Bypassing MITM Protection

Spotify have a mitigation in place to protect from this type of attack, every Spotify app contains a public RSA key that is used to verify a signature generated and sent by the server. Since only Spotify know the private key, an attacker (e.g. us) couldn't generate a valid signature causing the client to terminate our intercepted connection. What we can do is generate our own RSA key pair so we hold the private key then replace the public key in the Spotify app with our public key, causing the app to trust our signature and thus our connection.

### Redirecting traffic to us

When deciding where to connect to, the Spotify apps first make a request to [apresolve.spotify.com](http://apresolve.spotify.com/) which returns a list of APs (Access Points) with their ports. If that request fails [mobile-ap.spotify.com](http://mobile-ap.spotify.com) or [ap.spotify.com](http://ap.spotify.com) can be used instead using port 4070 then 443 then 80.

All of these options give a list of domain names and ports which must first be resolved using [DNS](https://en.wikipedia.org/wiki/Domain_Name_System). If we want to redirect traffic to ourselves, we can intercept the DNS request (or hook the DNS resolver function) then change the response and put in the address of our proxy server, making the client connect to us. On unix-based systems the lookup is done using the [getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) function which takes a domain and returns an IP address, so if we hook that function we can intercept all DNS lookups then when an AP is resolved we override the AP server with an IP address we are listening on e.g. a computer on the local network. DNS is for hostnames and doesn't allow us to change the port the app will connect to. The actual TCP connection is established using the [connect](https://man7.org/linux/man-pages/man2/connect.2.html) system call, so we can hook that and replace both the IP address and port when it is called and use our [getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) hook to maintain a mapping of domains to resolved IP addresses so we know what to overwrite.

#### Why not use the app/system proxy settings?

While this would allow us to redirect traffic we would still need to replace the RSA public key in the Spotify app so our signatures are valid. The easiest non-permanent way to do this is by injecting Frida and overwriting the key in memory with our own, and if we are already injecting code we might as well redirect traffic using hooks instead of requiring the user to set their proxy settings.

## Architecture

There are a couple of components that make up this tool which have different roles:
* Launcher - Launch the spotify app on the target platform, inject Frida, inject the redirect script, and pass the proxy details to the redirector
* Redirector (Frida script) - Stemming from an entrypoint, replace the server key with ours and hook some functions to redirect SPIRC traffic
* SPIRC Proxy - Accept TCP traffic and act like a Spotify Access Point. Log all traffic and optionally save it to a file, then forward it to Spotify for processing. Written in a nonblocking architecture.

### Server Key

Currently Pineapple uses a hardcoded public & private key pair located in `src/proxy/proxy_session.rs`. Feel free to generate a new pair and replace it with your own.

### Multiple Clients and Proxies

The proxy can be configured to listen on a user-provided host and port. To run multiple instances of the proxy simultaneously (for example to save traffic from different platforms to different files) use unique host and port combinations then specify the host of the proxy to connect to when launching the app

For example to connect Spotify on the current computer (reachable at 192.168.1.60 on a local network) to a proxy and an iOS device via USB on the same network to a proxy:
```bash
pineapple listen 127.0.0.1:4070 --write mac.pcapng
pineapple listen 192.168.1.60:4060 --write ios.pcapng
pineapple launch --host 127.0.0.1:4070
pineapple launch --usb --exec Spotify --host 192.168.1.60:4060
```

### UI

When dumping traffic to a file it will be saved in the [PcapNG](https://pcapng.com/) format which can be read using [Wireshark](https://wireshark.org). On Linux and Windows Wireshark can connect to the proxy directly and receive packets in real time using [named pipes](https://wiki.wireshark.org/CaptureSetup/Pipes). In the future a dissector for Wireshark is planned which will parse SPIRC packets and protobuf messages to display them with a user-friendly UI. Currently users are advised to copy the raw hex stream of a packet from Wireshark and parse it themselves.

## TODO List

- Support realtime capture in Wireshark on MacOS
- Write wireshark dissector or GUI (Qt maybe?)
- IPC between launcher & proxy
- Generate new keypair on every run

## Contributing

Given how early this project is in development anything other than code improvements will likely not be accepted. Once a significant portion of the code is done I'll be much more open to submission but for now feel free to open an issue or draft pull request with suggestions.
