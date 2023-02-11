# Spotify Analyze V2

An updated version of [librespot-org/spotify-analyze](https://github.com/librespot-org/spotify-analyze) based on the same concepts

### Needle
A library that can be loaded/injected into the Spotify desktop app to log spIRC traffic. It contains a Mercury parser and some protobuf definitions with the aim of aiding further reverse engineering of the protocol. Customization options are defined in the CMakeLists.txt file  
![Needle Example](/assets/needle.png)

### Shannon
Reference implementation of the Shannon cipher used in spIRC from [here](https://github.com/timniederhausen/shannon). The test file is slightly edited to allow it to be used as a test for Needle and not spam stdout

### Contribution
I am very open to contribution, if you feel something needs changing or have something to add feel free to open an issue, I'm always looking to learn and I understand this code could certainly be improved