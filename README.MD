# Spotify Analyze V2

An updated version of [librespot-org/spotify-analyze](https://github.com/librespot-org/spotify-analyze) based on the same concepts

## Pineapple

A proxy that performs a Man-In-The-Middle attack on the Spotify apps, allowing us to intercept, decrypt and modify data on the fly. This contains the most up-to-date parsing code and can be used as a reference implementation for SPIRC which is Spotify's custom protocol built upon TCP. More details are available in the [README](./pineapple/)

## Needle

**NOTE: [Pineapple](#pineapple) contains the latest parsing code, this is preserved as instrumenting can be useful for other reasons**

A library and injector that can log encrypted SPIRC messages. It contains a Mercury parser and some protobuf definitions with the aim of aiding further reverse engineering of the protocol. More details are available in the [README](./needle/)

![Needle Example](/assets/needle.png)

## Shannon

Reference implementation of the Shannon cipher used in SPIRC from [here](https://github.com/timniederhausen/shannon). The test file is slightly edited to allow it to be used as a test for Needle and not spam stdout

## Contribution

I am very open to contribution, if you feel something needs changing or have something to add feel free to open an issue.

## TODO

* Further reverse engineering of events. As shown in [librespot#626](https://github.com/librespot-org/librespot/discussions/626) there has been some work done on this however it is very incomplete.
* MITM server for SPIRC traffic. This would allow for some interesting analysis by modifying client and server messages.
* Write a single-source-of-truth documentation of Spotify's internals with links to implementations, probably using this repository's Wiki.
