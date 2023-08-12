# Research

## iOS

iOS apps use .ipa files which are encrypted by default. They can be decrypted using a mac or jailbroken device or the unencrypted version can be dumped using frida-ios-dump. Once a decrypted IPA has been obtained it can be extracted (standard zip archive like an APK) and the main binary can be analyzed. The main binary should be at `./Payload/Spotify.app/Spotify`.

### Obtaining a decrypted IPA using a rootless jailbreak

I'm using an iPhone SE 1st Gen running iOS 15.7.8 and palera1n rootless. These are the steps for my setup:
1. Install frida-server by either following [miticollo's guide for building Frida](https://gist.github.com/miticollo/6e65b59d83b17bacc00523a0f9d41c11) or adding [their repository for Sileo/Zebra](https://miticollo.github.io/repos/) and installing from there
2. Clone [miticollo's fork of frida-ios-dump](https://github.com/miticollo/frida-ios-dump) and follow the instructions to install dependencies
3. Start the spotify app and run `./dump.py --list`. There should be a process called "Spotify"
4. Dump the app: `python ./dump.py -H <local ip> -u mobile -P <password> Spotify`

### Web archive

There are some old versions of the app available here - https://archive.org/details/iOSObscura  
These are decrypted IPA files which is the apple version of an APK. Unzipping them, there are two binaries that look interesting:

* `./Payload/Spotify.app/Spotify`
* `./Payload/Spotify.app/Frameworks/SpotifyShared.framework/SpotifyShared` (Only on later versions)

`SpotifyShared` contains some Login5 code and seems to be UI related. Since it isn't present in old versions lets just ignore it for now.

The main `Spotify` binary is a Mach-O file which supports multi-architecture. To properly analyze it, it needs splitting into architecture specific files which can be done using [Lipo](https://keith.github.io/xcode-man-pages/lipo.1.html). A linux port is available at [tpoechtrager/cctools-port/](https://github.com/tpoechtrager/cctools-port/) for non-mac users. The oldest version on archive.org supports iOS 4 and has `armv6` and `armv7` architectures.

### Theory

The injector will need to find offsets for all architectures that the binary supports. All offsets should be sent to the frida script which will then detect the architecture it is running on and use the correct set of offsets accordingly. I need to learn more about Mach-O and iOS in general before I'll be able to write this part however a pull request is always welcome.

### Versions

#### 0.4.26.1.g01466bb9 (eb9b670a3255961df5f0e7257e5922cb)

This is the iOS 4 version mentioned above. On armv7 there is only one occurrence of the constant and encryption functions aren't nearby. On armv6 there are 3 occurrences, shn_finish contains the last one and the encryption functions are directly before. These are the important bits:

```asm
shn_addr2
__text:000FC51C F0 40 2D E9                 PUSH    {R4-R7,LR}
__text:000FC520 0C 70 8D E2                 ADD     R7, SP, #0xC
__text:000FC524 00 0D 2D E9                 PUSH    {R8,R10,R11}
__text:000FC528 08 D0 4D E2                 SUB     SP, SP, #8
__text:000FC52C 00 40 A0 E1                 MOV     R4, R0
__text:000FC530 01 80 A0 E1                 MOV     R8, R1
__text:000FC534 CC 10 94 E5                 LDR     R1, [R4,#0xCC]
__text:000FC538 02 B0 A0 E1                 MOV     R11, R2
__text:000FC53C 00 00 51 E3                 CMP     R1, #0
__text:000FC540 1E 00 00 0A                 BEQ     loc_FC5C0
__text:000FC544 00 20 A0 E3                 MOV     R2, #0
__text:000FC548 00 00 5B E3                 CMP     R11, #0
__text:000FC54C 16 00 00 0A                 BEQ     loc_FC5AC
__text:000FC550 01 00 4B E2                 SUB     R0, R11, #1

shn_addr1
__text:000FD634 F0 40 2D E9                 PUSH    {R4-R7,LR}
__text:000FD638 0C 70 8D E2                 ADD     R7, SP, #0xC
__text:000FD63C 00 0D 2D E9                 PUSH    {R8,R10,R11}
__text:000FD640 08 D0 4D E2                 SUB     SP, SP, #8
__text:000FD644 00 40 A0 E1                 MOV     R4, R0
__text:000FD648 02 B0 A0 E1                 MOV     R11, R2
__text:000FD64C CC 50 94 E5                 LDR     R5, [R4,#0xCC]
__text:000FD650 01 80 A0 E1                 MOV     R8, R1
__text:000FD654 00 00 55 E3                 CMP     R5, #0
__text:000FD658 21 00 00 0A                 BEQ     loc_FD6E4
__text:000FD65C 00 20 A0 E3                 MOV     R2, #0
__text:000FD660 00 00 5B E3                 CMP     R11, #0
__text:000FD664 19 00 00 0A                 BEQ     loc_FD6D0
__text:000FD668 01 10 4B E2                 SUB     R1, R11, #1

shn_finish
__text:000FE710 F0 40 2D E9                 PUSH    {R4-R7,LR}
__text:000FE714 0C 70 8D E2                 ADD     R7, SP, #0xC
__text:000FE718 00 0D 2D E9                 PUSH    {R8,R10,R11}
__text:000FE71C 00 40 A0 E1                 MOV     R4, R0
__text:000FE720 02 80 A0 E1                 MOV     R8, R2
__text:000FE724 CC 00 94 E5                 LDR     R0, [R4,#0xCC]
__text:000FE728 01 A0 A0 E1                 MOV     R10, R1
__text:000FE72C 00 00 50 E3                 CMP     R0, #0
__text:000FE730 02 00 00 0A                 BEQ     loc_FE740
__text:000FE734 C8 10 94 E5                 LDR     R1, [R4,#0xC8]
__text:000FE738 04 00 A0 E1                 MOV     R0, R4
__text:000FE73C 6B F7 FF EB                 BL      sub_FC4F0

__text:000FE750 C4 10 9F E5                 LDR     R1, =0x6996C53A
```

#### 0.6.4.2.ge85967b8 (9dbd827cd49d781592c6acda86f3a148)

Only supports armv7. This version doesn't have function names stripped:

```asm
sp::ApConnectionImpl::powSolveHashcash
spotify::protocol::ap::PoWHashCashResponse::PoWHashCashResponse
spotify::protocol::ap::PoWHashCashChallenge::PoWHashCashChallenge
spotify::protocol::ap::FingerprintGrainChallenge::kek
boink::ProtobufOutputStream::ok
```

```asm
shn_addr2 (shn_encrypt)
__text:002EF480 F0 B5                       PUSH            {R4-R7,LR}
__text:002EF482 03 AF                       ADD             R7, SP, #0xC
__text:002EF484 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:002EF488 81 B0                       SUB             SP, SP, #4
__text:002EF48A 04 46                       MOV             R4, R0
__text:002EF48C 8A 46                       MOV             R10, R1
__text:002EF48E D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:002EF492 08 B9                       CBNZ            R0, loc_2EF498
__text:002EF494 90 46                       MOV             R8, R2
__text:002EF496 30 E0                       B               loc_2EF4FA

shn_addr1 (shn_decrypt)
__text:002F0324 F0 B5                       PUSH            {R4-R7,LR}
__text:002F0326 03 AF                       ADD             R7, SP, #0xC
__text:002F0328 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:002F032C 83 B0                       SUB             SP, SP, #0xC
__text:002F032E 04 46                       MOV             R4, R0
__text:002F0330 8A 46                       MOV             R10, R1
__text:002F0332 D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:002F0336 08 B9                       CBNZ            R0, loc_2F033C
__text:002F0338 90 46                       MOV             R8, R2
__text:002F033A 33 E0                       B               loc_2F03A4

shn_finish
__text:002F11B0 F0 B5                       PUSH            {R4-R7,LR}
__text:002F11B2 05 46                       MOV             R5, R0
__text:002F11B4 14 46                       MOV             R4, R2
__text:002F11B6 D5 F8 CC 00                 LDR.W           R0, [R5,#0xCC]
__text:002F11BA 0E 46                       MOV             R6, R1
__text:002F11BC 03 AF                       ADD             R7, SP, #0xC
__text:002F11BE 20 B1                       CBZ             R0, loc_2F11CA
__text:002F11C0 D5 F8 C8 10                 LDR.W           R1, [R5,#0xC8]
__text:002F11C4 28 46                       MOV             R0, R5
__text:002F11C6 FE F7 51 F9                 BL              __ZL7macfuncP7shn_ctxj ; macfunc(shn_ctx *,uint)

__text:002F11D4 4C F2 3A 52                 MOVW            R2, #0xC53A
__text:002F11D8 68 6B                       LDR             R0, [R5,#0x34]
__text:002F11DA C6 F6 96 12                 MOVT            R2, #0x6996
```

The symbols give us the internal names for many SPIRC protobuf definitions although this is a very old version of the app, before even login5.

#### 0.7.2.26.g5c684ef7 (72e7d6963d659c3b8493e1c4d887ca7a)
Only supports armv7. Again no symbols stripped.

```asm
shn_addr2 (shn_encrypt)
__text:003E896C F0 B5                       PUSH            {R4-R7,LR}
__text:003E896E 03 AF                       ADD             R7, SP, #0xC
__text:003E8970 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:003E8974 81 B0                       SUB             SP, SP, #4
__text:003E8976 04 46                       MOV             R4, R0
__text:003E8978 8A 46                       MOV             R10, R1
__text:003E897A D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:003E897E 08 B9                       CBNZ            R0, loc_3E8984
__text:003E8980 90 46                       MOV             R8, R2
__text:003E8982 30 E0                       B               loc_3E89E6

shn_addr1 (shn_decrypt)
__text:003E9810 F0 B5                       PUSH            {R4-R7,LR}
__text:003E9812 03 AF                       ADD             R7, SP, #0xC
__text:003E9814 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:003E9818 83 B0                       SUB             SP, SP, #0xC
__text:003E981A 04 46                       MOV             R4, R0
__text:003E981C 8A 46                       MOV             R10, R1
__text:003E981E D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:003E9822 08 B9                       CBNZ            R0, loc_3E9828
__text:003E9824 90 46                       MOV             R8, R2
__text:003E9826 33 E0                       B               loc_3E9890

shn_finish
__text:003EA69C F0 B5                       PUSH            {R4-R7,LR}
__text:003EA69E 05 46                       MOV             R5, R0
__text:003EA6A0 14 46                       MOV             R4, R2
__text:003EA6A2 D5 F8 CC 00                 LDR.W           R0, [R5,#0xCC]
__text:003EA6A6 0E 46                       MOV             R6, R1
__text:003EA6A8 03 AF                       ADD             R7, SP, #0xC
__text:003EA6AA 20 B1                       CBZ             R0, loc_3EA6B6
__text:003EA6AC D5 F8 C8 10                 LDR.W           R1, [R5,#0xC8]
__text:003EA6B0 28 46                       MOV             R0, R5
__text:003EA6B2 FE F7 51 F9                 BL              __ZL7macfuncP7shn_ctxj ; macfunc(shn_ctx *,uint)

__text:003EA6C0 4C F2 3A 52                 MOVW            R2, #0xC53A
__text:003EA6C4 68 6B                       LDR             R0, [R5,#0x34]
__text:003EA6C6 C6 F6 96 12                 MOVT            R2, #0x6996
```

#### 0.7.2.26.g5c684ef7 (9ac18ecfca39d6547ba0fb9d56a27d92)
Same sha256sum as 72e7d6963d659c3b8493e1c4d887ca7a

#### 0.7.2.26.g5c684ef7 (3bdf369fa0d199953c21c72073631d4f)
Same sha256sum as 72e7d6963d659c3b8493e1c4d887ca7a

#### Encrypted - bcf2b51545d4716998b5fdaa0f83eb9d
Nothing we can do here

#### Encrypted - fe6487c28188a06a9a850514247da0d1
Same sha256sum as bcf2b51545d4716998b5fdaa0f83eb9d

#### 1.8.1.8.gbd63e79 (14f6e462e4f6be2e60d29ee2b0fb1705)

This version only supports armv7. There are 2 occurrences of the constant, and shn_finish contains the last one:

```asm
shn_addr2
__text:0030D434 F0 B5                       PUSH            {R4-R7,LR}
__text:0030D436 03 AF                       ADD             R7, SP, #0xC
__text:0030D438 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:0030D43C 81 B0                       SUB             SP, SP, #4
__text:0030D43E 04 46                       MOV             R4, R0
__text:0030D440 0E 46                       MOV             R6, R1
__text:0030D442 D4 F8 CC 10                 LDR.W           R1, [R4,#0xCC]
__text:0030D446 90 46                       MOV             R8, R2
__text:0030D448 81 B3                       CBZ             R1, loc_30D4AC
__text:0030D44A B8 F1 00 0F                 CMP.W           R8, #0
__text:0030D44E 24 D0                       BEQ             loc_30D49A
__text:0030D450 40 46                       MOV             R0, R8

shn_addr1
__text:0030E2A8 F0 B5                       PUSH            {R4-R7,LR}
__text:0030E2AA 03 AF                       ADD             R7, SP, #0xC
__text:0030E2AC 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:0030E2B0 82 B0                       SUB             SP, SP, #8
__text:0030E2B2 04 46                       MOV             R4, R0
__text:0030E2B4 0D 46                       MOV             R5, R1
__text:0030E2B6 D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:0030E2BA 00 28                       CMP             R0, #0
__text:0030E2BC 2A D0                       BEQ             loc_30E314
__text:0030E2BE 00 21                       MOVS            R1, #0
__text:0030E2C0 00 2A                       CMP             R2, #0
__text:0030E2C2 29 D0                       BEQ             loc_30E318

shn_finish
__text:0030F0EC                                                     ; sub_24C280+C0↑p ...
__text:0030F0EC F0 B5                       PUSH            {R4-R7,LR}
__text:0030F0EE 06 46                       MOV             R6, R0
__text:0030F0F0 14 46                       MOV             R4, R2
__text:0030F0F2 D6 F8 CC 00                 LDR.W           R0, [R6,#0xCC]
__text:0030F0F6 0D 46                       MOV             R5, R1
__text:0030F0F8 03 AF                       ADD             R7, SP, #0xC
__text:0030F0FA 20 B1                       CBZ             R0, loc_30F106
__text:0030F0FC D6 F8 C8 10                 LDR.W           R1, [R6,#0xC8]
__text:0030F100 30 46                       MOV             R0, R6
__text:0030F102 FE F7 8D F9                 BL              sub_30D420

__text:0030F116 4C F2 3A 51+                MOV             R1, #0x6996C53A
__text:0030F116 C6 F6 96 11
```

#### 1.40.0.0.g9165563 (379288533e1f0d6325bff24206d4835d)

Only supports armv7. No symbols this time. There are 2 occurrences of the constant, the second is in shn_finish. The encryption functions are directly before shn_finish.

```asm
shn_addr2
__text:00F0AE08 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0AE0A 03 AF                       ADD             R7, SP, #0xC
__text:00F0AE0C 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:00F0AE10 81 B0                       SUB             SP, SP, #4
__text:00F0AE12 04 46                       MOV             R4, R0
__text:00F0AE14 0E 46                       MOV             R6, R1
__text:00F0AE16 D4 F8 CC 10                 LDR.W           R1, [R4,#0xCC]
__text:00F0AE1A 90 46                       MOV             R8, R2
__text:00F0AE1C 81 B3                       CBZ             R1, loc_F0AE80
__text:00F0AE1E B8 F1 00 0F                 CMP.W           R8, #0
__text:00F0AE22 24 D0                       BEQ             loc_F0AE6E
__text:00F0AE24 40 46                       MOV             R0, R8

shn_addr1
__text:00F0BC84 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0BC86 03 AF                       ADD             R7, SP, #0xC
__text:00F0BC88 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:00F0BC8C 82 B0                       SUB             SP, SP, #8
__text:00F0BC8E 04 46                       MOV             R4, R0
__text:00F0BC90 0D 46                       MOV             R5, R1
__text:00F0BC92 D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:00F0BC96 00 28                       CMP             R0, #0
__text:00F0BC98 2A D0                       BEQ             loc_F0BCF0
__text:00F0BC9A 00 21                       MOVS            R1, #0
__text:00F0BC9C 00 2A                       CMP             R2, #0
__text:00F0BC9E 29 D0                       BEQ             loc_F0BCF4

shn_finish
__text:00F0CAD0 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0CAD2 03 AF                       ADD             R7, SP, #0xC
__text:00F0CAD4 2D E9 00 05                 PUSH.W          {R8,R10}
__text:00F0CAD8 04 46                       MOV             R4, R0
__text:00F0CADA 90 46                       MOV             R8, R2
__text:00F0CADC D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:00F0CAE0 8A 46                       MOV             R10, R1
__text:00F0CAE2 20 B1                       CBZ             R0, loc_F0CAEE
__text:00F0CAE4 D4 F8 C8 10                 LDR.W           R1, [R4,#0xC8]
__text:00F0CAE8 20 46                       MOV             R0, R4
__text:00F0CAEA FE F7 83 F9                 BL              sub_F0ADF4

__text:00F0CAFE 4C F2 3A 51+                MOV             R1, #0x6996C53A
__text:00F0CAFE C6 F6 96 11
```

#### 1.40.0.0.g9165563 (d8c8dc87a166c9f3019ab143026071fa)

Only supports armv7. There are 2 occurrences of the constant, second is in shn_finish. The encryption functions are directly before

```asm
shn_addr2
__text:00F0AE08 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0AE0A 03 AF                       ADD             R7, SP, #0xC
__text:00F0AE0C 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:00F0AE10 81 B0                       SUB             SP, SP, #4
__text:00F0AE12 04 46                       MOV             R4, R0
__text:00F0AE14 0E 46                       MOV             R6, R1
__text:00F0AE16 D4 F8 CC 10                 LDR.W           R1, [R4,#0xCC]
__text:00F0AE1A 90 46                       MOV             R8, R2
__text:00F0AE1C 81 B3                       CBZ             R1, loc_F0AE80
__text:00F0AE1E B8 F1 00 0F                 CMP.W           R8, #0
__text:00F0AE22 24 D0                       BEQ             loc_F0AE6E
__text:00F0AE24 40 46                       MOV             R0, R8

shn_addr1
__text:00F0BC84 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0BC86 03 AF                       ADD             R7, SP, #0xC
__text:00F0BC88 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:00F0BC8C 82 B0                       SUB             SP, SP, #8
__text:00F0BC8E 04 46                       MOV             R4, R0
__text:00F0BC90 0D 46                       MOV             R5, R1
__text:00F0BC92 D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:00F0BC96 00 28                       CMP             R0, #0
__text:00F0BC98 2A D0                       BEQ             loc_F0BCF0
__text:00F0BC9A 00 21                       MOVS            R1, #0
__text:00F0BC9C 00 2A                       CMP             R2, #0
__text:00F0BC9E 29 D0                       BEQ             loc_F0BCF4

shn_finish
__text:00F0CAD0 F0 B5                       PUSH            {R4-R7,LR}
__text:00F0CAD2 03 AF                       ADD             R7, SP, #0xC
__text:00F0CAD4 2D E9 00 05                 PUSH.W          {R8,R10}
__text:00F0CAD8 04 46                       MOV             R4, R0
__text:00F0CADA 90 46                       MOV             R8, R2
__text:00F0CADC D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:00F0CAE0 8A 46                       MOV             R10, R1
__text:00F0CAE2 20 B1                       CBZ             R0, loc_F0CAEE
__text:00F0CAE4 D4 F8 C8 10                 LDR.W           R1, [R4,#0xC8]
__text:00F0CAE8 20 46                       MOV             R0, R4
__text:00F0CAEA FE F7 83 F9                 BL              sub_F0ADF4

__text:00F0CAFE 4C F2 3A 51+                MOV             R1, #0x6996C53A
__text:00F0CAFE C6 F6 96 11
```

#### 1.95.0.0.g89388157d5 (7afcc0f3c70a08a15579b6d93c05bb10)

Only supports armv7. There are 2 instances of the constant, the second is in shn_finish. shn_finish is directly after the encryption functions.

```asm
shn_addr2
__text:01ABF01C F0 B5                       PUSH            {R4-R7,LR}
__text:01ABF01E 03 AF                       ADD             R7, SP, #0xC
__text:01ABF020 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:01ABF024 82 B0                       SUB             SP, SP, #8
__text:01ABF026 04 46                       MOV             R4, R0
__text:01ABF028 0D 46                       MOV             R5, R1
__text:01ABF02A D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:01ABF02E 58 B3                       CBZ             R0, loc_1ABF088
__text:01ABF030 00 2A                       CMP             R2, #0
__text:01ABF032 00 F0 3B 87                 BEQ.W           loc_1ABFEAC

shn_addr1
__text:01ABFEB4 F0 B5                       PUSH            {R4-R7,LR}
__text:01ABFEB6 03 AF                       ADD             R7, SP, #0xC
__text:01ABFEB8 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:01ABFEBC 82 B0                       SUB             SP, SP, #8
__text:01ABFEBE 04 46                       MOV             R4, R0
__text:01ABFEC0 0D 46                       MOV             R5, R1
__text:01ABFEC2 D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:01ABFEC6 58 B3                       CBZ             R0, loc_1ABFF20
__text:01ABFEC8 00 2A                       CMP             R2, #0
__text:01ABFECA 00 F0 26 87                 BEQ.W           loc_1AC0D1A

shn_finish
__text:01AC0D22 F0 B5                       PUSH            {R4-R7,LR}
__text:01AC0D24 03 AF                       ADD             R7, SP, #0xC
__text:01AC0D26 2D E9 00 0D                 PUSH.W          {R8,R10,R11}
__text:01AC0D2A 04 46                       MOV             R4, R0
__text:01AC0D2C 90 46                       MOV             R8, R2
__text:01AC0D2E D4 F8 CC 00                 LDR.W           R0, [R4,#0xCC]
__text:01AC0D32 8A 46                       MOV             R10, R1
__text:01AC0D34 00 28                       CMP             R0, #0
__text:01AC0D36 1E BF                       ITTT NE
__text:01AC0D38 D4 F8 C8 10                 LDRNE.W         R1, [R4,#0xC8]

__text:01AC0D52 4C F2 3A 51+                MOV             R1, #0x6996C53A
__text:01AC0D52 C6 F6 96 11
```

#### 8.8.58-4.95.0.0082.gbfb5444b60

There are 6 occurrences of the constant. shn_finish contains the second occurrence. One of the encryption functions is before shn_finish, the other is a few subroutines later

```asm
shn_addr1
__text:0000000100984A7C FA 67 BB A9                 STP             X26, X25, [SP,#-0x10+var_40]!
__text:0000000100984A80 F8 5F 01 A9                 STP             X24, X23, [SP,#0x40+var_30]
__text:0000000100984A84 F6 57 02 A9                 STP             X22, X21, [SP,#0x40+var_20]
__text:0000000100984A88 F4 4F 03 A9                 STP             X20, X19, [SP,#0x40+var_10]
__text:0000000100984A8C FD 7B 04 A9                 STP             X29, X30, [SP,#0x40+var_s0]
__text:0000000100984A90 FD 03 01 91                 ADD             X29, SP, #0x40
__text:0000000100984A94 CA 0D 08 95                 BL              sub_104B881BC
__text:0000000100984A98 C8 02 00 34                 CBZ             W8, loc_100984AF0
__text:0000000100984A9C D5 1C 00 34                 CBZ             W21, loc_100984E34

shn_finish
__text:0000000100984E3C F8 5F BC A9                 STP             X24, X23, [SP,#-0x10+var_30]!
__text:0000000100984E40 F6 57 01 A9                 STP             X22, X21, [SP,#0x30+var_20]
__text:0000000100984E44 F4 4F 02 A9                 STP             X20, X19, [SP,#0x30+var_10]
__text:0000000100984E48 FD 7B 03 A9                 STP             X29, X30, [SP,#0x30+var_s0]
__text:0000000100984E4C FD C3 00 91                 ADD             X29, SP, #0x30
__text:0000000100984E50 DB 0C 08 95                 BL              sub_104B881BC
__text:0000000100984E54 68 00 00 34                 CBZ             W8, loc_100984E60
__text:0000000100984E58 23 0E 08 95                 BL              sub_104B886E4
__text:0000000100984E5C D3 0C 08 95                 BL              sub_104B881A8

__text:0000000100984E74 4A A7 98 52+                MOV             W10, #0x6996C53A
__text:0000000100984E74 CA 32 AD 72

shn_addr2
__text:00000001009851A0 FA 67 BB A9                 STP             X26, X25, [SP,#-0x10+var_40]!
__text:00000001009851A4 F8 5F 01 A9                 STP             X24, X23, [SP,#0x40+var_30]
__text:00000001009851A8 F6 57 02 A9                 STP             X22, X21, [SP,#0x40+var_20]
__text:00000001009851AC F4 4F 03 A9                 STP             X20, X19, [SP,#0x40+var_10]
__text:00000001009851B0 FD 7B 04 A9                 STP             X29, X30, [SP,#0x40+var_s0]
__text:00000001009851B4 FD 03 01 91                 ADD             X29, SP, #0x40
__text:00000001009851B8 01 0C 08 95                 BL              sub_104B881BC
__text:00000001009851BC 08 03 00 34                 CBZ             W8, loc_10098521C
__text:00000001009851C0 55 1E 00 34                 CBZ             W21, loc_100985588

```
