/*
Very good tool for searching for structures
https://codebrowser.dev/

TODO: IPv6
*/

const TARGET_IP = `192.168.1.120`;
const TARGET_PORT = 4070;
const SERVER_KEY_ARM64_OFFSET = 0x312cbc;
const OUR_SERVER_KEY = [
  0x94, 0x8f, 0x67, 0xa9, 0x51, 0xd7, 0x5f, 0x38, 0xa4, 0x36, 0x19, 0x11, 0x28,
  0x32, 0xad, 0x49, 0x33, 0xdd, 0x00, 0xf5, 0xdd, 0x24, 0xe6, 0xb9, 0x10, 0xed,
  0xd3, 0x8c, 0xcd, 0xd0, 0x0a, 0x3d, 0x77, 0x30, 0x8f, 0x91, 0x7c, 0x96, 0x43,
  0xbe, 0x2b, 0x17, 0x7d, 0x2a, 0x4f, 0xaf, 0x7d, 0xdb, 0x35, 0xd4, 0xe5, 0x41,
  0x8a, 0x33, 0x18, 0xd1, 0x2c, 0x00, 0xe6, 0x07, 0xf4, 0xd3, 0xc6, 0xd4, 0x1f,
  0xc8, 0xd6, 0xf5, 0x26, 0x16, 0x59, 0xea, 0x71, 0x32, 0xec, 0xda, 0xeb, 0x0f,
  0x55, 0x70, 0xd0, 0x98, 0x21, 0x57, 0x6b, 0x87, 0x1a, 0x03, 0x64, 0x2c, 0x8c,
  0xe1, 0x3c, 0x8e, 0xa8, 0x02, 0x7c, 0x8a, 0x1b, 0x9a, 0xe9, 0xcc, 0x36, 0x7d,
  0x9c, 0x3f, 0xbf, 0x02, 0xc6, 0x7f, 0xc1, 0x6f, 0x46, 0x54, 0x5b, 0xe6, 0x95,
  0x05, 0x6e, 0x6b, 0x2b, 0x66, 0x0e, 0x4f, 0xae, 0xc2, 0xe7, 0x4a, 0xc1, 0x43,
  0x87, 0xa4, 0xf9, 0x56, 0x24, 0xda, 0x87, 0x3f, 0x78, 0x9a, 0x13, 0x55, 0x1f,
  0x32, 0x51, 0x93, 0x36, 0x1e, 0xa9, 0xf2, 0xee, 0x3a, 0xc8, 0xd2, 0x73, 0xd2,
  0x81, 0xa7, 0x6f, 0xfb, 0xe9, 0xbc, 0x87, 0xd7, 0x7d, 0xbd, 0xfb, 0xdf, 0x91,
  0xd5, 0x83, 0x76, 0xd3, 0x7c, 0x46, 0x8a, 0xd1, 0xc2, 0x73, 0x1c, 0x5e, 0xa1,
  0xa0, 0x9f, 0xf8, 0xc4, 0xaf, 0xcb, 0x8c, 0x7c, 0x86, 0x09, 0x8e, 0xd7, 0xc8,
  0x51, 0xc7, 0x2d, 0xac, 0x61, 0x37, 0x3b, 0x84, 0xa8, 0x4f, 0x7a, 0x76, 0x17,
  0x2d, 0x88, 0xf3, 0x16, 0x7f, 0x73, 0x83, 0x38, 0x86, 0x09, 0xe1, 0xcd, 0xe1,
  0x89, 0x3d, 0x9d, 0x91, 0x61, 0x6c, 0xb4, 0x5f, 0x4c, 0xf4, 0x93, 0x6d, 0xa8,
  0x42, 0xa2, 0x4b, 0xf6, 0xf1, 0x82, 0x1e, 0xcc, 0x05, 0xd2, 0x10, 0xff, 0xd3,
  0x9f, 0xe9, 0x12, 0x05, 0x3a, 0x0c, 0x0c, 0xa6, 0x93,
];

export function callStack() {
  let bt = "";
  Java.perform(function () {
    bt = exceptionCallStack(Java.use("java.lang.Exception").$new());
  });
  return bt;
}

export function nativeCallStack(ctx: CpuContext) {
  console.log(
    Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join("\n\t")
  );
}

export function exceptionCallStack(ex: Java.Wrapper<{}>) {
  return Java.use("android.util.Log")
    .getStackTraceString(ex)
    .replace(/^java\.lang\.Exception\n/, "");
}

export function arrayBuffer2Hex(
  buffer: ArrayBuffer | null,
  addSpaces = false
): string {
  return buffer
    ? [...new Uint8Array(buffer)]
        .map((x) => x.toString(16).padStart(2, "0"))
        .join(addSpaces ? " " : "")
    : "<EMPTY>";
}

type Replacement = {
  domain: RegExp;
  ip: string;
  port: number;
};
const replacements: Replacement[] = [
  {
    domain: /ap[\-a-z0-9]+\.spotify\.com/,
    ip: TARGET_IP,
    port: TARGET_PORT,
  },
  {
    domain: /mobile-ap\.spotify\.com/,
    ip: TARGET_IP,
    port: TARGET_PORT,
  },
];

type FdDetails = {
  domain: number;
  type: number;
  protocol: number;
};
const fds: { [k: number]: FdDetails } = {};

const resolvedIps: { [k: string]: string } = {};
const AF_INET = 2;
const AF_INET6 = 10;

class Sockaddr_in {
  /*
    struct sockaddr
    {
      unsigned short int sa_family;	  // Common data: address family and length.
      char sa_data[14];		            // Address data.
    };
    struct sockaddr_in
    {
      unsigned short int sin_family;
      uint16_t sin_port;
      struct in_addr sin_addr; // uint32_t
    };
  */

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  private ptr: NativePointer;

  getFamily(): number {
    if (this.ptr.isNull()) return 0;
    return this.ptr.add(0).readU16();
  }

  setFamily(family: number) {
    if (this.ptr.isNull()) return;
    this.ptr.add(0).writeU16(family & 0xffff);
  }

  getPort(): number {
    if (this.ptr.isNull()) return 0;
    return (this.ptr.add(2).readU8() << 8) | this.ptr.add(3).readU8();
  }

  setPort(port: number) {
    if (this.ptr.isNull()) return;
    this.ptr.add(2).writeU8((port >> 8) & 0xff);
    this.ptr.add(3).writeU8((port >> 0) & 0xff);
  }

  getIP(): string {
    if (this.ptr.isNull()) return "<NULL>";
    const octet0 = this.ptr.add(4 + 1 * 0).readU8();
    const octet1 = this.ptr.add(4 + 1 * 1).readU8();
    const octet2 = this.ptr.add(4 + 1 * 2).readU8();
    const octet3 = this.ptr.add(4 + 1 * 3).readU8();
    return `${octet0}.${octet1}.${octet2}.${octet3}`;
  }

  setIP(ip: string) {
    if (this.ptr.isNull()) return;

    if (ip.includes(":")) {
      const [actualIp, port] = ip.split(":");
      ip = actualIp;
      this.setPort(+port);
    }

    const [octet0, octet1, octet2, octet3] = ip.split(".");
    this.ptr.add(4 + 1 * 0).writeU8(+octet0 & 0xff);
    this.ptr.add(4 + 1 * 1).writeU8(+octet1 & 0xff);
    this.ptr.add(4 + 1 * 2).writeU8(+octet2 & 0xff);
    this.ptr.add(4 + 1 * 3).writeU8(+octet3 & 0xff);
  }

  toString(): string {
    return `Sockaddr_in{${this.getIP()}:${this.getPort()}}`;
  }
}

class Addrinfo {
  /*
    struct addrinfo
    {
      int ai_flags;			          // Input flags.
      int ai_family;		          // Protocol family for socket.
      int ai_socktype;		        // Socket type.
      int ai_protocol;		        // Protocol for socket.
      unsigned int ai_addrlen;		// Length of socket address.
      struct sockaddr *ai_addr;	  // Socket address for socket.
      char *ai_canonname;		      // Canonical name for service location.
      struct addrinfo *ai_next;	  // Pointer to next in list.
    };

                 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    7a284cd250  00 04 00 00 02 00 00 00 01 00 00 00 06 00 00 00  ................
    7a284cd260  10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    7a284cd270  80 d2 4c 28 7a 00 00 00 00 00 00 00 00 00 00 00  ..L(z...........

                {  flags  } {  family } {socktype } {protocol }
                { addrlen }
                {   addr  } <- Why not above? Maybe an optimisation on ARM64?
  */

  constructor(ptr: NativePointer) {
    this.ptr = ptr;
  }

  private ptr: NativePointer;

  // getFlags / setFlags / AI_ enum
  // getFamily / setFamily / AF_ enum
  // getSocktype / setSocktype / SOCK_ enum
  // getProtocol / setProtocol

  getAddrlen(): number {
    if (this.ptr.isNull()) return 0;
    return this.ptr.add(0x10).readU32();
  }

  getAddrPtr(): NativePointer {
    if (this.ptr.isNull()) return NULL;
    return this.ptr.add(0x20).readPointer();
  }

  // getCanonname / setCanonname
  // getNext / setNext

  toString(): string {
    const addrLen = this.getAddrlen();
    if (addrLen === 16) {
      return `Addrinfo{addr=${new Sockaddr_in(this.getAddrPtr())}}`;
    }
    return `Addrinfo{addr=unknown,addrLen=${addrLen}}`;
  }
}

const int = setInterval(() => {
  if (Process.findModuleByName("libc.so")) {
    clearInterval(int);
    // https://man7.org/linux/man-pages/man2/socket.2.html
    Interceptor.attach(Module.getExportByName(null, "socket"), {
      onEnter: function (args) {
        this.domain = args[0].toInt32();
        this.type = args[1].toInt32();
        this.protocol = args[2].toInt32();
      },
      onLeave: function (retval) {
        if (retval.equals(-1)) {
          return;
        }
        const domain: number = this.domain;
        const type: number = this.type;
        const protocol: number = this.protocol;
        const fd = retval.toInt32();
        fds[fd] = { domain, type, protocol };
      },
    });
    // https://man7.org/linux/man-pages/man2/close.2.html
    Interceptor.attach(Module.getExportByName(null, "close"), {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        delete fds[fd];
      },
    });
    // https://man7.org/linux/man-pages/man2/connect.2.html
    Interceptor.attach(Module.getExportByName(null, "connect"), {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const addr = args[1];
        const addrLen = args[2].toUInt32();
        const details = fds[fd];
        if (!details) {
          console.error(
            `connect(${fd}, ${addr}, ${addrLen}) FAILED TO FIND DETAILS FOR FD`
          );
          return;
        }
        if (details.domain != 2 /* INET */ || details.type != 1 /* TCP */) {
          return;
        }

        const sockaddr = new Sockaddr_in(addr);
        const resolved = resolvedIps[sockaddr.getIP()];
        if (resolved) {
          console.log(
            `connect(${fd}, ${addr}, ${addrLen}) ${sockaddr} (${resolved})`
          );
          for (const replacement of replacements) {
            if (new RegExp(replacement.domain).test(resolved)) {
              sockaddr.setIP(replacement.ip);
              sockaddr.setPort(replacement.port);
              console.log(
                `  Overriding ${resolved} with ${replacement.ip} - ${sockaddr}`
              );
            }
          }
        }
      },
    });
    // https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    Interceptor.attach(Module.getExportByName(null, "getaddrinfo"), {
      onEnter: function (args) {
        this.name = args[0];
        this.res = args[3];
      },
      onLeave: function (retval) {
        if (!retval.equals(0)) {
          return;
        }
        const res = (this.res as NativePointer).readPointer();
        const name: string = this.name.readCString();

        const addrinfo = new Addrinfo(res);
        const addrLen = addrinfo.getAddrlen();
        if (addrLen != 16) {
          console.error(
            `getaddrinfo: Expected sockaddr size 16, got ${addrLen}`
          );
          return;
        }
        const sockaddr = new Sockaddr_in(addrinfo.getAddrPtr());
        // console.log(`Resolved ${name} to ${sockaddr}`);
        resolvedIps[sockaddr.getIP()] = name;
      },
    });
  }
}, 100);

const int2 = setInterval(() => {
  const JNI = Process.findModuleByName("liborbit-jni-spotify.so");
  if (JNI) {
    clearInterval(int2);
    const serverKeyAddr = JNI.base.add(SERVER_KEY_ARM64_OFFSET);
    Memory.protect(serverKeyAddr, OUR_SERVER_KEY.length, "rwx");
    serverKeyAddr.writeByteArray(OUR_SERVER_KEY);
  }
}, 100);
