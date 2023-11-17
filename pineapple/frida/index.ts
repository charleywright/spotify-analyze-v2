/*
Very good tool for searching for structures
https://codebrowser.dev/

TODO: IPv6
*/

const TARGET_IP = `192.168.12.1`;
const TARGET_PORT = 4070;

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
