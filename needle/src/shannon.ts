import { status, error, info } from "./log";
import LaunchArguments from "./launchArguments";
import SPIRCParser from "./spirc";

type ShannonFunctions = {
  shn_encrypt: NativePointer;
  shn_decrypt: NativePointer;
};

const BEFORE_ENCRYPT =
  "039ee193f9d9753dce1067983847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dd1a5da0de30062d26b203740300000005000000080000000d0000001500000022000000370000005900000090000000e90000007803030466020000db030000a2e8cb48004a1f84039ee193f9d9753dce1067983847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dd1a5da0de30062d039ee193af31947d0000000000000000";
const AFTER_ENCRYPT =
  "9d3a689dce1067983847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dc185ea4de30062d5ca42dff0300000005000000080000000d0000001500000022000000370000005900000090000000e90000007803030466020000db030000a2e8cb48004a1f8422fa1ff4039ee193f9d9753dce1067983847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dd1a5da0de30062d039ee193753af9270000000000000000";
const BEFORE_DECRYPT = AFTER_ENCRYPT;
const AFTER_DECRYPT =
  "1459b4e73847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dc185ea4c99a349d5ca42dff521adbf705000000080000000d0000001500000022000000370000005900000090000000e90000007803030466020000db030000a2e8cb48004a1f8422fa1ff43e502d44039ee193f9d9753dce1067983847bb3885790e92cbeaeee42293384a5669187e773ed644d846803565c34548100569c791c93f5bc99f64b2dd1a5da0de30062d039ee1936392c8930000000000000000";
const CTX_SIZE = 208; // sizeof(int) is 4 bytes on 32 and 64 bit

function loadHex(ptr: NativePointer, str: string) {
  if (str.length % 2 != 0) {
    return;
  }
  for (let i = 0; i < str.length / 2; i++) {
    ptr.add(i).writeU8(parseInt(`0x${str.substring(i * 2, i * 2 + 2)}`));
  }
}
const padHex = (str: string) => "00".substring(0, 2 - str.length) + str;
function toHex(ptr: NativePointer, size: number): string {
  let str = "";
  for (let i = 0; i < size; i++) {
    str += padHex(ptr.add(i).readU8().toString(16));
  }
  return str;
}

enum ShannonTestResult {
  NONE = 0,
  ENCRYPT,
  DECRYPT,
}
function testFunc(addr: NativePointer): ShannonTestResult {
  const func = new NativeFunction(addr, "void", ["pointer", "pointer", "int"]);
  const buff = Memory.alloc(4);
  const ctx = Memory.alloc(CTX_SIZE);

  loadHex(buff, "01020304");
  loadHex(ctx, BEFORE_ENCRYPT);
  func(ctx, buff, 4);
  if (toHex(ctx, CTX_SIZE) === AFTER_ENCRYPT) {
    return ShannonTestResult.ENCRYPT;
  }

  loadHex(buff, "7438fa23");
  loadHex(ctx, BEFORE_DECRYPT);
  func(ctx, buff, 4);
  if (toHex(ctx, CTX_SIZE) === AFTER_DECRYPT) {
    return ShannonTestResult.DECRYPT;
  }

  return ShannonTestResult.NONE;
}

function determine(
  addr1: NativePointer,
  addr2: NativePointer
): ShannonFunctions {
  const functions: ShannonFunctions = {
    shn_encrypt: NULL,
    shn_decrypt: NULL,
  };

  switch (testFunc(addr1)) {
    case ShannonTestResult.ENCRYPT: {
      functions.shn_encrypt = addr1;
      status(`Determined {${DebugSymbol.fromAddress(addr1)}} is shn_encrypt`);
      break;
    }
    case ShannonTestResult.DECRYPT: {
      functions.shn_decrypt = addr1;
      status(`Determined {${DebugSymbol.fromAddress(addr1)}} is shn_decrypt`);
      break;
    }
    default: {
      error(`Failed to determine what {${DebugSymbol.fromAddress(addr1)}} is`);
    }
  }

  switch (testFunc(addr2)) {
    case ShannonTestResult.ENCRYPT: {
      functions.shn_encrypt = addr2;
      status(`Determined {${DebugSymbol.fromAddress(addr2)}} is shn_encrypt`);
      break;
    }
    case ShannonTestResult.DECRYPT: {
      functions.shn_decrypt = addr2;
      status(`Determined {${DebugSymbol.fromAddress(addr2)}} is shn_decrypt`);
      break;
    }
    default: {
      error(`Failed to determine what {${DebugSymbol.fromAddress(addr2)}} is`);
    }
  }

  return functions;
}

type ShnFuncCtx = {
  c: NativePointer;
  buf: NativePointer;
  nbytes: number;
};
class SafeCallers {
  static shn_encrypt: NativePointer = NULL;
  static shn_decrypt: NativePointer = NULL;
}

function callStack(context: CpuContext) {
  return (
    "\t" +
    Thread.backtrace(context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join("\n\t")
  );
}

export function hook() {
  status("Hooking shannon functions");
  const shannon = determine(
    ptr(LaunchArguments.shnAddr1),
    ptr(LaunchArguments.shnAddr2)
  );
  if (shannon.shn_encrypt.isNull() || shannon.shn_decrypt.isNull()) {
    error("Failed to determine one or more shannon functions");
    return;
  }

  Interceptor.attach(shannon.shn_encrypt, {
    onEnter: function (args) {
      if (
        !LaunchArguments.shannonDisableSafeCallers &&
        !SafeCallers.shn_encrypt.isNull()
      ) {
        if (
          this.returnAddress < SafeCallers.shn_encrypt.sub(0x10) ||
          this.returnAddress > SafeCallers.shn_encrypt.add(0x10)
        ) {
          if (LaunchArguments.shannonLogInvalidCalls) {
            info(
              `\nSPIRC: (send) Ignoring call from invalid return address {${DebugSymbol.fromAddress(
                this.returnAddress
              )}}\n${hexdump(args[1], {
                length: args[2].toUInt32(),
                header: false,
              })}`
            );
          }
          return;
        }
      } else {
        SafeCallers.shn_encrypt = this.returnAddress;
      }

      const ctx = this as unknown as ShnFuncCtx;
      ctx.c = args[0];
      ctx.buf = args[1];
      ctx.nbytes = args[2].toUInt32();
      const data = ctx.buf.readByteArray(ctx.nbytes) || new ArrayBuffer(0);
      SPIRCParser.send(data);
      if (LaunchArguments.shannonLogCallStacks) {
        console.log(callStack(this.context));
      }
    },
    onLeave: function () {},
  });
  Interceptor.attach(shannon.shn_decrypt, {
    onEnter: function (args) {
      const ctx = this as unknown as ShnFuncCtx;
      ctx.c = args[0];
      ctx.buf = args[1];
      ctx.nbytes = args[2].toUInt32();
    },
    onLeave: function () {
      const ctx = this as unknown as ShnFuncCtx;
      const data = ctx.buf.readByteArray(ctx.nbytes) || new ArrayBuffer(0);

      if (
        !LaunchArguments.shannonDisableSafeCallers &&
        !SafeCallers.shn_decrypt.isNull()
      ) {
        if (
          this.returnAddress < SafeCallers.shn_decrypt.sub(0x100) ||
          this.returnAddress > SafeCallers.shn_decrypt.add(0x100)
        ) {
          if (LaunchArguments.shannonLogInvalidCalls) {
            info(
              `\nSPIRC: (recv) Ignoring call from invalid return address {${DebugSymbol.fromAddress(
                this.returnAddress
              )}}\n${hexdump(data, {
                header: false,
              })}`
            );
          }
          return;
        }
      } else {
        SafeCallers.shn_decrypt = this.returnAddress;
      }

      SPIRCParser.recv(data);
      if (LaunchArguments.shannonLogCallStacks) {
        console.log(callStack(this.context));
      }
    },
  });

  status("Hooked shannon functions");
}
