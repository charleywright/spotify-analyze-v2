import { LaunchArgs } from "../types/launchArgs";
import { status, info } from "../log";
import { hook as hookShannonFunctions } from "../shannon";
import "../base64-polyfill";

// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/bits/dlfcn.h#L24-L41
enum RTLD {
  LAZY = 0x00001,
  NOW = 0x00002,
  NOLOAD = 0x00004,
  DEEPBIND = 0x00008,
  GLOBAL = 0x00100,
  NODELETE = 0x01000,
}

function hookDlopen() {
  function getRtldFlags(flag: number): string {
    let str = "";
    if (flag & RTLD.LAZY) str += " | RTLD_LAZY";
    if (flag & RTLD.NOW) str += " | RTLD_NOW";
    if (flag & RTLD.NOLOAD) str += " | RTLD_NOLOAD";
    if (flag & RTLD.DEEPBIND) str += " | RTLD_DEEPBIND";
    if (flag & RTLD.GLOBAL) str += " | RTLD_GLOBAL";
    if (flag & RTLD.NODELETE) str += " | RTLD_NODELETE";
    return str.length > 0 ? str.substring(3) : "";
  }

  const dlopen = Module.getExportByName(null, "dlopen");
  Interceptor.attach(dlopen, {
    onEnter: function (args) {
      const filename = args[0].readCString();
      const flag = args[1].toUInt32();
      info(`dlopen(${filename}, ${getRtldFlags(flag)})`);
    },
  });
}

function init(launchArgs: LaunchArgs) {
  (globalThis as any).Buffer = undefined;
  (global as any).Buffer = undefined;

  status(
    `Injected into process. Got arguments:\n${JSON.stringify(
      launchArgs,
      null,
      2
    )}`
  );
  hookDlopen();
  status(`Hooked dlopen`);
  hookShannonFunctions(launchArgs);
}

rpc.exports.init = init;
