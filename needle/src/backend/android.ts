import LaunchArguments from "../launchArguments";
import { status, info } from "../log";
import { postInit, preInit } from ".";
import { getRtldFlags } from "./linux";

const LIB_NAME = "liborbit-jni-spotify.so";

function hookDlopen() {
  // https://developer.android.com/ndk/reference/structandroid/dlextinfo
  Interceptor.attach(Module.getExportByName(null, "android_dlopen_ext"), {
    onEnter: function (args) {
      const filename = args[0].readCString();
      const flag = args[1].toUInt32();
      const dlExtInfo = args[2];
      info(
        `android_dlopen_ext(${filename}, ${getRtldFlags(flag)}, ${dlExtInfo})`
      );

      if (filename && filename.toLowerCase().includes(LIB_NAME)) {
        this.isOrbitLib = true;
      }
    },
    onLeave: function () {
      if (this.isOrbitLib) {
        const module = Process.getModuleByName(LIB_NAME);
        status(`Spotify JNI loaded at ${module.base}`);
        LaunchArguments.relocate(module.base);
        postInit();
      }
    },
  });
}

export function androidInit(launchArgs: any) {
  preInit(launchArgs);
  hookDlopen();
  status(`Hooked dlopen`);
}
