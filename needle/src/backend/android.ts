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

function overrideProxy(proxy_host: string, proxy_port: number) {
  function proxy_2_str(proxy: Java.Wrapper<{}>) {
    return proxy == null
      ? "<NONE>"
      : `${proxy["getHost"]()}:${proxy["getPort"]()}`;
  }

  Java.perform(() => {
    const ConnectivityManager = Java.use("android.net.ConnectivityManager");
    const ProxyInfo = Java.use("android.net.ProxyInfo");

    ConnectivityManager["getDefaultProxy"].implementation = function () {
      let system_proxy = this["getDefaultProxy"]();
      let new_proxy = ProxyInfo["buildDirectProxy"](proxy_host, proxy_port);
      console.log(
        `[PROXY] Overriding ${proxy_2_str(system_proxy)} with ${proxy_2_str(
          new_proxy
        )}`
      );
      return new_proxy;
    };
  });
}

export function androidInit(launchArgs: any) {
  preInit(launchArgs);
  /*
    Completely broken on Android. Once detection uses XREFS
    and disassembly they can be enabled again.
  */
  LaunchArguments.shannonDisableSafeCallers = true;
  hookDlopen();
  status(`Hooked dlopen`);
}
