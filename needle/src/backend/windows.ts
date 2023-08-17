import { status, info } from "../log";
import { postInit, preInit } from "./any";
import LaunchArguments from "../launchArguments";

enum LL_FLAGS {
  DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
  LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
  LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
  LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
  LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
  LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
  LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
  LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
  LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
  LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
  LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008,
  LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x00000080,
  LOAD_LIBRARY_SAFE_CURRENT_DIRS = 0x00002000,
}

function hookLoadLibrary() {
  // LoadLibrary is called over and over again with these
  const WHITELIST = [
    "crypt32.dll",
    "rsaenh.dll",
    "cryptnet.dll",
    "dsound.dll",
    "kernel32.dll",
    "System32",
  ];
  function checkWhitelist(str: string | null) {
    return (
      WHITELIST.filter((s) => str?.toLowerCase().includes(s.toLowerCase()))
        .length > 0
    );
  }

  // Interceptor.attach(Module.getExportByName(null, "LoadLibraryA"), {
  //   onEnter: function (args) {
  //     info(`LoadLibraryA(${args[0].readUtf8String()})`);
  //   },
  // });
  // Interceptor.attach(Module.getExportByName(null, "LoadLibraryW"), {
  //   onEnter: function (args) {
  //     info(`LoadLibraryW(${args[0].readUtf16String()})`);
  //   },
  // });
  function getDwFlags(dwFlags: number): string {
    let str = "";
    for (const flag in LL_FLAGS) {
      // Enums create { A: 0, 0: "A" }
      if (isNaN(+flag)) {
        continue;
      }
      if (dwFlags & +flag) {
        str += ` | ${LL_FLAGS[flag]}`;
      }
    }
    return str.length > 0 ? str.substring(3) : str;
  }
  // Interceptor.attach(Module.getExportByName(null, "LoadLibraryExA"), {
  //   onEnter: function (args) {
  //     info(
  //       `LoadLibraryExA(${args[0].readUtf8String()}, ${args[1]}, "${getDwFlags(
  //         args[2].toUInt32()
  //       )}")`
  //     );
  //   },
  // });
  Interceptor.attach(Module.getExportByName(null, "LoadLibraryExW"), {
    // LoadLibraryA -> LoadLibraryExA -> LoadLibraryExW
    // LoadLibraryExA -> LoadLibraryExW
    // LoadLibraryW -> LoadLibraryExW
    onEnter: function (args) {
      const lpLibFileName = args[0].readUtf16String();
      const hFile = args[1];
      const dwFlags = args[2].toUInt32();
      if (checkWhitelist(lpLibFileName)) {
        return;
      }
      info(
        `LoadLibraryExW(${lpLibFileName}, ${hFile}, "${getDwFlags(dwFlags)}")`
      );
    },
  });
}

function init(launchArgs: any) {
  preInit(launchArgs);

  const moduleBase = Process.getModuleByName("Spotify.exe").base;
  LaunchArguments.relocate(moduleBase);

  hookLoadLibrary();
  status(`Hooked LoadLibraryA/LoadLibraryW`);

  postInit();
}

rpc.exports.init = init;
