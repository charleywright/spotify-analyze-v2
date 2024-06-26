import { status } from "../log";
import { postInit, preInit } from ".";
import LaunchArguments from "../launchArguments";

function dyldImageCount(): number {
  const _dyld_image_count_addr = Module.getExportByName(
    null,
    "_dyld_image_count"
  );
  const _dyld_image_count = new NativeFunction(
    _dyld_image_count_addr,
    "uint32",
    []
  );
  return _dyld_image_count();
}

function dyldGetImageHeader(index: number): NativePointer {
  const _dyld_get_image_header_addr = Module.getExportByName(
    null,
    "_dyld_get_image_header"
  );
  const _dyld_get_image_header = new NativeFunction(
    _dyld_get_image_header_addr,
    "pointer",
    ["uint32"]
  );
  return _dyld_get_image_header(index);
}

export function iosInit(launchArgs: any) {
  preInit(launchArgs);
  const checkInt = setInterval(() => {
    const mod = Process.findModuleByName("Spotify");
    if (mod !== null) {
      clearInterval(checkInt);
      status(`Spotify binary loaded at ${mod.base}`);
      LaunchArguments.relocate(mod.base);
      postInit();
    }
  }, 100);
}
