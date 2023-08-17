import LaunchArguments from "../launchArguments";
import { status } from "../log";
import { hook as hookShannonFunctions } from "../shannon";
import "../base64-polyfill";

export function preInit(launchArgs: any) {
  LaunchArguments.init(launchArgs);
  (globalThis as any).Buffer = undefined;
  (global as any).Buffer = undefined;

  status(
    `Injected into process. Got arguments:\n${JSON.stringify(
      launchArgs,
      null,
      2
    )}`
  );
}

export function postInit() {
  hookShannonFunctions();
}
