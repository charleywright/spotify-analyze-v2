#!/usr/bin/env node

/*
This is a small script that uses the Frida Node.js bindings to spawn a Spotify
process, inject our script then pass the offsets found by the injector to the
script. In the future this script should be removed, and it's purpose integrated
into the injector using the Frida C API however due to a lack of documentation,
time, and having issues building frida-core, I won't be doing this anytime soon.

Usage: node bootstrap.mjs --platform <platform> --exec <executable> [offsets]

platform should be one of "linux", "windows", "android" or "ios"
exec is platform dependant. it is the value supplied to frida -f
offsets are specified as "--key value" and will all be sent to the frida script
 */

import parser from "yargs-parser";
import frida from "frida";
import fs from "node:fs";

function sleep(milli) {
  return new Promise((resolve) => setTimeout(resolve, milli));
}

(async () => {
  const args = parser(process.argv, {
    configuration: {
      "camel-case-expansion": false,
      "parse-numbers": false,
    },
  });

  const offsets = Object.fromEntries(
    args._.slice(2).map((str) => str.toString().split("="))
  );

  const { platform, exec } = args;

  if (!platform || !exec) {
    console.error(`platform and executable required`);
    process.exit(1);
  }

  switch (platform) {
    case "linux": {
      const scriptSrc = fs.readFileSync("./build/linux.js", "utf-8");
      const pid = await frida.spawn(exec);
      const session = await frida.attach(pid);
      const script = await session.createScript(scriptSrc);
      await script.load();
      await script.exports.init(offsets);
      await sleep(1000);
      await frida.resume(pid);
      break;
    }
    case "windows": {
      break;
    }
    case "android": {
      break;
    }
    case "ios": {
      break;
    }
  }
})();
