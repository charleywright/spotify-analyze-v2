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

import {enumerateDevices, spawn, Script} from "frida"
import parser from "yargs-parser"

const argv = parser(process.argv, {
  configuration: {
    "camel-case-expansion": false,
    "parse-numbers": false
  }
})

function parseOffsets(argv) {
  const offsetsNames = Object.keys(argv).filter(key => {
    if (key === "_") return false;
    if (key === "platform") return false;
    if (key === "exec") return false;
    if (key.startsWith("$")) return false;
    return true;
  });

  return Object.fromEntries(offsetsNames.map(name => ([name, argv[name]])));
}

(async () => {
  if (!argv.platform) {
    console.error("platform is required");
    process.exit(1);
  }
  if (!argv.exec) {
    console.error("exec is required");
    process.exit(1);
  }

  console.log(argv._)

  switch (argv.platform) {
    case "linux": {
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
    default: {
      console.error(`Invalid platform "${argv.platform}"`);
      process.exit(1);
      break;
    }
  }
})()
