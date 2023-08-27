import { MercuryHandler } from ".";
import { logSend, logRecv } from ".";
import { warn } from "../log";
import { arrayToText } from "../utils";

export const SendEventHandler: MercuryHandler = {
  template: "hm://event-service/v1/events",
  handler(header, parts) {
    switch (header.method) {
      case "POST": {
        if (parts.length !== 1) {
          warn(`Mercury: (send) Expected one part for POST event`);
          return;
        }

        const data = parts[0];
        const dataText = arrayToText(new Uint8Array(data));
        // The splitter is 0x09 or \t. Might as well just print the whole thing
        logSend(dataText);
        break;
      }
      default: {
        warn(`Unhandled method ${header.method} for mercury event service`);
        break;
      }
    }
  },
};

export const RecvEventHandler: MercuryHandler = {
  template: "hm://event-service/v1/events",
  handler(header, parts) {
    if (header.statusCode === 200) {
      logRecv("Accepted event");
    } else {
      warn(`Mercury: (recv) Got status ${header.statusCode} for event-service`);
    }
  },
};
