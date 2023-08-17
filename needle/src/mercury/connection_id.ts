import { MercuryHandler, logRecv } from ".";
import { warn } from "../log";
import { arrayToText } from "../utils";

export const ConnectionIdHandler: MercuryHandler = {
  template: "hm://pusher/v1/connections/[]",
  handler(header, parts) {
    if (parts.length !== 0) {
      warn(
        `Mercury: (recv) Expected no parts for connection ID update. Got\n${parts
          .map((p) => hexdump(p))
          .join("\n")}`
      );
      return;
    }
    const connectionId = header.userFields.filter(
      (field) => field.key.toLowerCase() === "spotify-connection-id"
    );
    if (connectionId.length === 0) {
      warn(`Mercury: (recv) Expected connection ID in header`);
      return;
    }
    logRecv(`Got connection ID ${arrayToText(connectionId[0].value)}`);
  },
};
