import * as Mercury from "../proto/mercury/mercury.old";
import { warn, info, Color, RST_COL_CODE, color_code } from "../log";
import { PacketType } from "../spirc";

import { ConnectionIdHandler } from "./connection_id";

export function logSend(message: string) {
  console.log(`${color_code(Color.GREEN)}${message}${RST_COL_CODE}`);
}

export function logRecv(message: string) {
  console.log(`${color_code(Color.CYAN)}${message}${RST_COL_CODE}`);
}

function urlMatch(url: string, template: string): boolean {
  const url_parts = url.split("/");
  const template_parts = template.split("/");
  if (url_parts.length != template_parts.length) {
    return false;
  }
  for (let i = 0; i < url_parts.length; i++) {
    if (template_parts[i].startsWith("[") && template_parts[i].endsWith("]")) {
      continue;
    }
    if (url_parts[i] != template_parts[i]) {
      return false;
    }
  }
  return true;
}

class MercuryStorage {
  static inProgress = {} as { [k: string]: ArrayBuffer[] };
}

function parsePacket(data: ArrayBuffer): [string, number] {
  const dv = new DataView(data);
  let offset = 0;
  const sequenceLen = dv.getUint16(offset);
  offset += 2;
  let sequence = BigInt(0);
  switch (sequenceLen) {
    case 2: {
      sequence = BigInt(dv.getUint16(offset));
      break;
    }
    case 4: {
      sequence = BigInt(dv.getUint32(offset));
      break;
    }
    case 8: {
      sequence = dv.getBigUint64(offset);
      break;
    }
    default: {
      return ["", 0];
    }
  }
  const sequenceStr = sequence.toString();
  offset += sequenceLen;
  if (!(sequenceStr in MercuryStorage.inProgress)) {
    MercuryStorage.inProgress[sequenceStr] = [];
  }
  const flags = dv.getUint8(offset);
  offset += 1;
  const numParts = dv.getUint16(offset);
  offset += 2;
  for (let i = 0; i < numParts; i++) {
    const partLen = dv.getUint16(offset);
    offset += 2;
    MercuryStorage.inProgress[sequenceStr][i] = new ArrayBuffer(partLen);
    const partView = new DataView(MercuryStorage.inProgress[sequenceStr][i]);
    for (let j = 0; j < partLen; j++) {
      partView.setUint8(j, dv.getUint8(offset + j));
    }
    offset += partLen;
  }
  return [sequenceStr, flags];
}

export type MercuryHandler = {
  template: string;
  handler: { (header: Mercury.Header, parts: ArrayBuffer[]): void };
};
const SEND_HANDLERS: MercuryHandler[] = [];
const RECV_HANDLERS: MercuryHandler[] = [ConnectionIdHandler];

export function send(type: PacketType, data: ArrayBuffer) {
  const typeStr = PacketType[type];
  const [seqStr, flags] = parsePacket(data);
  if (seqStr === "") {
    warn(
      `Mercury: (send) Failed to parse type=${typeStr}\n${hexdump(data, {
        header: false,
      })}`
    );
    return;
  }
  if ((flags & 1) != 1) {
    return; // Not end of packet
  }
  let parts = MercuryStorage.inProgress[seqStr];
  delete MercuryStorage.inProgress[seqStr];

  if (parts.length === 0) {
    warn(
      `Mercury: (send) No parts for packet of type ${typeStr}\n${hexdump(data, {
        header: false,
      })}`
    );
    return;
  }

  try {
    const header = Mercury.Header.decode(new Uint8Array(parts[0]));
    parts.shift();
    const url = header.uri;
    logSend(
      `[SEND] [M] type=${typeStr} seq=${seqStr} parts=${parts.length} url=${url}`
    );
    logSend(JSON.stringify(Mercury.Header.toJSON(header), null, 2));

    for (let i = 0; i < SEND_HANDLERS.length; i++) {
      if (urlMatch(url, SEND_HANDLERS[i].template)) {
        SEND_HANDLERS[i].handler(header, parts);
        return;
      }
    }

    warn(
      `Mercury: (send) No handler for ${url}\n${
        parts.length === 0
          ? "<No parts>"
          : parts.map((p) => hexdump(p)).join("\n")
      }`
    );
  } catch {
    warn(
      `Mercury: (send) Failed to parse header\n${parts
        .map((p) => hexdump(p))
        .join("\n")}`
    );
  }
}

export function recv(type: PacketType, data: ArrayBuffer) {
  const typeStr = PacketType[type];
  const [seqStr, flags] = parsePacket(data);
  if (seqStr === "") {
    warn(
      `Mercury: (recv) Failed to parse type=${typeStr}\n${hexdump(data, {
        header: false,
      })}`
    );
    return;
  }
  if ((flags & 1) != 1) {
    return; // Not end of packet
  }
  let parts = MercuryStorage.inProgress[seqStr];
  delete MercuryStorage.inProgress[seqStr];

  if (parts.length === 0) {
    warn(
      `Mercury: (recv) No parts for packet of type ${typeStr}\n${hexdump(data, {
        header: false,
      })}`
    );
    return;
  }

  try {
    const header = Mercury.Header.decode(new Uint8Array(parts[0]));
    parts.shift();
    const url = header.uri;
    logRecv(
      `[RECV] [M] type=${typeStr} seq=${seqStr} parts=${parts.length} url=${url}`
    );
    logRecv(JSON.stringify(Mercury.Header.toJSON(header), null, 2));

    for (let i = 0; i < RECV_HANDLERS.length; i++) {
      if (urlMatch(url, RECV_HANDLERS[i].template)) {
        RECV_HANDLERS[i].handler(header, parts);
        return;
      }
    }

    warn(
      `Mercury: (recv) No handler for ${url}\n${
        parts.length === 0
          ? "<No parts>"
          : parts.map((p) => hexdump(p)).join("\n")
      }`
    );
  } catch {
    warn(
      `Mercury: (recv) Failed to parse header\n${parts
        .map((p) => hexdump(p))
        .join("\n")}`
    );
  }
}

export default {
  send,
  recv,
};
