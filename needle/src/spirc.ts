import { warn, info, Color, RST_COL_CODE, color_code } from "./log";
import * as Authentication from "./proto/authentication/authentication.old";
import Mercury from "./mercury";

export enum PacketType {
  // SecretBlock = 0x02,
  Ping = 0x04,
  StreamChunk = 0x08,
  StreamChunkRes = 0x09,
  ChannelError = 0x0a,
  ChannelAbort = 0x0b,
  RequestKey = 0x0c,
  AesKey = 0x0d,
  AesKeyError = 0x0e,
  Image = 0x19,
  CountryCode = 0x1b,
  Pong = 0x49,
  PongAck = 0x4a,
  Pause = 0x4b,
  ProductInfo = 0x50,
  LegacyWelcome = 0x69,
  LicenseVersion = 0x76,
  Login = 0xab,
  APWelcome = 0xac,
  AuthFailure = 0xad,
  MercuryReq = 0xb2,
  MercurySub = 0xb3,
  MercuryUnsub = 0xb4,
  MercuryEvent = 0xb5,
  TrackEndedTime = 0x82,
  PreferredLocale = 0x74,
  Error = 0xff,
}

function packetTypeToStr(type: PacketType) {
  return PacketType[type] || "0x" + ("0" + type.toString(16)).slice(-2);
}

function logSend(message: string) {
  console.log(`${color_code(Color.GREEN)}${message}${RST_COL_CODE}`);
}

function logRecv(message: string) {
  console.log(`${color_code(Color.CYAN)}${message}${RST_COL_CODE}`);
}

/*
typedef struct HermesHeader 
{
  std::uint8_t type;
  std::uint16_t header; // big-endian
} HermesHeader;
*/
type HermesHeader = {
  type: PacketType;
  length: number;
};

function parseHeader(data: ArrayBuffer): HermesHeader | null {
  if (data.byteLength < 3) {
    return null;
  }
  const dv = new DataView(data);
  const packet: HermesHeader = { type: PacketType.Error, length: 0 };
  packet.type = dv.getUint8(0) as PacketType;
  packet.length = dv.getUint16(1, false);
  return packet;
}

function send(data: ArrayBuffer) {
  const header = parseHeader(data);
  if (!header) {
    warn(
      `SPIRC: (send) Failed to decode header from packet\n${hexdump(data, {
        header: false,
      })}`
    );
    return;
  }

  if (data.byteLength != 3 + header.length) {
    warn(
      `SPIRC: (send) Expected packet length ${data.byteLength - 3}, got ${
        header.length
      }\n${hexdump(data, { header: false })}`
    );
    return;
  }

  const typeStr = packetTypeToStr(header.type);
  switch (header.type) {
    case PacketType.Login: {
      const login = Authentication.ClientResponseEncrypted.decode(
        new Uint8Array(data.slice(3))
      );
      const loginJson = JSON.stringify(
        Authentication.ClientResponseEncrypted.toJSON(login),
        null,
        2
      );
      logSend(`[SEND] type=${typeStr}\n${loginJson}`);
      break;
    }
    case PacketType.Pong: {
      logSend(`[SEND] type=${typeStr}\nPong`);
      break;
    }
    case PacketType.MercuryEvent:
    case PacketType.MercuryReq:
    case PacketType.MercurySub:
    case PacketType.MercuryUnsub: {
      Mercury.send(header.type, data.slice(3));
      break;
    }
    default: {
      warn(
        `SPIRC: (send) No handler for packet ${typeStr}\n${hexdump(data, {
          header: false,
        })}`
      );
      break;
    }
  }
}

class RecvIntermediate {
  static header: HermesHeader = { type: PacketType.Error, length: -1 };
}
function recv(data: ArrayBuffer) {
  if (RecvIntermediate.header.length === -1) {
    if (data.byteLength !== 3) {
      warn(
        `SPIRC: (recv) Expected header of length 3:\n${hexdump(data, {
          header: false,
        })}`
      );
      return;
    }
    const hdr = parseHeader(data);
    if (hdr === null) {
      warn(
        `SPIRC: (recv) Failed to parse header:\n${hexdump(data, {
          header: false,
        })}`
      );
      return;
    }
    RecvIntermediate.header = hdr;
    return;
  }

  if (data.byteLength != RecvIntermediate.header.length) {
    warn(
      `SPIRC: (recv) Expected packet of length ${
        RecvIntermediate.header.length
      }, got ${data.byteLength}:\n${hexdump(data, { header: false })}`
    );
    RecvIntermediate.header.type = PacketType.Error;
    RecvIntermediate.header.length = -1;
    return;
  }

  const header: HermesHeader = { type: PacketType.Error, length: -1 };
  Object.assign(header, RecvIntermediate.header);
  RecvIntermediate.header.type = PacketType.Error;
  RecvIntermediate.header.length = -1;

  const typeStr = packetTypeToStr(header.type);
  switch (header.type) {
    case PacketType.APWelcome: {
      const apWelcome = Authentication.APWelcome.decode(new Uint8Array(data));
      const apWelcomeJson = JSON.stringify(
        Authentication.APWelcome.toJSON(apWelcome),
        null,
        2
      );
      logRecv(`[RECV] type=${typeStr}\n${apWelcomeJson}`);
      break;
    }
    case PacketType.Ping: {
      const dv = new DataView(data);
      const server_ts = dv.getUint32(0) * 1000;
      const our_ts = Date.now();
      logRecv(
        `[RECV] type=${typeStr}\nServer TS: ${server_ts}\nOur TS: ${our_ts}`
      );
      break;
    }
    case PacketType.PongAck: {
      logRecv(`[RECV] type=${typeStr}\nPing Acknowledged`);
      break;
    }
    // case PacketType.SecretBlock: {
    //   logRecv(`[RECV] type=${typeStr}\n${arrayToHex(data)}`);
    //   break;
    // }
    case PacketType.LicenseVersion: {
      if (data.byteLength !== 2) {
        warn(
          `SPIRC: (recv) Expected license version to be 2, got ${
            data.byteLength
          }\n${hexdump(data, { header: false })}`
        );
        return;
      }
      const dv = new DataView(data);
      const type = dv.getUint16(0, false);
      switch (type) {
        case 0: {
          logRecv(`[RECV] type=${typeStr}\nPremium`);
          break;
        }
        default: {
          logRecv(`[RECV] type=${typeStr}\nUnknown license type: ${type}`);
          break;
        }
      }
      break;
    }
    case PacketType.LegacyWelcome: {
      logRecv(`[RECV] type=${typeStr} Welcome :)`);
      break;
    }
    case PacketType.CountryCode: {
      const dv = new DataView(data);
      let str = "";
      for (let i = 0; i < dv.byteLength; i++) {
        str += String.fromCharCode(dv.getUint8(i));
      }
      logRecv(`[RECV] type=${typeStr}\nCountry Code: ${str}`);
      break;
    }
    case PacketType.ProductInfo: {
      let xml = "";
      const dv = new DataView(data);
      for (let i = 0; i < dv.byteLength; i++) {
        xml += String.fromCharCode(dv.getUint8(i));
      }
      logRecv(`[RECV] type=${typeStr}\n${xml}`);
      break;
    }
    case PacketType.MercuryEvent:
    case PacketType.MercuryReq:
    case PacketType.MercurySub:
    case PacketType.MercuryUnsub: {
      Mercury.recv(header.type, data);
      break;
    }
    default: {
      warn(
        `SPIRC: (recv) No handler for packet ${typeStr}\n${hexdump(data, {
          header: false,
        })}`
      );
      break;
    }
  }
}

const SPIRCParser = {
  send,
  recv,
};

export default SPIRCParser;
