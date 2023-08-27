/* eslint-disable */
import _m0 from "protobufjs/minimal";

export const protobufPackage = "spotify.authentication";

export enum AuthenticationType {
  AUTHENTICATION_USER_PASS = 0,
  AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS = 1,
  AUTHENTICATION_STORED_FACEBOOK_CREDENTIALS = 2,
  AUTHENTICATION_SPOTIFY_TOKEN = 3,
  AUTHENTICATION_FACEBOOK_TOKEN = 4,
  UNRECOGNIZED = -1,
}

export function authenticationTypeFromJSON(object: any): AuthenticationType {
  switch (object) {
    case 0:
    case "AUTHENTICATION_USER_PASS":
      return AuthenticationType.AUTHENTICATION_USER_PASS;
    case 1:
    case "AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS":
      return AuthenticationType.AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS;
    case 2:
    case "AUTHENTICATION_STORED_FACEBOOK_CREDENTIALS":
      return AuthenticationType.AUTHENTICATION_STORED_FACEBOOK_CREDENTIALS;
    case 3:
    case "AUTHENTICATION_SPOTIFY_TOKEN":
      return AuthenticationType.AUTHENTICATION_SPOTIFY_TOKEN;
    case 4:
    case "AUTHENTICATION_FACEBOOK_TOKEN":
      return AuthenticationType.AUTHENTICATION_FACEBOOK_TOKEN;
    case -1:
    case "UNRECOGNIZED":
    default:
      return AuthenticationType.UNRECOGNIZED;
  }
}

export function authenticationTypeToJSON(object: AuthenticationType): string {
  switch (object) {
    case AuthenticationType.AUTHENTICATION_USER_PASS:
      return "AUTHENTICATION_USER_PASS";
    case AuthenticationType.AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS:
      return "AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS";
    case AuthenticationType.AUTHENTICATION_STORED_FACEBOOK_CREDENTIALS:
      return "AUTHENTICATION_STORED_FACEBOOK_CREDENTIALS";
    case AuthenticationType.AUTHENTICATION_SPOTIFY_TOKEN:
      return "AUTHENTICATION_SPOTIFY_TOKEN";
    case AuthenticationType.AUTHENTICATION_FACEBOOK_TOKEN:
      return "AUTHENTICATION_FACEBOOK_TOKEN";
    case AuthenticationType.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum AccountCreation {
  ACCOUNT_CREATION_ALWAYS_PROMPT = 1,
  ACCOUNT_CREATION_ALWAYS_CREATE = 3,
  UNRECOGNIZED = -1,
}

export function accountCreationFromJSON(object: any): AccountCreation {
  switch (object) {
    case 1:
    case "ACCOUNT_CREATION_ALWAYS_PROMPT":
      return AccountCreation.ACCOUNT_CREATION_ALWAYS_PROMPT;
    case 3:
    case "ACCOUNT_CREATION_ALWAYS_CREATE":
      return AccountCreation.ACCOUNT_CREATION_ALWAYS_CREATE;
    case -1:
    case "UNRECOGNIZED":
    default:
      return AccountCreation.UNRECOGNIZED;
  }
}

export function accountCreationToJSON(object: AccountCreation): string {
  switch (object) {
    case AccountCreation.ACCOUNT_CREATION_ALWAYS_PROMPT:
      return "ACCOUNT_CREATION_ALWAYS_PROMPT";
    case AccountCreation.ACCOUNT_CREATION_ALWAYS_CREATE:
      return "ACCOUNT_CREATION_ALWAYS_CREATE";
    case AccountCreation.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum CpuFamily {
  CPU_UNKNOWN = 0,
  CPU_X86 = 1,
  CPU_X86_64 = 2,
  CPU_PPC = 3,
  CPU_PPC_64 = 4,
  CPU_ARM = 5,
  CPU_IA64 = 6,
  CPU_SH = 7,
  CPU_MIPS = 8,
  CPU_BLACKFIN = 9,
  UNRECOGNIZED = -1,
}

export function cpuFamilyFromJSON(object: any): CpuFamily {
  switch (object) {
    case 0:
    case "CPU_UNKNOWN":
      return CpuFamily.CPU_UNKNOWN;
    case 1:
    case "CPU_X86":
      return CpuFamily.CPU_X86;
    case 2:
    case "CPU_X86_64":
      return CpuFamily.CPU_X86_64;
    case 3:
    case "CPU_PPC":
      return CpuFamily.CPU_PPC;
    case 4:
    case "CPU_PPC_64":
      return CpuFamily.CPU_PPC_64;
    case 5:
    case "CPU_ARM":
      return CpuFamily.CPU_ARM;
    case 6:
    case "CPU_IA64":
      return CpuFamily.CPU_IA64;
    case 7:
    case "CPU_SH":
      return CpuFamily.CPU_SH;
    case 8:
    case "CPU_MIPS":
      return CpuFamily.CPU_MIPS;
    case 9:
    case "CPU_BLACKFIN":
      return CpuFamily.CPU_BLACKFIN;
    case -1:
    case "UNRECOGNIZED":
    default:
      return CpuFamily.UNRECOGNIZED;
  }
}

export function cpuFamilyToJSON(object: CpuFamily): string {
  switch (object) {
    case CpuFamily.CPU_UNKNOWN:
      return "CPU_UNKNOWN";
    case CpuFamily.CPU_X86:
      return "CPU_X86";
    case CpuFamily.CPU_X86_64:
      return "CPU_X86_64";
    case CpuFamily.CPU_PPC:
      return "CPU_PPC";
    case CpuFamily.CPU_PPC_64:
      return "CPU_PPC_64";
    case CpuFamily.CPU_ARM:
      return "CPU_ARM";
    case CpuFamily.CPU_IA64:
      return "CPU_IA64";
    case CpuFamily.CPU_SH:
      return "CPU_SH";
    case CpuFamily.CPU_MIPS:
      return "CPU_MIPS";
    case CpuFamily.CPU_BLACKFIN:
      return "CPU_BLACKFIN";
    case CpuFamily.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Brand {
  BRAND_UNBRANDED = 0,
  BRAND_INQ = 1,
  BRAND_HTC = 2,
  BRAND_NOKIA = 3,
  UNRECOGNIZED = -1,
}

export function brandFromJSON(object: any): Brand {
  switch (object) {
    case 0:
    case "BRAND_UNBRANDED":
      return Brand.BRAND_UNBRANDED;
    case 1:
    case "BRAND_INQ":
      return Brand.BRAND_INQ;
    case 2:
    case "BRAND_HTC":
      return Brand.BRAND_HTC;
    case 3:
    case "BRAND_NOKIA":
      return Brand.BRAND_NOKIA;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Brand.UNRECOGNIZED;
  }
}

export function brandToJSON(object: Brand): string {
  switch (object) {
    case Brand.BRAND_UNBRANDED:
      return "BRAND_UNBRANDED";
    case Brand.BRAND_INQ:
      return "BRAND_INQ";
    case Brand.BRAND_HTC:
      return "BRAND_HTC";
    case Brand.BRAND_NOKIA:
      return "BRAND_NOKIA";
    case Brand.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Os {
  OS_UNKNOWN = 0,
  OS_WINDOWS = 1,
  OS_OSX = 2,
  OS_IPHONE = 3,
  OS_S60 = 4,
  OS_LINUX = 5,
  OS_WINDOWS_CE = 6,
  OS_ANDROID = 7,
  OS_PALM = 8,
  OS_FREEBSD = 9,
  OS_BLACKBERRY = 10,
  OS_SONOS = 11,
  OS_LOGITECH = 12,
  OS_WP7 = 13,
  OS_ONKYO = 14,
  OS_PHILIPS = 15,
  OS_WD = 16,
  OS_VOLVO = 17,
  OS_TIVO = 18,
  OS_AWOX = 19,
  OS_MEEGO = 20,
  OS_QNXNTO = 21,
  OS_BCO = 22,
  UNRECOGNIZED = -1,
}

export function osFromJSON(object: any): Os {
  switch (object) {
    case 0:
    case "OS_UNKNOWN":
      return Os.OS_UNKNOWN;
    case 1:
    case "OS_WINDOWS":
      return Os.OS_WINDOWS;
    case 2:
    case "OS_OSX":
      return Os.OS_OSX;
    case 3:
    case "OS_IPHONE":
      return Os.OS_IPHONE;
    case 4:
    case "OS_S60":
      return Os.OS_S60;
    case 5:
    case "OS_LINUX":
      return Os.OS_LINUX;
    case 6:
    case "OS_WINDOWS_CE":
      return Os.OS_WINDOWS_CE;
    case 7:
    case "OS_ANDROID":
      return Os.OS_ANDROID;
    case 8:
    case "OS_PALM":
      return Os.OS_PALM;
    case 9:
    case "OS_FREEBSD":
      return Os.OS_FREEBSD;
    case 10:
    case "OS_BLACKBERRY":
      return Os.OS_BLACKBERRY;
    case 11:
    case "OS_SONOS":
      return Os.OS_SONOS;
    case 12:
    case "OS_LOGITECH":
      return Os.OS_LOGITECH;
    case 13:
    case "OS_WP7":
      return Os.OS_WP7;
    case 14:
    case "OS_ONKYO":
      return Os.OS_ONKYO;
    case 15:
    case "OS_PHILIPS":
      return Os.OS_PHILIPS;
    case 16:
    case "OS_WD":
      return Os.OS_WD;
    case 17:
    case "OS_VOLVO":
      return Os.OS_VOLVO;
    case 18:
    case "OS_TIVO":
      return Os.OS_TIVO;
    case 19:
    case "OS_AWOX":
      return Os.OS_AWOX;
    case 20:
    case "OS_MEEGO":
      return Os.OS_MEEGO;
    case 21:
    case "OS_QNXNTO":
      return Os.OS_QNXNTO;
    case 22:
    case "OS_BCO":
      return Os.OS_BCO;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Os.UNRECOGNIZED;
  }
}

export function osToJSON(object: Os): string {
  switch (object) {
    case Os.OS_UNKNOWN:
      return "OS_UNKNOWN";
    case Os.OS_WINDOWS:
      return "OS_WINDOWS";
    case Os.OS_OSX:
      return "OS_OSX";
    case Os.OS_IPHONE:
      return "OS_IPHONE";
    case Os.OS_S60:
      return "OS_S60";
    case Os.OS_LINUX:
      return "OS_LINUX";
    case Os.OS_WINDOWS_CE:
      return "OS_WINDOWS_CE";
    case Os.OS_ANDROID:
      return "OS_ANDROID";
    case Os.OS_PALM:
      return "OS_PALM";
    case Os.OS_FREEBSD:
      return "OS_FREEBSD";
    case Os.OS_BLACKBERRY:
      return "OS_BLACKBERRY";
    case Os.OS_SONOS:
      return "OS_SONOS";
    case Os.OS_LOGITECH:
      return "OS_LOGITECH";
    case Os.OS_WP7:
      return "OS_WP7";
    case Os.OS_ONKYO:
      return "OS_ONKYO";
    case Os.OS_PHILIPS:
      return "OS_PHILIPS";
    case Os.OS_WD:
      return "OS_WD";
    case Os.OS_VOLVO:
      return "OS_VOLVO";
    case Os.OS_TIVO:
      return "OS_TIVO";
    case Os.OS_AWOX:
      return "OS_AWOX";
    case Os.OS_MEEGO:
      return "OS_MEEGO";
    case Os.OS_QNXNTO:
      return "OS_QNXNTO";
    case Os.OS_BCO:
      return "OS_BCO";
    case Os.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum AccountType {
  Spotify = 0,
  Facebook = 1,
  UNRECOGNIZED = -1,
}

export function accountTypeFromJSON(object: any): AccountType {
  switch (object) {
    case 0:
    case "Spotify":
      return AccountType.Spotify;
    case 1:
    case "Facebook":
      return AccountType.Facebook;
    case -1:
    case "UNRECOGNIZED":
    default:
      return AccountType.UNRECOGNIZED;
  }
}

export function accountTypeToJSON(object: AccountType): string {
  switch (object) {
    case AccountType.Spotify:
      return "Spotify";
    case AccountType.Facebook:
      return "Facebook";
    case AccountType.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface ClientResponseEncrypted {
  loginCredentials: LoginCredentials | undefined;
  accountCreation: AccountCreation;
  fingerprintResponse: FingerprintResponseUnion | undefined;
  peerTicket: PeerTicketUnion | undefined;
  systemInfo: SystemInfo | undefined;
  platformModel: string;
  versionString: string;
  appkey: LibspotifyAppKey | undefined;
  clientInfo: ClientInfo | undefined;
}

export interface LoginCredentials {
  username: string;
  typ: AuthenticationType;
  authData: Uint8Array;
}

export interface FingerprintResponseUnion {
  grain: FingerprintGrainResponse | undefined;
  hmacRipemd: FingerprintHmacRipemdResponse | undefined;
}

export interface FingerprintGrainResponse {
  encryptedKey: Uint8Array;
}

export interface FingerprintHmacRipemdResponse {
  hmac: Uint8Array;
}

export interface PeerTicketUnion {
  publicKey: PeerTicketPublicKey | undefined;
  oldTicket: PeerTicketOld | undefined;
}

export interface PeerTicketPublicKey {
  publicKey: Uint8Array;
}

export interface PeerTicketOld {
  peerTicket: Uint8Array;
  peerTicketSignature: Uint8Array;
}

export interface SystemInfo {
  cpuFamily: CpuFamily;
  cpuSubtype: number;
  cpuExt: number;
  brand: Brand;
  brandFlags: number;
  os: Os;
  osVersion: number;
  osExt: number;
  systemInformationString: string;
  deviceId: string;
}

export interface LibspotifyAppKey {
  version: number;
  devkey: Uint8Array;
  signature: Uint8Array;
  useragent: string;
  callbackHash: Uint8Array;
}

export interface ClientInfo {
  limited: boolean;
  fb: ClientInfoFacebook | undefined;
  language: string;
}

export interface ClientInfoFacebook {
  machineId: string;
}

export interface APWelcome {
  canonicalUsername: string;
  accountTypeLoggedIn: AccountType;
  credentialsTypeLoggedIn: AccountType;
  reusableAuthCredentialsType: AuthenticationType;
  reusableAuthCredentials: Uint8Array;
  lfsSecret: Uint8Array;
  accountInfo: AccountInfo | undefined;
  fb: AccountInfoFacebook | undefined;
}

export interface AccountInfo {
  spotify: AccountInfoSpotify | undefined;
  facebook: AccountInfoFacebook | undefined;
}

export interface AccountInfoSpotify {
}

export interface AccountInfoFacebook {
  accessToken: string;
  machineId: string;
}

function createBaseClientResponseEncrypted(): ClientResponseEncrypted {
  return {
    loginCredentials: undefined,
    accountCreation: 1,
    fingerprintResponse: undefined,
    peerTicket: undefined,
    systemInfo: undefined,
    platformModel: "",
    versionString: "",
    appkey: undefined,
    clientInfo: undefined,
  };
}

export const ClientResponseEncrypted = {
  encode(message: ClientResponseEncrypted, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.loginCredentials !== undefined) {
      LoginCredentials.encode(message.loginCredentials, writer.uint32(82).fork()).ldelim();
    }
    if (message.accountCreation !== 1) {
      writer.uint32(160).int32(message.accountCreation);
    }
    if (message.fingerprintResponse !== undefined) {
      FingerprintResponseUnion.encode(message.fingerprintResponse, writer.uint32(242).fork()).ldelim();
    }
    if (message.peerTicket !== undefined) {
      PeerTicketUnion.encode(message.peerTicket, writer.uint32(322).fork()).ldelim();
    }
    if (message.systemInfo !== undefined) {
      SystemInfo.encode(message.systemInfo, writer.uint32(402).fork()).ldelim();
    }
    if (message.platformModel !== "") {
      writer.uint32(482).string(message.platformModel);
    }
    if (message.versionString !== "") {
      writer.uint32(562).string(message.versionString);
    }
    if (message.appkey !== undefined) {
      LibspotifyAppKey.encode(message.appkey, writer.uint32(642).fork()).ldelim();
    }
    if (message.clientInfo !== undefined) {
      ClientInfo.encode(message.clientInfo, writer.uint32(722).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ClientResponseEncrypted {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseClientResponseEncrypted();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.loginCredentials = LoginCredentials.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.accountCreation = reader.int32() as any;
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.fingerprintResponse = FingerprintResponseUnion.decode(reader, reader.uint32());
          continue;
        case 40:
          if (tag !== 322) {
            break;
          }

          message.peerTicket = PeerTicketUnion.decode(reader, reader.uint32());
          continue;
        case 50:
          if (tag !== 402) {
            break;
          }

          message.systemInfo = SystemInfo.decode(reader, reader.uint32());
          continue;
        case 60:
          if (tag !== 482) {
            break;
          }

          message.platformModel = reader.string();
          continue;
        case 70:
          if (tag !== 562) {
            break;
          }

          message.versionString = reader.string();
          continue;
        case 80:
          if (tag !== 642) {
            break;
          }

          message.appkey = LibspotifyAppKey.decode(reader, reader.uint32());
          continue;
        case 90:
          if (tag !== 722) {
            break;
          }

          message.clientInfo = ClientInfo.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ClientResponseEncrypted {
    return {
      loginCredentials: isSet(object.loginCredentials) ? LoginCredentials.fromJSON(object.loginCredentials) : undefined,
      accountCreation: isSet(object.accountCreation) ? accountCreationFromJSON(object.accountCreation) : 1,
      fingerprintResponse: isSet(object.fingerprintResponse)
        ? FingerprintResponseUnion.fromJSON(object.fingerprintResponse)
        : undefined,
      peerTicket: isSet(object.peerTicket) ? PeerTicketUnion.fromJSON(object.peerTicket) : undefined,
      systemInfo: isSet(object.systemInfo) ? SystemInfo.fromJSON(object.systemInfo) : undefined,
      platformModel: isSet(object.platformModel) ? String(object.platformModel) : "",
      versionString: isSet(object.versionString) ? String(object.versionString) : "",
      appkey: isSet(object.appkey) ? LibspotifyAppKey.fromJSON(object.appkey) : undefined,
      clientInfo: isSet(object.clientInfo) ? ClientInfo.fromJSON(object.clientInfo) : undefined,
    };
  },

  toJSON(message: ClientResponseEncrypted): unknown {
    const obj: any = {};
    if (message.loginCredentials !== undefined) {
      obj.loginCredentials = LoginCredentials.toJSON(message.loginCredentials);
    }
    if (message.accountCreation !== 1) {
      obj.accountCreation = accountCreationToJSON(message.accountCreation);
    }
    if (message.fingerprintResponse !== undefined) {
      obj.fingerprintResponse = FingerprintResponseUnion.toJSON(message.fingerprintResponse);
    }
    if (message.peerTicket !== undefined) {
      obj.peerTicket = PeerTicketUnion.toJSON(message.peerTicket);
    }
    if (message.systemInfo !== undefined) {
      obj.systemInfo = SystemInfo.toJSON(message.systemInfo);
    }
    if (message.platformModel !== "") {
      obj.platformModel = message.platformModel;
    }
    if (message.versionString !== "") {
      obj.versionString = message.versionString;
    }
    if (message.appkey !== undefined) {
      obj.appkey = LibspotifyAppKey.toJSON(message.appkey);
    }
    if (message.clientInfo !== undefined) {
      obj.clientInfo = ClientInfo.toJSON(message.clientInfo);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ClientResponseEncrypted>, I>>(base?: I): ClientResponseEncrypted {
    return ClientResponseEncrypted.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ClientResponseEncrypted>, I>>(object: I): ClientResponseEncrypted {
    const message = createBaseClientResponseEncrypted();
    message.loginCredentials = (object.loginCredentials !== undefined && object.loginCredentials !== null)
      ? LoginCredentials.fromPartial(object.loginCredentials)
      : undefined;
    message.accountCreation = object.accountCreation ?? 1;
    message.fingerprintResponse = (object.fingerprintResponse !== undefined && object.fingerprintResponse !== null)
      ? FingerprintResponseUnion.fromPartial(object.fingerprintResponse)
      : undefined;
    message.peerTicket = (object.peerTicket !== undefined && object.peerTicket !== null)
      ? PeerTicketUnion.fromPartial(object.peerTicket)
      : undefined;
    message.systemInfo = (object.systemInfo !== undefined && object.systemInfo !== null)
      ? SystemInfo.fromPartial(object.systemInfo)
      : undefined;
    message.platformModel = object.platformModel ?? "";
    message.versionString = object.versionString ?? "";
    message.appkey = (object.appkey !== undefined && object.appkey !== null)
      ? LibspotifyAppKey.fromPartial(object.appkey)
      : undefined;
    message.clientInfo = (object.clientInfo !== undefined && object.clientInfo !== null)
      ? ClientInfo.fromPartial(object.clientInfo)
      : undefined;
    return message;
  },
};

function createBaseLoginCredentials(): LoginCredentials {
  return { username: "", typ: 0, authData: new Uint8Array(0) };
}

export const LoginCredentials = {
  encode(message: LoginCredentials, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.username !== "") {
      writer.uint32(82).string(message.username);
    }
    if (message.typ !== 0) {
      writer.uint32(160).int32(message.typ);
    }
    if (message.authData.length !== 0) {
      writer.uint32(242).bytes(message.authData);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCredentials {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCredentials();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.username = reader.string();
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.typ = reader.int32() as any;
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.authData = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCredentials {
    return {
      username: isSet(object.username) ? String(object.username) : "",
      typ: isSet(object.typ) ? authenticationTypeFromJSON(object.typ) : 0,
      authData: isSet(object.authData) ? bytesFromBase64(object.authData) : new Uint8Array(0),
    };
  },

  toJSON(message: LoginCredentials): unknown {
    const obj: any = {};
    if (message.username !== "") {
      obj.username = message.username;
    }
    if (message.typ !== 0) {
      obj.typ = authenticationTypeToJSON(message.typ);
    }
    if (message.authData.length !== 0) {
      obj.authData = base64FromBytes(message.authData);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCredentials>, I>>(base?: I): LoginCredentials {
    return LoginCredentials.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCredentials>, I>>(object: I): LoginCredentials {
    const message = createBaseLoginCredentials();
    message.username = object.username ?? "";
    message.typ = object.typ ?? 0;
    message.authData = object.authData ?? new Uint8Array(0);
    return message;
  },
};

function createBaseFingerprintResponseUnion(): FingerprintResponseUnion {
  return { grain: undefined, hmacRipemd: undefined };
}

export const FingerprintResponseUnion = {
  encode(message: FingerprintResponseUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.grain !== undefined) {
      FingerprintGrainResponse.encode(message.grain, writer.uint32(82).fork()).ldelim();
    }
    if (message.hmacRipemd !== undefined) {
      FingerprintHmacRipemdResponse.encode(message.hmacRipemd, writer.uint32(162).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintResponseUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintResponseUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.grain = FingerprintGrainResponse.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.hmacRipemd = FingerprintHmacRipemdResponse.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintResponseUnion {
    return {
      grain: isSet(object.grain) ? FingerprintGrainResponse.fromJSON(object.grain) : undefined,
      hmacRipemd: isSet(object.hmacRipemd) ? FingerprintHmacRipemdResponse.fromJSON(object.hmacRipemd) : undefined,
    };
  },

  toJSON(message: FingerprintResponseUnion): unknown {
    const obj: any = {};
    if (message.grain !== undefined) {
      obj.grain = FingerprintGrainResponse.toJSON(message.grain);
    }
    if (message.hmacRipemd !== undefined) {
      obj.hmacRipemd = FingerprintHmacRipemdResponse.toJSON(message.hmacRipemd);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintResponseUnion>, I>>(base?: I): FingerprintResponseUnion {
    return FingerprintResponseUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintResponseUnion>, I>>(object: I): FingerprintResponseUnion {
    const message = createBaseFingerprintResponseUnion();
    message.grain = (object.grain !== undefined && object.grain !== null)
      ? FingerprintGrainResponse.fromPartial(object.grain)
      : undefined;
    message.hmacRipemd = (object.hmacRipemd !== undefined && object.hmacRipemd !== null)
      ? FingerprintHmacRipemdResponse.fromPartial(object.hmacRipemd)
      : undefined;
    return message;
  },
};

function createBaseFingerprintGrainResponse(): FingerprintGrainResponse {
  return { encryptedKey: new Uint8Array(0) };
}

export const FingerprintGrainResponse = {
  encode(message: FingerprintGrainResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.encryptedKey.length !== 0) {
      writer.uint32(82).bytes(message.encryptedKey);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintGrainResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintGrainResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.encryptedKey = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintGrainResponse {
    return { encryptedKey: isSet(object.encryptedKey) ? bytesFromBase64(object.encryptedKey) : new Uint8Array(0) };
  },

  toJSON(message: FingerprintGrainResponse): unknown {
    const obj: any = {};
    if (message.encryptedKey.length !== 0) {
      obj.encryptedKey = base64FromBytes(message.encryptedKey);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintGrainResponse>, I>>(base?: I): FingerprintGrainResponse {
    return FingerprintGrainResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintGrainResponse>, I>>(object: I): FingerprintGrainResponse {
    const message = createBaseFingerprintGrainResponse();
    message.encryptedKey = object.encryptedKey ?? new Uint8Array(0);
    return message;
  },
};

function createBaseFingerprintHmacRipemdResponse(): FingerprintHmacRipemdResponse {
  return { hmac: new Uint8Array(0) };
}

export const FingerprintHmacRipemdResponse = {
  encode(message: FingerprintHmacRipemdResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.hmac.length !== 0) {
      writer.uint32(82).bytes(message.hmac);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintHmacRipemdResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintHmacRipemdResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.hmac = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintHmacRipemdResponse {
    return { hmac: isSet(object.hmac) ? bytesFromBase64(object.hmac) : new Uint8Array(0) };
  },

  toJSON(message: FingerprintHmacRipemdResponse): unknown {
    const obj: any = {};
    if (message.hmac.length !== 0) {
      obj.hmac = base64FromBytes(message.hmac);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintHmacRipemdResponse>, I>>(base?: I): FingerprintHmacRipemdResponse {
    return FingerprintHmacRipemdResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintHmacRipemdResponse>, I>>(
    object: I,
  ): FingerprintHmacRipemdResponse {
    const message = createBaseFingerprintHmacRipemdResponse();
    message.hmac = object.hmac ?? new Uint8Array(0);
    return message;
  },
};

function createBasePeerTicketUnion(): PeerTicketUnion {
  return { publicKey: undefined, oldTicket: undefined };
}

export const PeerTicketUnion = {
  encode(message: PeerTicketUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.publicKey !== undefined) {
      PeerTicketPublicKey.encode(message.publicKey, writer.uint32(82).fork()).ldelim();
    }
    if (message.oldTicket !== undefined) {
      PeerTicketOld.encode(message.oldTicket, writer.uint32(162).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PeerTicketUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePeerTicketUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.publicKey = PeerTicketPublicKey.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.oldTicket = PeerTicketOld.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PeerTicketUnion {
    return {
      publicKey: isSet(object.publicKey) ? PeerTicketPublicKey.fromJSON(object.publicKey) : undefined,
      oldTicket: isSet(object.oldTicket) ? PeerTicketOld.fromJSON(object.oldTicket) : undefined,
    };
  },

  toJSON(message: PeerTicketUnion): unknown {
    const obj: any = {};
    if (message.publicKey !== undefined) {
      obj.publicKey = PeerTicketPublicKey.toJSON(message.publicKey);
    }
    if (message.oldTicket !== undefined) {
      obj.oldTicket = PeerTicketOld.toJSON(message.oldTicket);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PeerTicketUnion>, I>>(base?: I): PeerTicketUnion {
    return PeerTicketUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PeerTicketUnion>, I>>(object: I): PeerTicketUnion {
    const message = createBasePeerTicketUnion();
    message.publicKey = (object.publicKey !== undefined && object.publicKey !== null)
      ? PeerTicketPublicKey.fromPartial(object.publicKey)
      : undefined;
    message.oldTicket = (object.oldTicket !== undefined && object.oldTicket !== null)
      ? PeerTicketOld.fromPartial(object.oldTicket)
      : undefined;
    return message;
  },
};

function createBasePeerTicketPublicKey(): PeerTicketPublicKey {
  return { publicKey: new Uint8Array(0) };
}

export const PeerTicketPublicKey = {
  encode(message: PeerTicketPublicKey, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.publicKey.length !== 0) {
      writer.uint32(82).bytes(message.publicKey);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PeerTicketPublicKey {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePeerTicketPublicKey();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.publicKey = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PeerTicketPublicKey {
    return { publicKey: isSet(object.publicKey) ? bytesFromBase64(object.publicKey) : new Uint8Array(0) };
  },

  toJSON(message: PeerTicketPublicKey): unknown {
    const obj: any = {};
    if (message.publicKey.length !== 0) {
      obj.publicKey = base64FromBytes(message.publicKey);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PeerTicketPublicKey>, I>>(base?: I): PeerTicketPublicKey {
    return PeerTicketPublicKey.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PeerTicketPublicKey>, I>>(object: I): PeerTicketPublicKey {
    const message = createBasePeerTicketPublicKey();
    message.publicKey = object.publicKey ?? new Uint8Array(0);
    return message;
  },
};

function createBasePeerTicketOld(): PeerTicketOld {
  return { peerTicket: new Uint8Array(0), peerTicketSignature: new Uint8Array(0) };
}

export const PeerTicketOld = {
  encode(message: PeerTicketOld, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.peerTicket.length !== 0) {
      writer.uint32(82).bytes(message.peerTicket);
    }
    if (message.peerTicketSignature.length !== 0) {
      writer.uint32(162).bytes(message.peerTicketSignature);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PeerTicketOld {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePeerTicketOld();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.peerTicket = reader.bytes();
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.peerTicketSignature = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PeerTicketOld {
    return {
      peerTicket: isSet(object.peerTicket) ? bytesFromBase64(object.peerTicket) : new Uint8Array(0),
      peerTicketSignature: isSet(object.peerTicketSignature)
        ? bytesFromBase64(object.peerTicketSignature)
        : new Uint8Array(0),
    };
  },

  toJSON(message: PeerTicketOld): unknown {
    const obj: any = {};
    if (message.peerTicket.length !== 0) {
      obj.peerTicket = base64FromBytes(message.peerTicket);
    }
    if (message.peerTicketSignature.length !== 0) {
      obj.peerTicketSignature = base64FromBytes(message.peerTicketSignature);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PeerTicketOld>, I>>(base?: I): PeerTicketOld {
    return PeerTicketOld.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PeerTicketOld>, I>>(object: I): PeerTicketOld {
    const message = createBasePeerTicketOld();
    message.peerTicket = object.peerTicket ?? new Uint8Array(0);
    message.peerTicketSignature = object.peerTicketSignature ?? new Uint8Array(0);
    return message;
  },
};

function createBaseSystemInfo(): SystemInfo {
  return {
    cpuFamily: 0,
    cpuSubtype: 0,
    cpuExt: 0,
    brand: 0,
    brandFlags: 0,
    os: 0,
    osVersion: 0,
    osExt: 0,
    systemInformationString: "",
    deviceId: "",
  };
}

export const SystemInfo = {
  encode(message: SystemInfo, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.cpuFamily !== 0) {
      writer.uint32(80).int32(message.cpuFamily);
    }
    if (message.cpuSubtype !== 0) {
      writer.uint32(160).uint32(message.cpuSubtype);
    }
    if (message.cpuExt !== 0) {
      writer.uint32(240).uint32(message.cpuExt);
    }
    if (message.brand !== 0) {
      writer.uint32(320).int32(message.brand);
    }
    if (message.brandFlags !== 0) {
      writer.uint32(400).uint32(message.brandFlags);
    }
    if (message.os !== 0) {
      writer.uint32(480).int32(message.os);
    }
    if (message.osVersion !== 0) {
      writer.uint32(560).uint32(message.osVersion);
    }
    if (message.osExt !== 0) {
      writer.uint32(640).uint32(message.osExt);
    }
    if (message.systemInformationString !== "") {
      writer.uint32(722).string(message.systemInformationString);
    }
    if (message.deviceId !== "") {
      writer.uint32(802).string(message.deviceId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): SystemInfo {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseSystemInfo();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 80) {
            break;
          }

          message.cpuFamily = reader.int32() as any;
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.cpuSubtype = reader.uint32();
          continue;
        case 30:
          if (tag !== 240) {
            break;
          }

          message.cpuExt = reader.uint32();
          continue;
        case 40:
          if (tag !== 320) {
            break;
          }

          message.brand = reader.int32() as any;
          continue;
        case 50:
          if (tag !== 400) {
            break;
          }

          message.brandFlags = reader.uint32();
          continue;
        case 60:
          if (tag !== 480) {
            break;
          }

          message.os = reader.int32() as any;
          continue;
        case 70:
          if (tag !== 560) {
            break;
          }

          message.osVersion = reader.uint32();
          continue;
        case 80:
          if (tag !== 640) {
            break;
          }

          message.osExt = reader.uint32();
          continue;
        case 90:
          if (tag !== 722) {
            break;
          }

          message.systemInformationString = reader.string();
          continue;
        case 100:
          if (tag !== 802) {
            break;
          }

          message.deviceId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): SystemInfo {
    return {
      cpuFamily: isSet(object.cpuFamily) ? cpuFamilyFromJSON(object.cpuFamily) : 0,
      cpuSubtype: isSet(object.cpuSubtype) ? Number(object.cpuSubtype) : 0,
      cpuExt: isSet(object.cpuExt) ? Number(object.cpuExt) : 0,
      brand: isSet(object.brand) ? brandFromJSON(object.brand) : 0,
      brandFlags: isSet(object.brandFlags) ? Number(object.brandFlags) : 0,
      os: isSet(object.os) ? osFromJSON(object.os) : 0,
      osVersion: isSet(object.osVersion) ? Number(object.osVersion) : 0,
      osExt: isSet(object.osExt) ? Number(object.osExt) : 0,
      systemInformationString: isSet(object.systemInformationString) ? String(object.systemInformationString) : "",
      deviceId: isSet(object.deviceId) ? String(object.deviceId) : "",
    };
  },

  toJSON(message: SystemInfo): unknown {
    const obj: any = {};
    if (message.cpuFamily !== 0) {
      obj.cpuFamily = cpuFamilyToJSON(message.cpuFamily);
    }
    if (message.cpuSubtype !== 0) {
      obj.cpuSubtype = Math.round(message.cpuSubtype);
    }
    if (message.cpuExt !== 0) {
      obj.cpuExt = Math.round(message.cpuExt);
    }
    if (message.brand !== 0) {
      obj.brand = brandToJSON(message.brand);
    }
    if (message.brandFlags !== 0) {
      obj.brandFlags = Math.round(message.brandFlags);
    }
    if (message.os !== 0) {
      obj.os = osToJSON(message.os);
    }
    if (message.osVersion !== 0) {
      obj.osVersion = Math.round(message.osVersion);
    }
    if (message.osExt !== 0) {
      obj.osExt = Math.round(message.osExt);
    }
    if (message.systemInformationString !== "") {
      obj.systemInformationString = message.systemInformationString;
    }
    if (message.deviceId !== "") {
      obj.deviceId = message.deviceId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<SystemInfo>, I>>(base?: I): SystemInfo {
    return SystemInfo.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<SystemInfo>, I>>(object: I): SystemInfo {
    const message = createBaseSystemInfo();
    message.cpuFamily = object.cpuFamily ?? 0;
    message.cpuSubtype = object.cpuSubtype ?? 0;
    message.cpuExt = object.cpuExt ?? 0;
    message.brand = object.brand ?? 0;
    message.brandFlags = object.brandFlags ?? 0;
    message.os = object.os ?? 0;
    message.osVersion = object.osVersion ?? 0;
    message.osExt = object.osExt ?? 0;
    message.systemInformationString = object.systemInformationString ?? "";
    message.deviceId = object.deviceId ?? "";
    return message;
  },
};

function createBaseLibspotifyAppKey(): LibspotifyAppKey {
  return {
    version: 0,
    devkey: new Uint8Array(0),
    signature: new Uint8Array(0),
    useragent: "",
    callbackHash: new Uint8Array(0),
  };
}

export const LibspotifyAppKey = {
  encode(message: LibspotifyAppKey, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.version !== 0) {
      writer.uint32(8).uint32(message.version);
    }
    if (message.devkey.length !== 0) {
      writer.uint32(18).bytes(message.devkey);
    }
    if (message.signature.length !== 0) {
      writer.uint32(26).bytes(message.signature);
    }
    if (message.useragent !== "") {
      writer.uint32(34).string(message.useragent);
    }
    if (message.callbackHash.length !== 0) {
      writer.uint32(42).bytes(message.callbackHash);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LibspotifyAppKey {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLibspotifyAppKey();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.version = reader.uint32();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.devkey = reader.bytes();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.signature = reader.bytes();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.useragent = reader.string();
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.callbackHash = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LibspotifyAppKey {
    return {
      version: isSet(object.version) ? Number(object.version) : 0,
      devkey: isSet(object.devkey) ? bytesFromBase64(object.devkey) : new Uint8Array(0),
      signature: isSet(object.signature) ? bytesFromBase64(object.signature) : new Uint8Array(0),
      useragent: isSet(object.useragent) ? String(object.useragent) : "",
      callbackHash: isSet(object.callbackHash) ? bytesFromBase64(object.callbackHash) : new Uint8Array(0),
    };
  },

  toJSON(message: LibspotifyAppKey): unknown {
    const obj: any = {};
    if (message.version !== 0) {
      obj.version = Math.round(message.version);
    }
    if (message.devkey.length !== 0) {
      obj.devkey = base64FromBytes(message.devkey);
    }
    if (message.signature.length !== 0) {
      obj.signature = base64FromBytes(message.signature);
    }
    if (message.useragent !== "") {
      obj.useragent = message.useragent;
    }
    if (message.callbackHash.length !== 0) {
      obj.callbackHash = base64FromBytes(message.callbackHash);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LibspotifyAppKey>, I>>(base?: I): LibspotifyAppKey {
    return LibspotifyAppKey.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LibspotifyAppKey>, I>>(object: I): LibspotifyAppKey {
    const message = createBaseLibspotifyAppKey();
    message.version = object.version ?? 0;
    message.devkey = object.devkey ?? new Uint8Array(0);
    message.signature = object.signature ?? new Uint8Array(0);
    message.useragent = object.useragent ?? "";
    message.callbackHash = object.callbackHash ?? new Uint8Array(0);
    return message;
  },
};

function createBaseClientInfo(): ClientInfo {
  return { limited: false, fb: undefined, language: "" };
}

export const ClientInfo = {
  encode(message: ClientInfo, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.limited === true) {
      writer.uint32(8).bool(message.limited);
    }
    if (message.fb !== undefined) {
      ClientInfoFacebook.encode(message.fb, writer.uint32(18).fork()).ldelim();
    }
    if (message.language !== "") {
      writer.uint32(26).string(message.language);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ClientInfo {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseClientInfo();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.limited = reader.bool();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.fb = ClientInfoFacebook.decode(reader, reader.uint32());
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.language = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ClientInfo {
    return {
      limited: isSet(object.limited) ? Boolean(object.limited) : false,
      fb: isSet(object.fb) ? ClientInfoFacebook.fromJSON(object.fb) : undefined,
      language: isSet(object.language) ? String(object.language) : "",
    };
  },

  toJSON(message: ClientInfo): unknown {
    const obj: any = {};
    if (message.limited === true) {
      obj.limited = message.limited;
    }
    if (message.fb !== undefined) {
      obj.fb = ClientInfoFacebook.toJSON(message.fb);
    }
    if (message.language !== "") {
      obj.language = message.language;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ClientInfo>, I>>(base?: I): ClientInfo {
    return ClientInfo.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ClientInfo>, I>>(object: I): ClientInfo {
    const message = createBaseClientInfo();
    message.limited = object.limited ?? false;
    message.fb = (object.fb !== undefined && object.fb !== null)
      ? ClientInfoFacebook.fromPartial(object.fb)
      : undefined;
    message.language = object.language ?? "";
    return message;
  },
};

function createBaseClientInfoFacebook(): ClientInfoFacebook {
  return { machineId: "" };
}

export const ClientInfoFacebook = {
  encode(message: ClientInfoFacebook, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.machineId !== "") {
      writer.uint32(10).string(message.machineId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ClientInfoFacebook {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseClientInfoFacebook();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.machineId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ClientInfoFacebook {
    return { machineId: isSet(object.machineId) ? String(object.machineId) : "" };
  },

  toJSON(message: ClientInfoFacebook): unknown {
    const obj: any = {};
    if (message.machineId !== "") {
      obj.machineId = message.machineId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ClientInfoFacebook>, I>>(base?: I): ClientInfoFacebook {
    return ClientInfoFacebook.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ClientInfoFacebook>, I>>(object: I): ClientInfoFacebook {
    const message = createBaseClientInfoFacebook();
    message.machineId = object.machineId ?? "";
    return message;
  },
};

function createBaseAPWelcome(): APWelcome {
  return {
    canonicalUsername: "",
    accountTypeLoggedIn: 0,
    credentialsTypeLoggedIn: 0,
    reusableAuthCredentialsType: 0,
    reusableAuthCredentials: new Uint8Array(0),
    lfsSecret: new Uint8Array(0),
    accountInfo: undefined,
    fb: undefined,
  };
}

export const APWelcome = {
  encode(message: APWelcome, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.canonicalUsername !== "") {
      writer.uint32(82).string(message.canonicalUsername);
    }
    if (message.accountTypeLoggedIn !== 0) {
      writer.uint32(160).int32(message.accountTypeLoggedIn);
    }
    if (message.credentialsTypeLoggedIn !== 0) {
      writer.uint32(200).int32(message.credentialsTypeLoggedIn);
    }
    if (message.reusableAuthCredentialsType !== 0) {
      writer.uint32(240).int32(message.reusableAuthCredentialsType);
    }
    if (message.reusableAuthCredentials.length !== 0) {
      writer.uint32(322).bytes(message.reusableAuthCredentials);
    }
    if (message.lfsSecret.length !== 0) {
      writer.uint32(402).bytes(message.lfsSecret);
    }
    if (message.accountInfo !== undefined) {
      AccountInfo.encode(message.accountInfo, writer.uint32(482).fork()).ldelim();
    }
    if (message.fb !== undefined) {
      AccountInfoFacebook.encode(message.fb, writer.uint32(562).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): APWelcome {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAPWelcome();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.canonicalUsername = reader.string();
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.accountTypeLoggedIn = reader.int32() as any;
          continue;
        case 25:
          if (tag !== 200) {
            break;
          }

          message.credentialsTypeLoggedIn = reader.int32() as any;
          continue;
        case 30:
          if (tag !== 240) {
            break;
          }

          message.reusableAuthCredentialsType = reader.int32() as any;
          continue;
        case 40:
          if (tag !== 322) {
            break;
          }

          message.reusableAuthCredentials = reader.bytes();
          continue;
        case 50:
          if (tag !== 402) {
            break;
          }

          message.lfsSecret = reader.bytes();
          continue;
        case 60:
          if (tag !== 482) {
            break;
          }

          message.accountInfo = AccountInfo.decode(reader, reader.uint32());
          continue;
        case 70:
          if (tag !== 562) {
            break;
          }

          message.fb = AccountInfoFacebook.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): APWelcome {
    return {
      canonicalUsername: isSet(object.canonicalUsername) ? String(object.canonicalUsername) : "",
      accountTypeLoggedIn: isSet(object.accountTypeLoggedIn) ? accountTypeFromJSON(object.accountTypeLoggedIn) : 0,
      credentialsTypeLoggedIn: isSet(object.credentialsTypeLoggedIn)
        ? accountTypeFromJSON(object.credentialsTypeLoggedIn)
        : 0,
      reusableAuthCredentialsType: isSet(object.reusableAuthCredentialsType)
        ? authenticationTypeFromJSON(object.reusableAuthCredentialsType)
        : 0,
      reusableAuthCredentials: isSet(object.reusableAuthCredentials)
        ? bytesFromBase64(object.reusableAuthCredentials)
        : new Uint8Array(0),
      lfsSecret: isSet(object.lfsSecret) ? bytesFromBase64(object.lfsSecret) : new Uint8Array(0),
      accountInfo: isSet(object.accountInfo) ? AccountInfo.fromJSON(object.accountInfo) : undefined,
      fb: isSet(object.fb) ? AccountInfoFacebook.fromJSON(object.fb) : undefined,
    };
  },

  toJSON(message: APWelcome): unknown {
    const obj: any = {};
    if (message.canonicalUsername !== "") {
      obj.canonicalUsername = message.canonicalUsername;
    }
    if (message.accountTypeLoggedIn !== 0) {
      obj.accountTypeLoggedIn = accountTypeToJSON(message.accountTypeLoggedIn);
    }
    if (message.credentialsTypeLoggedIn !== 0) {
      obj.credentialsTypeLoggedIn = accountTypeToJSON(message.credentialsTypeLoggedIn);
    }
    if (message.reusableAuthCredentialsType !== 0) {
      obj.reusableAuthCredentialsType = authenticationTypeToJSON(message.reusableAuthCredentialsType);
    }
    if (message.reusableAuthCredentials.length !== 0) {
      obj.reusableAuthCredentials = base64FromBytes(message.reusableAuthCredentials);
    }
    if (message.lfsSecret.length !== 0) {
      obj.lfsSecret = base64FromBytes(message.lfsSecret);
    }
    if (message.accountInfo !== undefined) {
      obj.accountInfo = AccountInfo.toJSON(message.accountInfo);
    }
    if (message.fb !== undefined) {
      obj.fb = AccountInfoFacebook.toJSON(message.fb);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<APWelcome>, I>>(base?: I): APWelcome {
    return APWelcome.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<APWelcome>, I>>(object: I): APWelcome {
    const message = createBaseAPWelcome();
    message.canonicalUsername = object.canonicalUsername ?? "";
    message.accountTypeLoggedIn = object.accountTypeLoggedIn ?? 0;
    message.credentialsTypeLoggedIn = object.credentialsTypeLoggedIn ?? 0;
    message.reusableAuthCredentialsType = object.reusableAuthCredentialsType ?? 0;
    message.reusableAuthCredentials = object.reusableAuthCredentials ?? new Uint8Array(0);
    message.lfsSecret = object.lfsSecret ?? new Uint8Array(0);
    message.accountInfo = (object.accountInfo !== undefined && object.accountInfo !== null)
      ? AccountInfo.fromPartial(object.accountInfo)
      : undefined;
    message.fb = (object.fb !== undefined && object.fb !== null)
      ? AccountInfoFacebook.fromPartial(object.fb)
      : undefined;
    return message;
  },
};

function createBaseAccountInfo(): AccountInfo {
  return { spotify: undefined, facebook: undefined };
}

export const AccountInfo = {
  encode(message: AccountInfo, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.spotify !== undefined) {
      AccountInfoSpotify.encode(message.spotify, writer.uint32(10).fork()).ldelim();
    }
    if (message.facebook !== undefined) {
      AccountInfoFacebook.encode(message.facebook, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): AccountInfo {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAccountInfo();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.spotify = AccountInfoSpotify.decode(reader, reader.uint32());
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.facebook = AccountInfoFacebook.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): AccountInfo {
    return {
      spotify: isSet(object.spotify) ? AccountInfoSpotify.fromJSON(object.spotify) : undefined,
      facebook: isSet(object.facebook) ? AccountInfoFacebook.fromJSON(object.facebook) : undefined,
    };
  },

  toJSON(message: AccountInfo): unknown {
    const obj: any = {};
    if (message.spotify !== undefined) {
      obj.spotify = AccountInfoSpotify.toJSON(message.spotify);
    }
    if (message.facebook !== undefined) {
      obj.facebook = AccountInfoFacebook.toJSON(message.facebook);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<AccountInfo>, I>>(base?: I): AccountInfo {
    return AccountInfo.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<AccountInfo>, I>>(object: I): AccountInfo {
    const message = createBaseAccountInfo();
    message.spotify = (object.spotify !== undefined && object.spotify !== null)
      ? AccountInfoSpotify.fromPartial(object.spotify)
      : undefined;
    message.facebook = (object.facebook !== undefined && object.facebook !== null)
      ? AccountInfoFacebook.fromPartial(object.facebook)
      : undefined;
    return message;
  },
};

function createBaseAccountInfoSpotify(): AccountInfoSpotify {
  return {};
}

export const AccountInfoSpotify = {
  encode(_: AccountInfoSpotify, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): AccountInfoSpotify {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAccountInfoSpotify();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(_: any): AccountInfoSpotify {
    return {};
  },

  toJSON(_: AccountInfoSpotify): unknown {
    const obj: any = {};
    return obj;
  },

  create<I extends Exact<DeepPartial<AccountInfoSpotify>, I>>(base?: I): AccountInfoSpotify {
    return AccountInfoSpotify.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<AccountInfoSpotify>, I>>(_: I): AccountInfoSpotify {
    const message = createBaseAccountInfoSpotify();
    return message;
  },
};

function createBaseAccountInfoFacebook(): AccountInfoFacebook {
  return { accessToken: "", machineId: "" };
}

export const AccountInfoFacebook = {
  encode(message: AccountInfoFacebook, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.accessToken !== "") {
      writer.uint32(10).string(message.accessToken);
    }
    if (message.machineId !== "") {
      writer.uint32(18).string(message.machineId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): AccountInfoFacebook {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAccountInfoFacebook();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.accessToken = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.machineId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): AccountInfoFacebook {
    return {
      accessToken: isSet(object.accessToken) ? String(object.accessToken) : "",
      machineId: isSet(object.machineId) ? String(object.machineId) : "",
    };
  },

  toJSON(message: AccountInfoFacebook): unknown {
    const obj: any = {};
    if (message.accessToken !== "") {
      obj.accessToken = message.accessToken;
    }
    if (message.machineId !== "") {
      obj.machineId = message.machineId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<AccountInfoFacebook>, I>>(base?: I): AccountInfoFacebook {
    return AccountInfoFacebook.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<AccountInfoFacebook>, I>>(object: I): AccountInfoFacebook {
    const message = createBaseAccountInfoFacebook();
    message.accessToken = object.accessToken ?? "";
    message.machineId = object.machineId ?? "";
    return message;
  },
};

declare const self: any | undefined;
declare const window: any | undefined;
declare const global: any | undefined;
const tsProtoGlobalThis: any = (() => {
  if (typeof globalThis !== "undefined") {
    return globalThis;
  }
  if (typeof self !== "undefined") {
    return self;
  }
  if (typeof window !== "undefined") {
    return window;
  }
  if (typeof global !== "undefined") {
    return global;
  }
  throw "Unable to locate global object";
})();

function bytesFromBase64(b64: string): Uint8Array {
  if (tsProtoGlobalThis.Buffer) {
    return Uint8Array.from(tsProtoGlobalThis.Buffer.from(b64, "base64"));
  } else {
    const bin = tsProtoGlobalThis.atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; ++i) {
      arr[i] = bin.charCodeAt(i);
    }
    return arr;
  }
}

function base64FromBytes(arr: Uint8Array): string {
  if (tsProtoGlobalThis.Buffer) {
    return tsProtoGlobalThis.Buffer.from(arr).toString("base64");
  } else {
    const bin: string[] = [];
    arr.forEach((byte) => {
      bin.push(String.fromCharCode(byte));
    });
    return tsProtoGlobalThis.btoa(bin.join(""));
  }
}

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;

export type DeepPartial<T> = T extends Builtin ? T
  : T extends Array<infer U> ? Array<DeepPartial<U>> : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>>
  : T extends {} ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;

type KeysOfUnion<T> = T extends T ? keyof T : never;
export type Exact<P, I extends P> = P extends Builtin ? P
  : P & { [K in keyof P]: Exact<P[K], I[K]> } & { [K in Exclude<keyof I, KeysOfUnion<P>>]: never };

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
