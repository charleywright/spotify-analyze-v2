/* eslint-disable */
import Long from "long";
import _m0 from "protobufjs/minimal";

export const protobufPackage = "spotify.keyexchange";

export enum Product {
  PRODUCT_CLIENT = 0,
  PRODUCT_LIBSPOTIFY = 1,
  PRODUCT_MOBILE = 2,
  PRODUCT_PARTNER = 3,
  PRODUCT_LIBSPOTIFY_EMBEDDED = 5,
  UNRECOGNIZED = -1,
}

export function productFromJSON(object: any): Product {
  switch (object) {
    case 0:
    case "PRODUCT_CLIENT":
      return Product.PRODUCT_CLIENT;
    case 1:
    case "PRODUCT_LIBSPOTIFY":
      return Product.PRODUCT_LIBSPOTIFY;
    case 2:
    case "PRODUCT_MOBILE":
      return Product.PRODUCT_MOBILE;
    case 3:
    case "PRODUCT_PARTNER":
      return Product.PRODUCT_PARTNER;
    case 5:
    case "PRODUCT_LIBSPOTIFY_EMBEDDED":
      return Product.PRODUCT_LIBSPOTIFY_EMBEDDED;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Product.UNRECOGNIZED;
  }
}

export function productToJSON(object: Product): string {
  switch (object) {
    case Product.PRODUCT_CLIENT:
      return "PRODUCT_CLIENT";
    case Product.PRODUCT_LIBSPOTIFY:
      return "PRODUCT_LIBSPOTIFY";
    case Product.PRODUCT_MOBILE:
      return "PRODUCT_MOBILE";
    case Product.PRODUCT_PARTNER:
      return "PRODUCT_PARTNER";
    case Product.PRODUCT_LIBSPOTIFY_EMBEDDED:
      return "PRODUCT_LIBSPOTIFY_EMBEDDED";
    case Product.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum ProductFlags {
  PRODUCT_FLAG_NONE = 0,
  PRODUCT_FLAG_DEV_BUILD = 1,
  UNRECOGNIZED = -1,
}

export function productFlagsFromJSON(object: any): ProductFlags {
  switch (object) {
    case 0:
    case "PRODUCT_FLAG_NONE":
      return ProductFlags.PRODUCT_FLAG_NONE;
    case 1:
    case "PRODUCT_FLAG_DEV_BUILD":
      return ProductFlags.PRODUCT_FLAG_DEV_BUILD;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ProductFlags.UNRECOGNIZED;
  }
}

export function productFlagsToJSON(object: ProductFlags): string {
  switch (object) {
    case ProductFlags.PRODUCT_FLAG_NONE:
      return "PRODUCT_FLAG_NONE";
    case ProductFlags.PRODUCT_FLAG_DEV_BUILD:
      return "PRODUCT_FLAG_DEV_BUILD";
    case ProductFlags.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Platform {
  PLATFORM_WIN32_X86 = 0,
  PLATFORM_OSX_X86 = 1,
  PLATFORM_LINUX_X86 = 2,
  PLATFORM_IPHONE_ARM = 3,
  PLATFORM_S60_ARM = 4,
  PLATFORM_OSX_PPC = 5,
  PLATFORM_ANDROID_ARM = 6,
  PLATFORM_WINDOWS_CE_ARM = 7,
  PLATFORM_LINUX_X86_64 = 8,
  PLATFORM_OSX_X86_64 = 9,
  PLATFORM_PALM_ARM = 10,
  PLATFORM_LINUX_SH = 11,
  PLATFORM_FREEBSD_X86 = 12,
  PLATFORM_FREEBSD_X86_64 = 13,
  PLATFORM_BLACKBERRY_ARM = 14,
  PLATFORM_SONOS = 15,
  PLATFORM_LINUX_MIPS = 16,
  PLATFORM_LINUX_ARM = 17,
  PLATFORM_LOGITECH_ARM = 18,
  PLATFORM_LINUX_BLACKFIN = 19,
  PLATFORM_WP7_ARM = 20,
  PLATFORM_ONKYO_ARM = 21,
  PLATFORM_QNXNTO_ARM = 22,
  PLATFORM_BCO_ARM = 23,
  PLATFORM_WEBPLAYER = 24,
  PLATFORM_WP8_ARM = 25,
  PLATFORM_WP8_X86 = 26,
  PLATFORM_WINRT_ARM = 27,
  PLATFORM_WINRT_X86 = 28,
  PLATFORM_WINRT_X86_64 = 29,
  PLATFORM_FRONTIER = 30,
  PLATFORM_AMIGA_PPC = 31,
  PLATFORM_NANRADIO_NRX901 = 32,
  PLATFORM_HARMAN_ARM = 33,
  PLATFORM_SONY_PS3 = 34,
  PLATFORM_SONY_PS4 = 35,
  PLATFORM_IPHONE_ARM64 = 36,
  PLATFORM_RTEMS_PPC = 37,
  PLATFORM_GENERIC_PARTNER = 38,
  PLATFORM_WIN32_X86_64 = 39,
  PLATFORM_WATCHOS = 40,
  UNRECOGNIZED = -1,
}

export function platformFromJSON(object: any): Platform {
  switch (object) {
    case 0:
    case "PLATFORM_WIN32_X86":
      return Platform.PLATFORM_WIN32_X86;
    case 1:
    case "PLATFORM_OSX_X86":
      return Platform.PLATFORM_OSX_X86;
    case 2:
    case "PLATFORM_LINUX_X86":
      return Platform.PLATFORM_LINUX_X86;
    case 3:
    case "PLATFORM_IPHONE_ARM":
      return Platform.PLATFORM_IPHONE_ARM;
    case 4:
    case "PLATFORM_S60_ARM":
      return Platform.PLATFORM_S60_ARM;
    case 5:
    case "PLATFORM_OSX_PPC":
      return Platform.PLATFORM_OSX_PPC;
    case 6:
    case "PLATFORM_ANDROID_ARM":
      return Platform.PLATFORM_ANDROID_ARM;
    case 7:
    case "PLATFORM_WINDOWS_CE_ARM":
      return Platform.PLATFORM_WINDOWS_CE_ARM;
    case 8:
    case "PLATFORM_LINUX_X86_64":
      return Platform.PLATFORM_LINUX_X86_64;
    case 9:
    case "PLATFORM_OSX_X86_64":
      return Platform.PLATFORM_OSX_X86_64;
    case 10:
    case "PLATFORM_PALM_ARM":
      return Platform.PLATFORM_PALM_ARM;
    case 11:
    case "PLATFORM_LINUX_SH":
      return Platform.PLATFORM_LINUX_SH;
    case 12:
    case "PLATFORM_FREEBSD_X86":
      return Platform.PLATFORM_FREEBSD_X86;
    case 13:
    case "PLATFORM_FREEBSD_X86_64":
      return Platform.PLATFORM_FREEBSD_X86_64;
    case 14:
    case "PLATFORM_BLACKBERRY_ARM":
      return Platform.PLATFORM_BLACKBERRY_ARM;
    case 15:
    case "PLATFORM_SONOS":
      return Platform.PLATFORM_SONOS;
    case 16:
    case "PLATFORM_LINUX_MIPS":
      return Platform.PLATFORM_LINUX_MIPS;
    case 17:
    case "PLATFORM_LINUX_ARM":
      return Platform.PLATFORM_LINUX_ARM;
    case 18:
    case "PLATFORM_LOGITECH_ARM":
      return Platform.PLATFORM_LOGITECH_ARM;
    case 19:
    case "PLATFORM_LINUX_BLACKFIN":
      return Platform.PLATFORM_LINUX_BLACKFIN;
    case 20:
    case "PLATFORM_WP7_ARM":
      return Platform.PLATFORM_WP7_ARM;
    case 21:
    case "PLATFORM_ONKYO_ARM":
      return Platform.PLATFORM_ONKYO_ARM;
    case 22:
    case "PLATFORM_QNXNTO_ARM":
      return Platform.PLATFORM_QNXNTO_ARM;
    case 23:
    case "PLATFORM_BCO_ARM":
      return Platform.PLATFORM_BCO_ARM;
    case 24:
    case "PLATFORM_WEBPLAYER":
      return Platform.PLATFORM_WEBPLAYER;
    case 25:
    case "PLATFORM_WP8_ARM":
      return Platform.PLATFORM_WP8_ARM;
    case 26:
    case "PLATFORM_WP8_X86":
      return Platform.PLATFORM_WP8_X86;
    case 27:
    case "PLATFORM_WINRT_ARM":
      return Platform.PLATFORM_WINRT_ARM;
    case 28:
    case "PLATFORM_WINRT_X86":
      return Platform.PLATFORM_WINRT_X86;
    case 29:
    case "PLATFORM_WINRT_X86_64":
      return Platform.PLATFORM_WINRT_X86_64;
    case 30:
    case "PLATFORM_FRONTIER":
      return Platform.PLATFORM_FRONTIER;
    case 31:
    case "PLATFORM_AMIGA_PPC":
      return Platform.PLATFORM_AMIGA_PPC;
    case 32:
    case "PLATFORM_NANRADIO_NRX901":
      return Platform.PLATFORM_NANRADIO_NRX901;
    case 33:
    case "PLATFORM_HARMAN_ARM":
      return Platform.PLATFORM_HARMAN_ARM;
    case 34:
    case "PLATFORM_SONY_PS3":
      return Platform.PLATFORM_SONY_PS3;
    case 35:
    case "PLATFORM_SONY_PS4":
      return Platform.PLATFORM_SONY_PS4;
    case 36:
    case "PLATFORM_IPHONE_ARM64":
      return Platform.PLATFORM_IPHONE_ARM64;
    case 37:
    case "PLATFORM_RTEMS_PPC":
      return Platform.PLATFORM_RTEMS_PPC;
    case 38:
    case "PLATFORM_GENERIC_PARTNER":
      return Platform.PLATFORM_GENERIC_PARTNER;
    case 39:
    case "PLATFORM_WIN32_X86_64":
      return Platform.PLATFORM_WIN32_X86_64;
    case 40:
    case "PLATFORM_WATCHOS":
      return Platform.PLATFORM_WATCHOS;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Platform.UNRECOGNIZED;
  }
}

export function platformToJSON(object: Platform): string {
  switch (object) {
    case Platform.PLATFORM_WIN32_X86:
      return "PLATFORM_WIN32_X86";
    case Platform.PLATFORM_OSX_X86:
      return "PLATFORM_OSX_X86";
    case Platform.PLATFORM_LINUX_X86:
      return "PLATFORM_LINUX_X86";
    case Platform.PLATFORM_IPHONE_ARM:
      return "PLATFORM_IPHONE_ARM";
    case Platform.PLATFORM_S60_ARM:
      return "PLATFORM_S60_ARM";
    case Platform.PLATFORM_OSX_PPC:
      return "PLATFORM_OSX_PPC";
    case Platform.PLATFORM_ANDROID_ARM:
      return "PLATFORM_ANDROID_ARM";
    case Platform.PLATFORM_WINDOWS_CE_ARM:
      return "PLATFORM_WINDOWS_CE_ARM";
    case Platform.PLATFORM_LINUX_X86_64:
      return "PLATFORM_LINUX_X86_64";
    case Platform.PLATFORM_OSX_X86_64:
      return "PLATFORM_OSX_X86_64";
    case Platform.PLATFORM_PALM_ARM:
      return "PLATFORM_PALM_ARM";
    case Platform.PLATFORM_LINUX_SH:
      return "PLATFORM_LINUX_SH";
    case Platform.PLATFORM_FREEBSD_X86:
      return "PLATFORM_FREEBSD_X86";
    case Platform.PLATFORM_FREEBSD_X86_64:
      return "PLATFORM_FREEBSD_X86_64";
    case Platform.PLATFORM_BLACKBERRY_ARM:
      return "PLATFORM_BLACKBERRY_ARM";
    case Platform.PLATFORM_SONOS:
      return "PLATFORM_SONOS";
    case Platform.PLATFORM_LINUX_MIPS:
      return "PLATFORM_LINUX_MIPS";
    case Platform.PLATFORM_LINUX_ARM:
      return "PLATFORM_LINUX_ARM";
    case Platform.PLATFORM_LOGITECH_ARM:
      return "PLATFORM_LOGITECH_ARM";
    case Platform.PLATFORM_LINUX_BLACKFIN:
      return "PLATFORM_LINUX_BLACKFIN";
    case Platform.PLATFORM_WP7_ARM:
      return "PLATFORM_WP7_ARM";
    case Platform.PLATFORM_ONKYO_ARM:
      return "PLATFORM_ONKYO_ARM";
    case Platform.PLATFORM_QNXNTO_ARM:
      return "PLATFORM_QNXNTO_ARM";
    case Platform.PLATFORM_BCO_ARM:
      return "PLATFORM_BCO_ARM";
    case Platform.PLATFORM_WEBPLAYER:
      return "PLATFORM_WEBPLAYER";
    case Platform.PLATFORM_WP8_ARM:
      return "PLATFORM_WP8_ARM";
    case Platform.PLATFORM_WP8_X86:
      return "PLATFORM_WP8_X86";
    case Platform.PLATFORM_WINRT_ARM:
      return "PLATFORM_WINRT_ARM";
    case Platform.PLATFORM_WINRT_X86:
      return "PLATFORM_WINRT_X86";
    case Platform.PLATFORM_WINRT_X86_64:
      return "PLATFORM_WINRT_X86_64";
    case Platform.PLATFORM_FRONTIER:
      return "PLATFORM_FRONTIER";
    case Platform.PLATFORM_AMIGA_PPC:
      return "PLATFORM_AMIGA_PPC";
    case Platform.PLATFORM_NANRADIO_NRX901:
      return "PLATFORM_NANRADIO_NRX901";
    case Platform.PLATFORM_HARMAN_ARM:
      return "PLATFORM_HARMAN_ARM";
    case Platform.PLATFORM_SONY_PS3:
      return "PLATFORM_SONY_PS3";
    case Platform.PLATFORM_SONY_PS4:
      return "PLATFORM_SONY_PS4";
    case Platform.PLATFORM_IPHONE_ARM64:
      return "PLATFORM_IPHONE_ARM64";
    case Platform.PLATFORM_RTEMS_PPC:
      return "PLATFORM_RTEMS_PPC";
    case Platform.PLATFORM_GENERIC_PARTNER:
      return "PLATFORM_GENERIC_PARTNER";
    case Platform.PLATFORM_WIN32_X86_64:
      return "PLATFORM_WIN32_X86_64";
    case Platform.PLATFORM_WATCHOS:
      return "PLATFORM_WATCHOS";
    case Platform.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Fingerprint {
  FINGERPRINT_GRAIN = 0,
  FINGERPRINT_HMAC_RIPEMD = 1,
  UNRECOGNIZED = -1,
}

export function fingerprintFromJSON(object: any): Fingerprint {
  switch (object) {
    case 0:
    case "FINGERPRINT_GRAIN":
      return Fingerprint.FINGERPRINT_GRAIN;
    case 1:
    case "FINGERPRINT_HMAC_RIPEMD":
      return Fingerprint.FINGERPRINT_HMAC_RIPEMD;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Fingerprint.UNRECOGNIZED;
  }
}

export function fingerprintToJSON(object: Fingerprint): string {
  switch (object) {
    case Fingerprint.FINGERPRINT_GRAIN:
      return "FINGERPRINT_GRAIN";
    case Fingerprint.FINGERPRINT_HMAC_RIPEMD:
      return "FINGERPRINT_HMAC_RIPEMD";
    case Fingerprint.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Cryptosuite {
  CRYPTO_SUITE_SHANNON = 0,
  CRYPTO_SUITE_RC4_SHA1_HMAC = 1,
  UNRECOGNIZED = -1,
}

export function cryptosuiteFromJSON(object: any): Cryptosuite {
  switch (object) {
    case 0:
    case "CRYPTO_SUITE_SHANNON":
      return Cryptosuite.CRYPTO_SUITE_SHANNON;
    case 1:
    case "CRYPTO_SUITE_RC4_SHA1_HMAC":
      return Cryptosuite.CRYPTO_SUITE_RC4_SHA1_HMAC;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Cryptosuite.UNRECOGNIZED;
  }
}

export function cryptosuiteToJSON(object: Cryptosuite): string {
  switch (object) {
    case Cryptosuite.CRYPTO_SUITE_SHANNON:
      return "CRYPTO_SUITE_SHANNON";
    case Cryptosuite.CRYPTO_SUITE_RC4_SHA1_HMAC:
      return "CRYPTO_SUITE_RC4_SHA1_HMAC";
    case Cryptosuite.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum Powscheme {
  POW_HASH_CASH = 0,
  UNRECOGNIZED = -1,
}

export function powschemeFromJSON(object: any): Powscheme {
  switch (object) {
    case 0:
    case "POW_HASH_CASH":
      return Powscheme.POW_HASH_CASH;
    case -1:
    case "UNRECOGNIZED":
    default:
      return Powscheme.UNRECOGNIZED;
  }
}

export function powschemeToJSON(object: Powscheme): string {
  switch (object) {
    case Powscheme.POW_HASH_CASH:
      return "POW_HASH_CASH";
    case Powscheme.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum ErrorCode {
  ProtocolError = 0,
  TryAnotherAP = 2,
  BadConnectionId = 5,
  TravelRestriction = 9,
  PremiumAccountRequired = 11,
  BadCredentials = 12,
  CouldNotValidateCredentials = 13,
  AccountExists = 14,
  ExtraVerificationRequired = 15,
  InvalidAppKey = 16,
  ApplicationBanned = 17,
  UNRECOGNIZED = -1,
}

export function errorCodeFromJSON(object: any): ErrorCode {
  switch (object) {
    case 0:
    case "ProtocolError":
      return ErrorCode.ProtocolError;
    case 2:
    case "TryAnotherAP":
      return ErrorCode.TryAnotherAP;
    case 5:
    case "BadConnectionId":
      return ErrorCode.BadConnectionId;
    case 9:
    case "TravelRestriction":
      return ErrorCode.TravelRestriction;
    case 11:
    case "PremiumAccountRequired":
      return ErrorCode.PremiumAccountRequired;
    case 12:
    case "BadCredentials":
      return ErrorCode.BadCredentials;
    case 13:
    case "CouldNotValidateCredentials":
      return ErrorCode.CouldNotValidateCredentials;
    case 14:
    case "AccountExists":
      return ErrorCode.AccountExists;
    case 15:
    case "ExtraVerificationRequired":
      return ErrorCode.ExtraVerificationRequired;
    case 16:
    case "InvalidAppKey":
      return ErrorCode.InvalidAppKey;
    case 17:
    case "ApplicationBanned":
      return ErrorCode.ApplicationBanned;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ErrorCode.UNRECOGNIZED;
  }
}

export function errorCodeToJSON(object: ErrorCode): string {
  switch (object) {
    case ErrorCode.ProtocolError:
      return "ProtocolError";
    case ErrorCode.TryAnotherAP:
      return "TryAnotherAP";
    case ErrorCode.BadConnectionId:
      return "BadConnectionId";
    case ErrorCode.TravelRestriction:
      return "TravelRestriction";
    case ErrorCode.PremiumAccountRequired:
      return "PremiumAccountRequired";
    case ErrorCode.BadCredentials:
      return "BadCredentials";
    case ErrorCode.CouldNotValidateCredentials:
      return "CouldNotValidateCredentials";
    case ErrorCode.AccountExists:
      return "AccountExists";
    case ErrorCode.ExtraVerificationRequired:
      return "ExtraVerificationRequired";
    case ErrorCode.InvalidAppKey:
      return "InvalidAppKey";
    case ErrorCode.ApplicationBanned:
      return "ApplicationBanned";
    case ErrorCode.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface ClientHello {
  buildInfo: BuildInfo | undefined;
  fingerprintsSupported: Fingerprint[];
  cryptosuitesSupported: Cryptosuite[];
  powschemesSupported: Powscheme[];
  loginCryptoHello: LoginCryptoHelloUnion | undefined;
  clientNonce: Uint8Array;
  padding: Uint8Array;
  featureSet: FeatureSet | undefined;
}

export interface BuildInfo {
  product: Product;
  productFlags: ProductFlags[];
  platform: Platform;
  version: number;
}

export interface LoginCryptoHelloUnion {
  diffieHellman: LoginCryptoDiffieHellmanHello | undefined;
}

export interface LoginCryptoDiffieHellmanHello {
  gc: Uint8Array;
  serverKeysKnown: number;
}

export interface FeatureSet {
  autoupdate2: boolean;
  currentLocation: boolean;
}

export interface APResponseMessage {
  challenge: APChallenge | undefined;
  upgrade: UpgradeRequiredMessage | undefined;
  loginFailed: APLoginFailed | undefined;
}

export interface APChallenge {
  loginCryptoChallenge: LoginCryptoChallengeUnion | undefined;
  fingerprintChallenge: FingerprintChallengeUnion | undefined;
  powChallenge: PoWChallengeUnion | undefined;
  cryptoChallenge: CryptoChallengeUnion | undefined;
  serverNonce: Uint8Array;
  padding: Uint8Array;
}

export interface LoginCryptoChallengeUnion {
  diffieHellman: LoginCryptoDiffieHellmanChallenge | undefined;
}

export interface LoginCryptoDiffieHellmanChallenge {
  gs: Uint8Array;
  serverSignatureKey: number;
  gsSignature: Uint8Array;
}

export interface FingerprintChallengeUnion {
  grain: FingerprintGrainChallenge | undefined;
  hmacRipemd: FingerprintHmacRipemdChallenge | undefined;
}

export interface FingerprintGrainChallenge {
  kek: Uint8Array;
}

export interface FingerprintHmacRipemdChallenge {
  challenge: Uint8Array;
}

export interface PoWChallengeUnion {
  hashCash: PoWHashCashChallenge | undefined;
}

export interface PoWHashCashChallenge {
  prefix: Uint8Array;
  length: number;
  target: number;
}

export interface CryptoChallengeUnion {
  shannon: CryptoShannonChallenge | undefined;
  rc4Sha1Hmac: CryptoRc4Sha1HmacChallenge | undefined;
}

export interface CryptoShannonChallenge {
}

export interface CryptoRc4Sha1HmacChallenge {
}

export interface UpgradeRequiredMessage {
  upgradeSignedPart: Uint8Array;
  signature: Uint8Array;
  httpSuffix: string;
}

export interface APLoginFailed {
  errorCode: ErrorCode;
  retryDelay: number;
  expiry: number;
  errorDescription: string;
}

export interface ClientResponsePlaintext {
  loginCryptoResponse: LoginCryptoResponseUnion | undefined;
  powResponse: PoWResponseUnion | undefined;
  cryptoResponse: CryptoResponseUnion | undefined;
}

export interface LoginCryptoResponseUnion {
  diffieHellman: LoginCryptoDiffieHellmanResponse | undefined;
}

export interface LoginCryptoDiffieHellmanResponse {
  hmac: Uint8Array;
}

export interface PoWResponseUnion {
  hashCash: PoWHashCashResponse | undefined;
}

export interface PoWHashCashResponse {
  hashSuffix: Uint8Array;
}

export interface CryptoResponseUnion {
  shannon: CryptoShannonResponse | undefined;
  rc4Sha1Hmac: CryptoRc4Sha1HmacResponse | undefined;
}

export interface CryptoShannonResponse {
  dummy: number;
}

export interface CryptoRc4Sha1HmacResponse {
  dummy: number;
}

function createBaseClientHello(): ClientHello {
  return {
    buildInfo: undefined,
    fingerprintsSupported: [],
    cryptosuitesSupported: [],
    powschemesSupported: [],
    loginCryptoHello: undefined,
    clientNonce: new Uint8Array(0),
    padding: new Uint8Array(0),
    featureSet: undefined,
  };
}

export const ClientHello = {
  encode(message: ClientHello, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.buildInfo !== undefined) {
      BuildInfo.encode(message.buildInfo, writer.uint32(82).fork()).ldelim();
    }
    writer.uint32(162).fork();
    for (const v of message.fingerprintsSupported) {
      writer.int32(v);
    }
    writer.ldelim();
    writer.uint32(242).fork();
    for (const v of message.cryptosuitesSupported) {
      writer.int32(v);
    }
    writer.ldelim();
    writer.uint32(322).fork();
    for (const v of message.powschemesSupported) {
      writer.int32(v);
    }
    writer.ldelim();
    if (message.loginCryptoHello !== undefined) {
      LoginCryptoHelloUnion.encode(message.loginCryptoHello, writer.uint32(402).fork()).ldelim();
    }
    if (message.clientNonce.length !== 0) {
      writer.uint32(482).bytes(message.clientNonce);
    }
    if (message.padding.length !== 0) {
      writer.uint32(562).bytes(message.padding);
    }
    if (message.featureSet !== undefined) {
      FeatureSet.encode(message.featureSet, writer.uint32(642).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ClientHello {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseClientHello();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.buildInfo = BuildInfo.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag === 160) {
            message.fingerprintsSupported.push(reader.int32() as any);

            continue;
          }

          if (tag === 162) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.fingerprintsSupported.push(reader.int32() as any);
            }

            continue;
          }

          break;
        case 30:
          if (tag === 240) {
            message.cryptosuitesSupported.push(reader.int32() as any);

            continue;
          }

          if (tag === 242) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.cryptosuitesSupported.push(reader.int32() as any);
            }

            continue;
          }

          break;
        case 40:
          if (tag === 320) {
            message.powschemesSupported.push(reader.int32() as any);

            continue;
          }

          if (tag === 322) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.powschemesSupported.push(reader.int32() as any);
            }

            continue;
          }

          break;
        case 50:
          if (tag !== 402) {
            break;
          }

          message.loginCryptoHello = LoginCryptoHelloUnion.decode(reader, reader.uint32());
          continue;
        case 60:
          if (tag !== 482) {
            break;
          }

          message.clientNonce = reader.bytes();
          continue;
        case 70:
          if (tag !== 562) {
            break;
          }

          message.padding = reader.bytes();
          continue;
        case 80:
          if (tag !== 642) {
            break;
          }

          message.featureSet = FeatureSet.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ClientHello {
    return {
      buildInfo: isSet(object.buildInfo) ? BuildInfo.fromJSON(object.buildInfo) : undefined,
      fingerprintsSupported: Array.isArray(object?.fingerprintsSupported)
        ? object.fingerprintsSupported.map((e: any) => fingerprintFromJSON(e))
        : [],
      cryptosuitesSupported: Array.isArray(object?.cryptosuitesSupported)
        ? object.cryptosuitesSupported.map((e: any) => cryptosuiteFromJSON(e))
        : [],
      powschemesSupported: Array.isArray(object?.powschemesSupported)
        ? object.powschemesSupported.map((e: any) => powschemeFromJSON(e))
        : [],
      loginCryptoHello: isSet(object.loginCryptoHello)
        ? LoginCryptoHelloUnion.fromJSON(object.loginCryptoHello)
        : undefined,
      clientNonce: isSet(object.clientNonce) ? bytesFromBase64(object.clientNonce) : new Uint8Array(0),
      padding: isSet(object.padding) ? bytesFromBase64(object.padding) : new Uint8Array(0),
      featureSet: isSet(object.featureSet) ? FeatureSet.fromJSON(object.featureSet) : undefined,
    };
  },

  toJSON(message: ClientHello): unknown {
    const obj: any = {};
    if (message.buildInfo !== undefined) {
      obj.buildInfo = BuildInfo.toJSON(message.buildInfo);
    }
    if (message.fingerprintsSupported?.length) {
      obj.fingerprintsSupported = message.fingerprintsSupported.map((e) => fingerprintToJSON(e));
    }
    if (message.cryptosuitesSupported?.length) {
      obj.cryptosuitesSupported = message.cryptosuitesSupported.map((e) => cryptosuiteToJSON(e));
    }
    if (message.powschemesSupported?.length) {
      obj.powschemesSupported = message.powschemesSupported.map((e) => powschemeToJSON(e));
    }
    if (message.loginCryptoHello !== undefined) {
      obj.loginCryptoHello = LoginCryptoHelloUnion.toJSON(message.loginCryptoHello);
    }
    if (message.clientNonce.length !== 0) {
      obj.clientNonce = base64FromBytes(message.clientNonce);
    }
    if (message.padding.length !== 0) {
      obj.padding = base64FromBytes(message.padding);
    }
    if (message.featureSet !== undefined) {
      obj.featureSet = FeatureSet.toJSON(message.featureSet);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ClientHello>, I>>(base?: I): ClientHello {
    return ClientHello.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ClientHello>, I>>(object: I): ClientHello {
    const message = createBaseClientHello();
    message.buildInfo = (object.buildInfo !== undefined && object.buildInfo !== null)
      ? BuildInfo.fromPartial(object.buildInfo)
      : undefined;
    message.fingerprintsSupported = object.fingerprintsSupported?.map((e) => e) || [];
    message.cryptosuitesSupported = object.cryptosuitesSupported?.map((e) => e) || [];
    message.powschemesSupported = object.powschemesSupported?.map((e) => e) || [];
    message.loginCryptoHello = (object.loginCryptoHello !== undefined && object.loginCryptoHello !== null)
      ? LoginCryptoHelloUnion.fromPartial(object.loginCryptoHello)
      : undefined;
    message.clientNonce = object.clientNonce ?? new Uint8Array(0);
    message.padding = object.padding ?? new Uint8Array(0);
    message.featureSet = (object.featureSet !== undefined && object.featureSet !== null)
      ? FeatureSet.fromPartial(object.featureSet)
      : undefined;
    return message;
  },
};

function createBaseBuildInfo(): BuildInfo {
  return { product: 0, productFlags: [], platform: 0, version: 0 };
}

export const BuildInfo = {
  encode(message: BuildInfo, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.product !== 0) {
      writer.uint32(80).int32(message.product);
    }
    writer.uint32(162).fork();
    for (const v of message.productFlags) {
      writer.int32(v);
    }
    writer.ldelim();
    if (message.platform !== 0) {
      writer.uint32(240).int32(message.platform);
    }
    if (message.version !== 0) {
      writer.uint32(320).uint64(message.version);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): BuildInfo {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBuildInfo();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 80) {
            break;
          }

          message.product = reader.int32() as any;
          continue;
        case 20:
          if (tag === 160) {
            message.productFlags.push(reader.int32() as any);

            continue;
          }

          if (tag === 162) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.productFlags.push(reader.int32() as any);
            }

            continue;
          }

          break;
        case 30:
          if (tag !== 240) {
            break;
          }

          message.platform = reader.int32() as any;
          continue;
        case 40:
          if (tag !== 320) {
            break;
          }

          message.version = longToNumber(reader.uint64() as Long);
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): BuildInfo {
    return {
      product: isSet(object.product) ? productFromJSON(object.product) : 0,
      productFlags: Array.isArray(object?.productFlags)
        ? object.productFlags.map((e: any) => productFlagsFromJSON(e))
        : [],
      platform: isSet(object.platform) ? platformFromJSON(object.platform) : 0,
      version: isSet(object.version) ? Number(object.version) : 0,
    };
  },

  toJSON(message: BuildInfo): unknown {
    const obj: any = {};
    if (message.product !== 0) {
      obj.product = productToJSON(message.product);
    }
    if (message.productFlags?.length) {
      obj.productFlags = message.productFlags.map((e) => productFlagsToJSON(e));
    }
    if (message.platform !== 0) {
      obj.platform = platformToJSON(message.platform);
    }
    if (message.version !== 0) {
      obj.version = Math.round(message.version);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<BuildInfo>, I>>(base?: I): BuildInfo {
    return BuildInfo.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<BuildInfo>, I>>(object: I): BuildInfo {
    const message = createBaseBuildInfo();
    message.product = object.product ?? 0;
    message.productFlags = object.productFlags?.map((e) => e) || [];
    message.platform = object.platform ?? 0;
    message.version = object.version ?? 0;
    return message;
  },
};

function createBaseLoginCryptoHelloUnion(): LoginCryptoHelloUnion {
  return { diffieHellman: undefined };
}

export const LoginCryptoHelloUnion = {
  encode(message: LoginCryptoHelloUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.diffieHellman !== undefined) {
      LoginCryptoDiffieHellmanHello.encode(message.diffieHellman, writer.uint32(82).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoHelloUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoHelloUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.diffieHellman = LoginCryptoDiffieHellmanHello.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCryptoHelloUnion {
    return {
      diffieHellman: isSet(object.diffieHellman)
        ? LoginCryptoDiffieHellmanHello.fromJSON(object.diffieHellman)
        : undefined,
    };
  },

  toJSON(message: LoginCryptoHelloUnion): unknown {
    const obj: any = {};
    if (message.diffieHellman !== undefined) {
      obj.diffieHellman = LoginCryptoDiffieHellmanHello.toJSON(message.diffieHellman);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoHelloUnion>, I>>(base?: I): LoginCryptoHelloUnion {
    return LoginCryptoHelloUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoHelloUnion>, I>>(object: I): LoginCryptoHelloUnion {
    const message = createBaseLoginCryptoHelloUnion();
    message.diffieHellman = (object.diffieHellman !== undefined && object.diffieHellman !== null)
      ? LoginCryptoDiffieHellmanHello.fromPartial(object.diffieHellman)
      : undefined;
    return message;
  },
};

function createBaseLoginCryptoDiffieHellmanHello(): LoginCryptoDiffieHellmanHello {
  return { gc: new Uint8Array(0), serverKeysKnown: 0 };
}

export const LoginCryptoDiffieHellmanHello = {
  encode(message: LoginCryptoDiffieHellmanHello, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.gc.length !== 0) {
      writer.uint32(82).bytes(message.gc);
    }
    if (message.serverKeysKnown !== 0) {
      writer.uint32(160).uint32(message.serverKeysKnown);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoDiffieHellmanHello {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoDiffieHellmanHello();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.gc = reader.bytes();
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.serverKeysKnown = reader.uint32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCryptoDiffieHellmanHello {
    return {
      gc: isSet(object.gc) ? bytesFromBase64(object.gc) : new Uint8Array(0),
      serverKeysKnown: isSet(object.serverKeysKnown) ? Number(object.serverKeysKnown) : 0,
    };
  },

  toJSON(message: LoginCryptoDiffieHellmanHello): unknown {
    const obj: any = {};
    if (message.gc.length !== 0) {
      obj.gc = base64FromBytes(message.gc);
    }
    if (message.serverKeysKnown !== 0) {
      obj.serverKeysKnown = Math.round(message.serverKeysKnown);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanHello>, I>>(base?: I): LoginCryptoDiffieHellmanHello {
    return LoginCryptoDiffieHellmanHello.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanHello>, I>>(
    object: I,
  ): LoginCryptoDiffieHellmanHello {
    const message = createBaseLoginCryptoDiffieHellmanHello();
    message.gc = object.gc ?? new Uint8Array(0);
    message.serverKeysKnown = object.serverKeysKnown ?? 0;
    return message;
  },
};

function createBaseFeatureSet(): FeatureSet {
  return { autoupdate2: false, currentLocation: false };
}

export const FeatureSet = {
  encode(message: FeatureSet, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.autoupdate2 === true) {
      writer.uint32(8).bool(message.autoupdate2);
    }
    if (message.currentLocation === true) {
      writer.uint32(16).bool(message.currentLocation);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FeatureSet {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFeatureSet();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.autoupdate2 = reader.bool();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.currentLocation = reader.bool();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FeatureSet {
    return {
      autoupdate2: isSet(object.autoupdate2) ? Boolean(object.autoupdate2) : false,
      currentLocation: isSet(object.currentLocation) ? Boolean(object.currentLocation) : false,
    };
  },

  toJSON(message: FeatureSet): unknown {
    const obj: any = {};
    if (message.autoupdate2 === true) {
      obj.autoupdate2 = message.autoupdate2;
    }
    if (message.currentLocation === true) {
      obj.currentLocation = message.currentLocation;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FeatureSet>, I>>(base?: I): FeatureSet {
    return FeatureSet.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FeatureSet>, I>>(object: I): FeatureSet {
    const message = createBaseFeatureSet();
    message.autoupdate2 = object.autoupdate2 ?? false;
    message.currentLocation = object.currentLocation ?? false;
    return message;
  },
};

function createBaseAPResponseMessage(): APResponseMessage {
  return { challenge: undefined, upgrade: undefined, loginFailed: undefined };
}

export const APResponseMessage = {
  encode(message: APResponseMessage, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.challenge !== undefined) {
      APChallenge.encode(message.challenge, writer.uint32(82).fork()).ldelim();
    }
    if (message.upgrade !== undefined) {
      UpgradeRequiredMessage.encode(message.upgrade, writer.uint32(162).fork()).ldelim();
    }
    if (message.loginFailed !== undefined) {
      APLoginFailed.encode(message.loginFailed, writer.uint32(242).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): APResponseMessage {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAPResponseMessage();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.challenge = APChallenge.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.upgrade = UpgradeRequiredMessage.decode(reader, reader.uint32());
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.loginFailed = APLoginFailed.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): APResponseMessage {
    return {
      challenge: isSet(object.challenge) ? APChallenge.fromJSON(object.challenge) : undefined,
      upgrade: isSet(object.upgrade) ? UpgradeRequiredMessage.fromJSON(object.upgrade) : undefined,
      loginFailed: isSet(object.loginFailed) ? APLoginFailed.fromJSON(object.loginFailed) : undefined,
    };
  },

  toJSON(message: APResponseMessage): unknown {
    const obj: any = {};
    if (message.challenge !== undefined) {
      obj.challenge = APChallenge.toJSON(message.challenge);
    }
    if (message.upgrade !== undefined) {
      obj.upgrade = UpgradeRequiredMessage.toJSON(message.upgrade);
    }
    if (message.loginFailed !== undefined) {
      obj.loginFailed = APLoginFailed.toJSON(message.loginFailed);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<APResponseMessage>, I>>(base?: I): APResponseMessage {
    return APResponseMessage.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<APResponseMessage>, I>>(object: I): APResponseMessage {
    const message = createBaseAPResponseMessage();
    message.challenge = (object.challenge !== undefined && object.challenge !== null)
      ? APChallenge.fromPartial(object.challenge)
      : undefined;
    message.upgrade = (object.upgrade !== undefined && object.upgrade !== null)
      ? UpgradeRequiredMessage.fromPartial(object.upgrade)
      : undefined;
    message.loginFailed = (object.loginFailed !== undefined && object.loginFailed !== null)
      ? APLoginFailed.fromPartial(object.loginFailed)
      : undefined;
    return message;
  },
};

function createBaseAPChallenge(): APChallenge {
  return {
    loginCryptoChallenge: undefined,
    fingerprintChallenge: undefined,
    powChallenge: undefined,
    cryptoChallenge: undefined,
    serverNonce: new Uint8Array(0),
    padding: new Uint8Array(0),
  };
}

export const APChallenge = {
  encode(message: APChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.loginCryptoChallenge !== undefined) {
      LoginCryptoChallengeUnion.encode(message.loginCryptoChallenge, writer.uint32(82).fork()).ldelim();
    }
    if (message.fingerprintChallenge !== undefined) {
      FingerprintChallengeUnion.encode(message.fingerprintChallenge, writer.uint32(162).fork()).ldelim();
    }
    if (message.powChallenge !== undefined) {
      PoWChallengeUnion.encode(message.powChallenge, writer.uint32(242).fork()).ldelim();
    }
    if (message.cryptoChallenge !== undefined) {
      CryptoChallengeUnion.encode(message.cryptoChallenge, writer.uint32(322).fork()).ldelim();
    }
    if (message.serverNonce.length !== 0) {
      writer.uint32(402).bytes(message.serverNonce);
    }
    if (message.padding.length !== 0) {
      writer.uint32(482).bytes(message.padding);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): APChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAPChallenge();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.loginCryptoChallenge = LoginCryptoChallengeUnion.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.fingerprintChallenge = FingerprintChallengeUnion.decode(reader, reader.uint32());
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.powChallenge = PoWChallengeUnion.decode(reader, reader.uint32());
          continue;
        case 40:
          if (tag !== 322) {
            break;
          }

          message.cryptoChallenge = CryptoChallengeUnion.decode(reader, reader.uint32());
          continue;
        case 50:
          if (tag !== 402) {
            break;
          }

          message.serverNonce = reader.bytes();
          continue;
        case 60:
          if (tag !== 482) {
            break;
          }

          message.padding = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): APChallenge {
    return {
      loginCryptoChallenge: isSet(object.loginCryptoChallenge)
        ? LoginCryptoChallengeUnion.fromJSON(object.loginCryptoChallenge)
        : undefined,
      fingerprintChallenge: isSet(object.fingerprintChallenge)
        ? FingerprintChallengeUnion.fromJSON(object.fingerprintChallenge)
        : undefined,
      powChallenge: isSet(object.powChallenge) ? PoWChallengeUnion.fromJSON(object.powChallenge) : undefined,
      cryptoChallenge: isSet(object.cryptoChallenge)
        ? CryptoChallengeUnion.fromJSON(object.cryptoChallenge)
        : undefined,
      serverNonce: isSet(object.serverNonce) ? bytesFromBase64(object.serverNonce) : new Uint8Array(0),
      padding: isSet(object.padding) ? bytesFromBase64(object.padding) : new Uint8Array(0),
    };
  },

  toJSON(message: APChallenge): unknown {
    const obj: any = {};
    if (message.loginCryptoChallenge !== undefined) {
      obj.loginCryptoChallenge = LoginCryptoChallengeUnion.toJSON(message.loginCryptoChallenge);
    }
    if (message.fingerprintChallenge !== undefined) {
      obj.fingerprintChallenge = FingerprintChallengeUnion.toJSON(message.fingerprintChallenge);
    }
    if (message.powChallenge !== undefined) {
      obj.powChallenge = PoWChallengeUnion.toJSON(message.powChallenge);
    }
    if (message.cryptoChallenge !== undefined) {
      obj.cryptoChallenge = CryptoChallengeUnion.toJSON(message.cryptoChallenge);
    }
    if (message.serverNonce.length !== 0) {
      obj.serverNonce = base64FromBytes(message.serverNonce);
    }
    if (message.padding.length !== 0) {
      obj.padding = base64FromBytes(message.padding);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<APChallenge>, I>>(base?: I): APChallenge {
    return APChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<APChallenge>, I>>(object: I): APChallenge {
    const message = createBaseAPChallenge();
    message.loginCryptoChallenge = (object.loginCryptoChallenge !== undefined && object.loginCryptoChallenge !== null)
      ? LoginCryptoChallengeUnion.fromPartial(object.loginCryptoChallenge)
      : undefined;
    message.fingerprintChallenge = (object.fingerprintChallenge !== undefined && object.fingerprintChallenge !== null)
      ? FingerprintChallengeUnion.fromPartial(object.fingerprintChallenge)
      : undefined;
    message.powChallenge = (object.powChallenge !== undefined && object.powChallenge !== null)
      ? PoWChallengeUnion.fromPartial(object.powChallenge)
      : undefined;
    message.cryptoChallenge = (object.cryptoChallenge !== undefined && object.cryptoChallenge !== null)
      ? CryptoChallengeUnion.fromPartial(object.cryptoChallenge)
      : undefined;
    message.serverNonce = object.serverNonce ?? new Uint8Array(0);
    message.padding = object.padding ?? new Uint8Array(0);
    return message;
  },
};

function createBaseLoginCryptoChallengeUnion(): LoginCryptoChallengeUnion {
  return { diffieHellman: undefined };
}

export const LoginCryptoChallengeUnion = {
  encode(message: LoginCryptoChallengeUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.diffieHellman !== undefined) {
      LoginCryptoDiffieHellmanChallenge.encode(message.diffieHellman, writer.uint32(82).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoChallengeUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoChallengeUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.diffieHellman = LoginCryptoDiffieHellmanChallenge.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCryptoChallengeUnion {
    return {
      diffieHellman: isSet(object.diffieHellman)
        ? LoginCryptoDiffieHellmanChallenge.fromJSON(object.diffieHellman)
        : undefined,
    };
  },

  toJSON(message: LoginCryptoChallengeUnion): unknown {
    const obj: any = {};
    if (message.diffieHellman !== undefined) {
      obj.diffieHellman = LoginCryptoDiffieHellmanChallenge.toJSON(message.diffieHellman);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoChallengeUnion>, I>>(base?: I): LoginCryptoChallengeUnion {
    return LoginCryptoChallengeUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoChallengeUnion>, I>>(object: I): LoginCryptoChallengeUnion {
    const message = createBaseLoginCryptoChallengeUnion();
    message.diffieHellman = (object.diffieHellman !== undefined && object.diffieHellman !== null)
      ? LoginCryptoDiffieHellmanChallenge.fromPartial(object.diffieHellman)
      : undefined;
    return message;
  },
};

function createBaseLoginCryptoDiffieHellmanChallenge(): LoginCryptoDiffieHellmanChallenge {
  return { gs: new Uint8Array(0), serverSignatureKey: 0, gsSignature: new Uint8Array(0) };
}

export const LoginCryptoDiffieHellmanChallenge = {
  encode(message: LoginCryptoDiffieHellmanChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.gs.length !== 0) {
      writer.uint32(82).bytes(message.gs);
    }
    if (message.serverSignatureKey !== 0) {
      writer.uint32(160).int32(message.serverSignatureKey);
    }
    if (message.gsSignature.length !== 0) {
      writer.uint32(242).bytes(message.gsSignature);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoDiffieHellmanChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoDiffieHellmanChallenge();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.gs = reader.bytes();
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.serverSignatureKey = reader.int32();
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.gsSignature = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCryptoDiffieHellmanChallenge {
    return {
      gs: isSet(object.gs) ? bytesFromBase64(object.gs) : new Uint8Array(0),
      serverSignatureKey: isSet(object.serverSignatureKey) ? Number(object.serverSignatureKey) : 0,
      gsSignature: isSet(object.gsSignature) ? bytesFromBase64(object.gsSignature) : new Uint8Array(0),
    };
  },

  toJSON(message: LoginCryptoDiffieHellmanChallenge): unknown {
    const obj: any = {};
    if (message.gs.length !== 0) {
      obj.gs = base64FromBytes(message.gs);
    }
    if (message.serverSignatureKey !== 0) {
      obj.serverSignatureKey = Math.round(message.serverSignatureKey);
    }
    if (message.gsSignature.length !== 0) {
      obj.gsSignature = base64FromBytes(message.gsSignature);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanChallenge>, I>>(
    base?: I,
  ): LoginCryptoDiffieHellmanChallenge {
    return LoginCryptoDiffieHellmanChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanChallenge>, I>>(
    object: I,
  ): LoginCryptoDiffieHellmanChallenge {
    const message = createBaseLoginCryptoDiffieHellmanChallenge();
    message.gs = object.gs ?? new Uint8Array(0);
    message.serverSignatureKey = object.serverSignatureKey ?? 0;
    message.gsSignature = object.gsSignature ?? new Uint8Array(0);
    return message;
  },
};

function createBaseFingerprintChallengeUnion(): FingerprintChallengeUnion {
  return { grain: undefined, hmacRipemd: undefined };
}

export const FingerprintChallengeUnion = {
  encode(message: FingerprintChallengeUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.grain !== undefined) {
      FingerprintGrainChallenge.encode(message.grain, writer.uint32(82).fork()).ldelim();
    }
    if (message.hmacRipemd !== undefined) {
      FingerprintHmacRipemdChallenge.encode(message.hmacRipemd, writer.uint32(162).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintChallengeUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintChallengeUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.grain = FingerprintGrainChallenge.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.hmacRipemd = FingerprintHmacRipemdChallenge.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintChallengeUnion {
    return {
      grain: isSet(object.grain) ? FingerprintGrainChallenge.fromJSON(object.grain) : undefined,
      hmacRipemd: isSet(object.hmacRipemd) ? FingerprintHmacRipemdChallenge.fromJSON(object.hmacRipemd) : undefined,
    };
  },

  toJSON(message: FingerprintChallengeUnion): unknown {
    const obj: any = {};
    if (message.grain !== undefined) {
      obj.grain = FingerprintGrainChallenge.toJSON(message.grain);
    }
    if (message.hmacRipemd !== undefined) {
      obj.hmacRipemd = FingerprintHmacRipemdChallenge.toJSON(message.hmacRipemd);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintChallengeUnion>, I>>(base?: I): FingerprintChallengeUnion {
    return FingerprintChallengeUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintChallengeUnion>, I>>(object: I): FingerprintChallengeUnion {
    const message = createBaseFingerprintChallengeUnion();
    message.grain = (object.grain !== undefined && object.grain !== null)
      ? FingerprintGrainChallenge.fromPartial(object.grain)
      : undefined;
    message.hmacRipemd = (object.hmacRipemd !== undefined && object.hmacRipemd !== null)
      ? FingerprintHmacRipemdChallenge.fromPartial(object.hmacRipemd)
      : undefined;
    return message;
  },
};

function createBaseFingerprintGrainChallenge(): FingerprintGrainChallenge {
  return { kek: new Uint8Array(0) };
}

export const FingerprintGrainChallenge = {
  encode(message: FingerprintGrainChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.kek.length !== 0) {
      writer.uint32(82).bytes(message.kek);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintGrainChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintGrainChallenge();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.kek = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintGrainChallenge {
    return { kek: isSet(object.kek) ? bytesFromBase64(object.kek) : new Uint8Array(0) };
  },

  toJSON(message: FingerprintGrainChallenge): unknown {
    const obj: any = {};
    if (message.kek.length !== 0) {
      obj.kek = base64FromBytes(message.kek);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintGrainChallenge>, I>>(base?: I): FingerprintGrainChallenge {
    return FingerprintGrainChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintGrainChallenge>, I>>(object: I): FingerprintGrainChallenge {
    const message = createBaseFingerprintGrainChallenge();
    message.kek = object.kek ?? new Uint8Array(0);
    return message;
  },
};

function createBaseFingerprintHmacRipemdChallenge(): FingerprintHmacRipemdChallenge {
  return { challenge: new Uint8Array(0) };
}

export const FingerprintHmacRipemdChallenge = {
  encode(message: FingerprintHmacRipemdChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.challenge.length !== 0) {
      writer.uint32(82).bytes(message.challenge);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): FingerprintHmacRipemdChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseFingerprintHmacRipemdChallenge();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.challenge = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): FingerprintHmacRipemdChallenge {
    return { challenge: isSet(object.challenge) ? bytesFromBase64(object.challenge) : new Uint8Array(0) };
  },

  toJSON(message: FingerprintHmacRipemdChallenge): unknown {
    const obj: any = {};
    if (message.challenge.length !== 0) {
      obj.challenge = base64FromBytes(message.challenge);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<FingerprintHmacRipemdChallenge>, I>>(base?: I): FingerprintHmacRipemdChallenge {
    return FingerprintHmacRipemdChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<FingerprintHmacRipemdChallenge>, I>>(
    object: I,
  ): FingerprintHmacRipemdChallenge {
    const message = createBaseFingerprintHmacRipemdChallenge();
    message.challenge = object.challenge ?? new Uint8Array(0);
    return message;
  },
};

function createBasePoWChallengeUnion(): PoWChallengeUnion {
  return { hashCash: undefined };
}

export const PoWChallengeUnion = {
  encode(message: PoWChallengeUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.hashCash !== undefined) {
      PoWHashCashChallenge.encode(message.hashCash, writer.uint32(82).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PoWChallengeUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePoWChallengeUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.hashCash = PoWHashCashChallenge.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PoWChallengeUnion {
    return { hashCash: isSet(object.hashCash) ? PoWHashCashChallenge.fromJSON(object.hashCash) : undefined };
  },

  toJSON(message: PoWChallengeUnion): unknown {
    const obj: any = {};
    if (message.hashCash !== undefined) {
      obj.hashCash = PoWHashCashChallenge.toJSON(message.hashCash);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PoWChallengeUnion>, I>>(base?: I): PoWChallengeUnion {
    return PoWChallengeUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PoWChallengeUnion>, I>>(object: I): PoWChallengeUnion {
    const message = createBasePoWChallengeUnion();
    message.hashCash = (object.hashCash !== undefined && object.hashCash !== null)
      ? PoWHashCashChallenge.fromPartial(object.hashCash)
      : undefined;
    return message;
  },
};

function createBasePoWHashCashChallenge(): PoWHashCashChallenge {
  return { prefix: new Uint8Array(0), length: 0, target: 0 };
}

export const PoWHashCashChallenge = {
  encode(message: PoWHashCashChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.prefix.length !== 0) {
      writer.uint32(82).bytes(message.prefix);
    }
    if (message.length !== 0) {
      writer.uint32(160).int32(message.length);
    }
    if (message.target !== 0) {
      writer.uint32(240).int32(message.target);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PoWHashCashChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePoWHashCashChallenge();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.prefix = reader.bytes();
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.length = reader.int32();
          continue;
        case 30:
          if (tag !== 240) {
            break;
          }

          message.target = reader.int32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PoWHashCashChallenge {
    return {
      prefix: isSet(object.prefix) ? bytesFromBase64(object.prefix) : new Uint8Array(0),
      length: isSet(object.length) ? Number(object.length) : 0,
      target: isSet(object.target) ? Number(object.target) : 0,
    };
  },

  toJSON(message: PoWHashCashChallenge): unknown {
    const obj: any = {};
    if (message.prefix.length !== 0) {
      obj.prefix = base64FromBytes(message.prefix);
    }
    if (message.length !== 0) {
      obj.length = Math.round(message.length);
    }
    if (message.target !== 0) {
      obj.target = Math.round(message.target);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PoWHashCashChallenge>, I>>(base?: I): PoWHashCashChallenge {
    return PoWHashCashChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PoWHashCashChallenge>, I>>(object: I): PoWHashCashChallenge {
    const message = createBasePoWHashCashChallenge();
    message.prefix = object.prefix ?? new Uint8Array(0);
    message.length = object.length ?? 0;
    message.target = object.target ?? 0;
    return message;
  },
};

function createBaseCryptoChallengeUnion(): CryptoChallengeUnion {
  return { shannon: undefined, rc4Sha1Hmac: undefined };
}

export const CryptoChallengeUnion = {
  encode(message: CryptoChallengeUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.shannon !== undefined) {
      CryptoShannonChallenge.encode(message.shannon, writer.uint32(82).fork()).ldelim();
    }
    if (message.rc4Sha1Hmac !== undefined) {
      CryptoRc4Sha1HmacChallenge.encode(message.rc4Sha1Hmac, writer.uint32(162).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoChallengeUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoChallengeUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.shannon = CryptoShannonChallenge.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.rc4Sha1Hmac = CryptoRc4Sha1HmacChallenge.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CryptoChallengeUnion {
    return {
      shannon: isSet(object.shannon) ? CryptoShannonChallenge.fromJSON(object.shannon) : undefined,
      rc4Sha1Hmac: isSet(object.rc4Sha1Hmac) ? CryptoRc4Sha1HmacChallenge.fromJSON(object.rc4Sha1Hmac) : undefined,
    };
  },

  toJSON(message: CryptoChallengeUnion): unknown {
    const obj: any = {};
    if (message.shannon !== undefined) {
      obj.shannon = CryptoShannonChallenge.toJSON(message.shannon);
    }
    if (message.rc4Sha1Hmac !== undefined) {
      obj.rc4Sha1Hmac = CryptoRc4Sha1HmacChallenge.toJSON(message.rc4Sha1Hmac);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoChallengeUnion>, I>>(base?: I): CryptoChallengeUnion {
    return CryptoChallengeUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoChallengeUnion>, I>>(object: I): CryptoChallengeUnion {
    const message = createBaseCryptoChallengeUnion();
    message.shannon = (object.shannon !== undefined && object.shannon !== null)
      ? CryptoShannonChallenge.fromPartial(object.shannon)
      : undefined;
    message.rc4Sha1Hmac = (object.rc4Sha1Hmac !== undefined && object.rc4Sha1Hmac !== null)
      ? CryptoRc4Sha1HmacChallenge.fromPartial(object.rc4Sha1Hmac)
      : undefined;
    return message;
  },
};

function createBaseCryptoShannonChallenge(): CryptoShannonChallenge {
  return {};
}

export const CryptoShannonChallenge = {
  encode(_: CryptoShannonChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoShannonChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoShannonChallenge();
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

  fromJSON(_: any): CryptoShannonChallenge {
    return {};
  },

  toJSON(_: CryptoShannonChallenge): unknown {
    const obj: any = {};
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoShannonChallenge>, I>>(base?: I): CryptoShannonChallenge {
    return CryptoShannonChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoShannonChallenge>, I>>(_: I): CryptoShannonChallenge {
    const message = createBaseCryptoShannonChallenge();
    return message;
  },
};

function createBaseCryptoRc4Sha1HmacChallenge(): CryptoRc4Sha1HmacChallenge {
  return {};
}

export const CryptoRc4Sha1HmacChallenge = {
  encode(_: CryptoRc4Sha1HmacChallenge, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoRc4Sha1HmacChallenge {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoRc4Sha1HmacChallenge();
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

  fromJSON(_: any): CryptoRc4Sha1HmacChallenge {
    return {};
  },

  toJSON(_: CryptoRc4Sha1HmacChallenge): unknown {
    const obj: any = {};
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoRc4Sha1HmacChallenge>, I>>(base?: I): CryptoRc4Sha1HmacChallenge {
    return CryptoRc4Sha1HmacChallenge.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoRc4Sha1HmacChallenge>, I>>(_: I): CryptoRc4Sha1HmacChallenge {
    const message = createBaseCryptoRc4Sha1HmacChallenge();
    return message;
  },
};

function createBaseUpgradeRequiredMessage(): UpgradeRequiredMessage {
  return { upgradeSignedPart: new Uint8Array(0), signature: new Uint8Array(0), httpSuffix: "" };
}

export const UpgradeRequiredMessage = {
  encode(message: UpgradeRequiredMessage, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.upgradeSignedPart.length !== 0) {
      writer.uint32(82).bytes(message.upgradeSignedPart);
    }
    if (message.signature.length !== 0) {
      writer.uint32(162).bytes(message.signature);
    }
    if (message.httpSuffix !== "") {
      writer.uint32(242).string(message.httpSuffix);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): UpgradeRequiredMessage {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUpgradeRequiredMessage();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.upgradeSignedPart = reader.bytes();
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.signature = reader.bytes();
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.httpSuffix = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): UpgradeRequiredMessage {
    return {
      upgradeSignedPart: isSet(object.upgradeSignedPart)
        ? bytesFromBase64(object.upgradeSignedPart)
        : new Uint8Array(0),
      signature: isSet(object.signature) ? bytesFromBase64(object.signature) : new Uint8Array(0),
      httpSuffix: isSet(object.httpSuffix) ? String(object.httpSuffix) : "",
    };
  },

  toJSON(message: UpgradeRequiredMessage): unknown {
    const obj: any = {};
    if (message.upgradeSignedPart.length !== 0) {
      obj.upgradeSignedPart = base64FromBytes(message.upgradeSignedPart);
    }
    if (message.signature.length !== 0) {
      obj.signature = base64FromBytes(message.signature);
    }
    if (message.httpSuffix !== "") {
      obj.httpSuffix = message.httpSuffix;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<UpgradeRequiredMessage>, I>>(base?: I): UpgradeRequiredMessage {
    return UpgradeRequiredMessage.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<UpgradeRequiredMessage>, I>>(object: I): UpgradeRequiredMessage {
    const message = createBaseUpgradeRequiredMessage();
    message.upgradeSignedPart = object.upgradeSignedPart ?? new Uint8Array(0);
    message.signature = object.signature ?? new Uint8Array(0);
    message.httpSuffix = object.httpSuffix ?? "";
    return message;
  },
};

function createBaseAPLoginFailed(): APLoginFailed {
  return { errorCode: 0, retryDelay: 0, expiry: 0, errorDescription: "" };
}

export const APLoginFailed = {
  encode(message: APLoginFailed, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.errorCode !== 0) {
      writer.uint32(80).int32(message.errorCode);
    }
    if (message.retryDelay !== 0) {
      writer.uint32(160).int32(message.retryDelay);
    }
    if (message.expiry !== 0) {
      writer.uint32(240).int32(message.expiry);
    }
    if (message.errorDescription !== "") {
      writer.uint32(322).string(message.errorDescription);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): APLoginFailed {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAPLoginFailed();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 80) {
            break;
          }

          message.errorCode = reader.int32() as any;
          continue;
        case 20:
          if (tag !== 160) {
            break;
          }

          message.retryDelay = reader.int32();
          continue;
        case 30:
          if (tag !== 240) {
            break;
          }

          message.expiry = reader.int32();
          continue;
        case 40:
          if (tag !== 322) {
            break;
          }

          message.errorDescription = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): APLoginFailed {
    return {
      errorCode: isSet(object.errorCode) ? errorCodeFromJSON(object.errorCode) : 0,
      retryDelay: isSet(object.retryDelay) ? Number(object.retryDelay) : 0,
      expiry: isSet(object.expiry) ? Number(object.expiry) : 0,
      errorDescription: isSet(object.errorDescription) ? String(object.errorDescription) : "",
    };
  },

  toJSON(message: APLoginFailed): unknown {
    const obj: any = {};
    if (message.errorCode !== 0) {
      obj.errorCode = errorCodeToJSON(message.errorCode);
    }
    if (message.retryDelay !== 0) {
      obj.retryDelay = Math.round(message.retryDelay);
    }
    if (message.expiry !== 0) {
      obj.expiry = Math.round(message.expiry);
    }
    if (message.errorDescription !== "") {
      obj.errorDescription = message.errorDescription;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<APLoginFailed>, I>>(base?: I): APLoginFailed {
    return APLoginFailed.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<APLoginFailed>, I>>(object: I): APLoginFailed {
    const message = createBaseAPLoginFailed();
    message.errorCode = object.errorCode ?? 0;
    message.retryDelay = object.retryDelay ?? 0;
    message.expiry = object.expiry ?? 0;
    message.errorDescription = object.errorDescription ?? "";
    return message;
  },
};

function createBaseClientResponsePlaintext(): ClientResponsePlaintext {
  return { loginCryptoResponse: undefined, powResponse: undefined, cryptoResponse: undefined };
}

export const ClientResponsePlaintext = {
  encode(message: ClientResponsePlaintext, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.loginCryptoResponse !== undefined) {
      LoginCryptoResponseUnion.encode(message.loginCryptoResponse, writer.uint32(82).fork()).ldelim();
    }
    if (message.powResponse !== undefined) {
      PoWResponseUnion.encode(message.powResponse, writer.uint32(162).fork()).ldelim();
    }
    if (message.cryptoResponse !== undefined) {
      CryptoResponseUnion.encode(message.cryptoResponse, writer.uint32(242).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ClientResponsePlaintext {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseClientResponsePlaintext();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.loginCryptoResponse = LoginCryptoResponseUnion.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.powResponse = PoWResponseUnion.decode(reader, reader.uint32());
          continue;
        case 30:
          if (tag !== 242) {
            break;
          }

          message.cryptoResponse = CryptoResponseUnion.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ClientResponsePlaintext {
    return {
      loginCryptoResponse: isSet(object.loginCryptoResponse)
        ? LoginCryptoResponseUnion.fromJSON(object.loginCryptoResponse)
        : undefined,
      powResponse: isSet(object.powResponse) ? PoWResponseUnion.fromJSON(object.powResponse) : undefined,
      cryptoResponse: isSet(object.cryptoResponse) ? CryptoResponseUnion.fromJSON(object.cryptoResponse) : undefined,
    };
  },

  toJSON(message: ClientResponsePlaintext): unknown {
    const obj: any = {};
    if (message.loginCryptoResponse !== undefined) {
      obj.loginCryptoResponse = LoginCryptoResponseUnion.toJSON(message.loginCryptoResponse);
    }
    if (message.powResponse !== undefined) {
      obj.powResponse = PoWResponseUnion.toJSON(message.powResponse);
    }
    if (message.cryptoResponse !== undefined) {
      obj.cryptoResponse = CryptoResponseUnion.toJSON(message.cryptoResponse);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ClientResponsePlaintext>, I>>(base?: I): ClientResponsePlaintext {
    return ClientResponsePlaintext.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ClientResponsePlaintext>, I>>(object: I): ClientResponsePlaintext {
    const message = createBaseClientResponsePlaintext();
    message.loginCryptoResponse = (object.loginCryptoResponse !== undefined && object.loginCryptoResponse !== null)
      ? LoginCryptoResponseUnion.fromPartial(object.loginCryptoResponse)
      : undefined;
    message.powResponse = (object.powResponse !== undefined && object.powResponse !== null)
      ? PoWResponseUnion.fromPartial(object.powResponse)
      : undefined;
    message.cryptoResponse = (object.cryptoResponse !== undefined && object.cryptoResponse !== null)
      ? CryptoResponseUnion.fromPartial(object.cryptoResponse)
      : undefined;
    return message;
  },
};

function createBaseLoginCryptoResponseUnion(): LoginCryptoResponseUnion {
  return { diffieHellman: undefined };
}

export const LoginCryptoResponseUnion = {
  encode(message: LoginCryptoResponseUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.diffieHellman !== undefined) {
      LoginCryptoDiffieHellmanResponse.encode(message.diffieHellman, writer.uint32(82).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoResponseUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoResponseUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.diffieHellman = LoginCryptoDiffieHellmanResponse.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoginCryptoResponseUnion {
    return {
      diffieHellman: isSet(object.diffieHellman)
        ? LoginCryptoDiffieHellmanResponse.fromJSON(object.diffieHellman)
        : undefined,
    };
  },

  toJSON(message: LoginCryptoResponseUnion): unknown {
    const obj: any = {};
    if (message.diffieHellman !== undefined) {
      obj.diffieHellman = LoginCryptoDiffieHellmanResponse.toJSON(message.diffieHellman);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoResponseUnion>, I>>(base?: I): LoginCryptoResponseUnion {
    return LoginCryptoResponseUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoResponseUnion>, I>>(object: I): LoginCryptoResponseUnion {
    const message = createBaseLoginCryptoResponseUnion();
    message.diffieHellman = (object.diffieHellman !== undefined && object.diffieHellman !== null)
      ? LoginCryptoDiffieHellmanResponse.fromPartial(object.diffieHellman)
      : undefined;
    return message;
  },
};

function createBaseLoginCryptoDiffieHellmanResponse(): LoginCryptoDiffieHellmanResponse {
  return { hmac: new Uint8Array(0) };
}

export const LoginCryptoDiffieHellmanResponse = {
  encode(message: LoginCryptoDiffieHellmanResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.hmac.length !== 0) {
      writer.uint32(82).bytes(message.hmac);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoginCryptoDiffieHellmanResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoginCryptoDiffieHellmanResponse();
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

  fromJSON(object: any): LoginCryptoDiffieHellmanResponse {
    return { hmac: isSet(object.hmac) ? bytesFromBase64(object.hmac) : new Uint8Array(0) };
  },

  toJSON(message: LoginCryptoDiffieHellmanResponse): unknown {
    const obj: any = {};
    if (message.hmac.length !== 0) {
      obj.hmac = base64FromBytes(message.hmac);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanResponse>, I>>(
    base?: I,
  ): LoginCryptoDiffieHellmanResponse {
    return LoginCryptoDiffieHellmanResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoginCryptoDiffieHellmanResponse>, I>>(
    object: I,
  ): LoginCryptoDiffieHellmanResponse {
    const message = createBaseLoginCryptoDiffieHellmanResponse();
    message.hmac = object.hmac ?? new Uint8Array(0);
    return message;
  },
};

function createBasePoWResponseUnion(): PoWResponseUnion {
  return { hashCash: undefined };
}

export const PoWResponseUnion = {
  encode(message: PoWResponseUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.hashCash !== undefined) {
      PoWHashCashResponse.encode(message.hashCash, writer.uint32(82).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PoWResponseUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePoWResponseUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.hashCash = PoWHashCashResponse.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PoWResponseUnion {
    return { hashCash: isSet(object.hashCash) ? PoWHashCashResponse.fromJSON(object.hashCash) : undefined };
  },

  toJSON(message: PoWResponseUnion): unknown {
    const obj: any = {};
    if (message.hashCash !== undefined) {
      obj.hashCash = PoWHashCashResponse.toJSON(message.hashCash);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PoWResponseUnion>, I>>(base?: I): PoWResponseUnion {
    return PoWResponseUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PoWResponseUnion>, I>>(object: I): PoWResponseUnion {
    const message = createBasePoWResponseUnion();
    message.hashCash = (object.hashCash !== undefined && object.hashCash !== null)
      ? PoWHashCashResponse.fromPartial(object.hashCash)
      : undefined;
    return message;
  },
};

function createBasePoWHashCashResponse(): PoWHashCashResponse {
  return { hashSuffix: new Uint8Array(0) };
}

export const PoWHashCashResponse = {
  encode(message: PoWHashCashResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.hashSuffix.length !== 0) {
      writer.uint32(82).bytes(message.hashSuffix);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): PoWHashCashResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBasePoWHashCashResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.hashSuffix = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): PoWHashCashResponse {
    return { hashSuffix: isSet(object.hashSuffix) ? bytesFromBase64(object.hashSuffix) : new Uint8Array(0) };
  },

  toJSON(message: PoWHashCashResponse): unknown {
    const obj: any = {};
    if (message.hashSuffix.length !== 0) {
      obj.hashSuffix = base64FromBytes(message.hashSuffix);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<PoWHashCashResponse>, I>>(base?: I): PoWHashCashResponse {
    return PoWHashCashResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<PoWHashCashResponse>, I>>(object: I): PoWHashCashResponse {
    const message = createBasePoWHashCashResponse();
    message.hashSuffix = object.hashSuffix ?? new Uint8Array(0);
    return message;
  },
};

function createBaseCryptoResponseUnion(): CryptoResponseUnion {
  return { shannon: undefined, rc4Sha1Hmac: undefined };
}

export const CryptoResponseUnion = {
  encode(message: CryptoResponseUnion, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.shannon !== undefined) {
      CryptoShannonResponse.encode(message.shannon, writer.uint32(82).fork()).ldelim();
    }
    if (message.rc4Sha1Hmac !== undefined) {
      CryptoRc4Sha1HmacResponse.encode(message.rc4Sha1Hmac, writer.uint32(162).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoResponseUnion {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoResponseUnion();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 10:
          if (tag !== 82) {
            break;
          }

          message.shannon = CryptoShannonResponse.decode(reader, reader.uint32());
          continue;
        case 20:
          if (tag !== 162) {
            break;
          }

          message.rc4Sha1Hmac = CryptoRc4Sha1HmacResponse.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CryptoResponseUnion {
    return {
      shannon: isSet(object.shannon) ? CryptoShannonResponse.fromJSON(object.shannon) : undefined,
      rc4Sha1Hmac: isSet(object.rc4Sha1Hmac) ? CryptoRc4Sha1HmacResponse.fromJSON(object.rc4Sha1Hmac) : undefined,
    };
  },

  toJSON(message: CryptoResponseUnion): unknown {
    const obj: any = {};
    if (message.shannon !== undefined) {
      obj.shannon = CryptoShannonResponse.toJSON(message.shannon);
    }
    if (message.rc4Sha1Hmac !== undefined) {
      obj.rc4Sha1Hmac = CryptoRc4Sha1HmacResponse.toJSON(message.rc4Sha1Hmac);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoResponseUnion>, I>>(base?: I): CryptoResponseUnion {
    return CryptoResponseUnion.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoResponseUnion>, I>>(object: I): CryptoResponseUnion {
    const message = createBaseCryptoResponseUnion();
    message.shannon = (object.shannon !== undefined && object.shannon !== null)
      ? CryptoShannonResponse.fromPartial(object.shannon)
      : undefined;
    message.rc4Sha1Hmac = (object.rc4Sha1Hmac !== undefined && object.rc4Sha1Hmac !== null)
      ? CryptoRc4Sha1HmacResponse.fromPartial(object.rc4Sha1Hmac)
      : undefined;
    return message;
  },
};

function createBaseCryptoShannonResponse(): CryptoShannonResponse {
  return { dummy: 0 };
}

export const CryptoShannonResponse = {
  encode(message: CryptoShannonResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.dummy !== 0) {
      writer.uint32(8).int32(message.dummy);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoShannonResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoShannonResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.dummy = reader.int32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CryptoShannonResponse {
    return { dummy: isSet(object.dummy) ? Number(object.dummy) : 0 };
  },

  toJSON(message: CryptoShannonResponse): unknown {
    const obj: any = {};
    if (message.dummy !== 0) {
      obj.dummy = Math.round(message.dummy);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoShannonResponse>, I>>(base?: I): CryptoShannonResponse {
    return CryptoShannonResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoShannonResponse>, I>>(object: I): CryptoShannonResponse {
    const message = createBaseCryptoShannonResponse();
    message.dummy = object.dummy ?? 0;
    return message;
  },
};

function createBaseCryptoRc4Sha1HmacResponse(): CryptoRc4Sha1HmacResponse {
  return { dummy: 0 };
}

export const CryptoRc4Sha1HmacResponse = {
  encode(message: CryptoRc4Sha1HmacResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.dummy !== 0) {
      writer.uint32(8).int32(message.dummy);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CryptoRc4Sha1HmacResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCryptoRc4Sha1HmacResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.dummy = reader.int32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CryptoRc4Sha1HmacResponse {
    return { dummy: isSet(object.dummy) ? Number(object.dummy) : 0 };
  },

  toJSON(message: CryptoRc4Sha1HmacResponse): unknown {
    const obj: any = {};
    if (message.dummy !== 0) {
      obj.dummy = Math.round(message.dummy);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<CryptoRc4Sha1HmacResponse>, I>>(base?: I): CryptoRc4Sha1HmacResponse {
    return CryptoRc4Sha1HmacResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CryptoRc4Sha1HmacResponse>, I>>(object: I): CryptoRc4Sha1HmacResponse {
    const message = createBaseCryptoRc4Sha1HmacResponse();
    message.dummy = object.dummy ?? 0;
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

function longToNumber(long: Long): number {
  if (long.gt(Number.MAX_SAFE_INTEGER)) {
    throw new tsProtoGlobalThis.Error("Value is larger than Number.MAX_SAFE_INTEGER");
  }
  return long.toNumber();
}

if (_m0.util.Long !== Long) {
  _m0.util.Long = Long as any;
  _m0.configure();
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
