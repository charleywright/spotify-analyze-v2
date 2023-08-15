/* eslint-disable */
import _m0 from "protobufjs/minimal";

export const protobufPackage = "spotify.mercury";

export interface MercuryMultiGetRequest {
  request: MercuryRequest[];
}

export interface MercuryMultiGetReply {
  reply: MercuryReply[];
}

export interface MercuryRequest {
  uri: string;
  contentType: string;
  body: Uint8Array;
  etag: Uint8Array;
}

export interface MercuryReply {
  statusCode: number;
  statusMessage: string;
  cachePolicy: MercuryReply_CachePolicy;
  ttl: number;
  etag: Uint8Array;
  contentType: string;
  body: Uint8Array;
}

export enum MercuryReply_CachePolicy {
  CACHE_NO = 1,
  CACHE_PRIVATE = 2,
  CACHE_PUBLIC = 3,
  UNRECOGNIZED = -1,
}

export function mercuryReply_CachePolicyFromJSON(object: any): MercuryReply_CachePolicy {
  switch (object) {
    case 1:
    case "CACHE_NO":
      return MercuryReply_CachePolicy.CACHE_NO;
    case 2:
    case "CACHE_PRIVATE":
      return MercuryReply_CachePolicy.CACHE_PRIVATE;
    case 3:
    case "CACHE_PUBLIC":
      return MercuryReply_CachePolicy.CACHE_PUBLIC;
    case -1:
    case "UNRECOGNIZED":
    default:
      return MercuryReply_CachePolicy.UNRECOGNIZED;
  }
}

export function mercuryReply_CachePolicyToJSON(object: MercuryReply_CachePolicy): string {
  switch (object) {
    case MercuryReply_CachePolicy.CACHE_NO:
      return "CACHE_NO";
    case MercuryReply_CachePolicy.CACHE_PRIVATE:
      return "CACHE_PRIVATE";
    case MercuryReply_CachePolicy.CACHE_PUBLIC:
      return "CACHE_PUBLIC";
    case MercuryReply_CachePolicy.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface Header {
  uri: string;
  contentType: string;
  method: string;
  statusCode: number;
  userFields: UserField[];
}

export interface UserField {
  key: string;
  value: Uint8Array;
}

function createBaseMercuryMultiGetRequest(): MercuryMultiGetRequest {
  return { request: [] };
}

export const MercuryMultiGetRequest = {
  encode(message: MercuryMultiGetRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.request) {
      MercuryRequest.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): MercuryMultiGetRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMercuryMultiGetRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.request.push(MercuryRequest.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): MercuryMultiGetRequest {
    return {
      request: Array.isArray(object?.request) ? object.request.map((e: any) => MercuryRequest.fromJSON(e)) : [],
    };
  },

  toJSON(message: MercuryMultiGetRequest): unknown {
    const obj: any = {};
    if (message.request?.length) {
      obj.request = message.request.map((e) => MercuryRequest.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<MercuryMultiGetRequest>, I>>(base?: I): MercuryMultiGetRequest {
    return MercuryMultiGetRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<MercuryMultiGetRequest>, I>>(object: I): MercuryMultiGetRequest {
    const message = createBaseMercuryMultiGetRequest();
    message.request = object.request?.map((e) => MercuryRequest.fromPartial(e)) || [];
    return message;
  },
};

function createBaseMercuryMultiGetReply(): MercuryMultiGetReply {
  return { reply: [] };
}

export const MercuryMultiGetReply = {
  encode(message: MercuryMultiGetReply, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.reply) {
      MercuryReply.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): MercuryMultiGetReply {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMercuryMultiGetReply();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.reply.push(MercuryReply.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): MercuryMultiGetReply {
    return { reply: Array.isArray(object?.reply) ? object.reply.map((e: any) => MercuryReply.fromJSON(e)) : [] };
  },

  toJSON(message: MercuryMultiGetReply): unknown {
    const obj: any = {};
    if (message.reply?.length) {
      obj.reply = message.reply.map((e) => MercuryReply.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<MercuryMultiGetReply>, I>>(base?: I): MercuryMultiGetReply {
    return MercuryMultiGetReply.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<MercuryMultiGetReply>, I>>(object: I): MercuryMultiGetReply {
    const message = createBaseMercuryMultiGetReply();
    message.reply = object.reply?.map((e) => MercuryReply.fromPartial(e)) || [];
    return message;
  },
};

function createBaseMercuryRequest(): MercuryRequest {
  return { uri: "", contentType: "", body: new Uint8Array(0), etag: new Uint8Array(0) };
}

export const MercuryRequest = {
  encode(message: MercuryRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.uri !== "") {
      writer.uint32(10).string(message.uri);
    }
    if (message.contentType !== "") {
      writer.uint32(18).string(message.contentType);
    }
    if (message.body.length !== 0) {
      writer.uint32(26).bytes(message.body);
    }
    if (message.etag.length !== 0) {
      writer.uint32(34).bytes(message.etag);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): MercuryRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMercuryRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.uri = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.contentType = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.body = reader.bytes();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.etag = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): MercuryRequest {
    return {
      uri: isSet(object.uri) ? String(object.uri) : "",
      contentType: isSet(object.contentType) ? String(object.contentType) : "",
      body: isSet(object.body) ? bytesFromBase64(object.body) : new Uint8Array(0),
      etag: isSet(object.etag) ? bytesFromBase64(object.etag) : new Uint8Array(0),
    };
  },

  toJSON(message: MercuryRequest): unknown {
    const obj: any = {};
    if (message.uri !== "") {
      obj.uri = message.uri;
    }
    if (message.contentType !== "") {
      obj.contentType = message.contentType;
    }
    if (message.body.length !== 0) {
      obj.body = base64FromBytes(message.body);
    }
    if (message.etag.length !== 0) {
      obj.etag = base64FromBytes(message.etag);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<MercuryRequest>, I>>(base?: I): MercuryRequest {
    return MercuryRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<MercuryRequest>, I>>(object: I): MercuryRequest {
    const message = createBaseMercuryRequest();
    message.uri = object.uri ?? "";
    message.contentType = object.contentType ?? "";
    message.body = object.body ?? new Uint8Array(0);
    message.etag = object.etag ?? new Uint8Array(0);
    return message;
  },
};

function createBaseMercuryReply(): MercuryReply {
  return {
    statusCode: 0,
    statusMessage: "",
    cachePolicy: 1,
    ttl: 0,
    etag: new Uint8Array(0),
    contentType: "",
    body: new Uint8Array(0),
  };
}

export const MercuryReply = {
  encode(message: MercuryReply, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.statusCode !== 0) {
      writer.uint32(8).sint32(message.statusCode);
    }
    if (message.statusMessage !== "") {
      writer.uint32(18).string(message.statusMessage);
    }
    if (message.cachePolicy !== 1) {
      writer.uint32(24).int32(message.cachePolicy);
    }
    if (message.ttl !== 0) {
      writer.uint32(32).sint32(message.ttl);
    }
    if (message.etag.length !== 0) {
      writer.uint32(42).bytes(message.etag);
    }
    if (message.contentType !== "") {
      writer.uint32(50).string(message.contentType);
    }
    if (message.body.length !== 0) {
      writer.uint32(58).bytes(message.body);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): MercuryReply {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMercuryReply();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.statusCode = reader.sint32();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.statusMessage = reader.string();
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.cachePolicy = reader.int32() as any;
          continue;
        case 4:
          if (tag !== 32) {
            break;
          }

          message.ttl = reader.sint32();
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.etag = reader.bytes();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.contentType = reader.string();
          continue;
        case 7:
          if (tag !== 58) {
            break;
          }

          message.body = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): MercuryReply {
    return {
      statusCode: isSet(object.statusCode) ? Number(object.statusCode) : 0,
      statusMessage: isSet(object.statusMessage) ? String(object.statusMessage) : "",
      cachePolicy: isSet(object.cachePolicy) ? mercuryReply_CachePolicyFromJSON(object.cachePolicy) : 1,
      ttl: isSet(object.ttl) ? Number(object.ttl) : 0,
      etag: isSet(object.etag) ? bytesFromBase64(object.etag) : new Uint8Array(0),
      contentType: isSet(object.contentType) ? String(object.contentType) : "",
      body: isSet(object.body) ? bytesFromBase64(object.body) : new Uint8Array(0),
    };
  },

  toJSON(message: MercuryReply): unknown {
    const obj: any = {};
    if (message.statusCode !== 0) {
      obj.statusCode = Math.round(message.statusCode);
    }
    if (message.statusMessage !== "") {
      obj.statusMessage = message.statusMessage;
    }
    if (message.cachePolicy !== 1) {
      obj.cachePolicy = mercuryReply_CachePolicyToJSON(message.cachePolicy);
    }
    if (message.ttl !== 0) {
      obj.ttl = Math.round(message.ttl);
    }
    if (message.etag.length !== 0) {
      obj.etag = base64FromBytes(message.etag);
    }
    if (message.contentType !== "") {
      obj.contentType = message.contentType;
    }
    if (message.body.length !== 0) {
      obj.body = base64FromBytes(message.body);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<MercuryReply>, I>>(base?: I): MercuryReply {
    return MercuryReply.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<MercuryReply>, I>>(object: I): MercuryReply {
    const message = createBaseMercuryReply();
    message.statusCode = object.statusCode ?? 0;
    message.statusMessage = object.statusMessage ?? "";
    message.cachePolicy = object.cachePolicy ?? 1;
    message.ttl = object.ttl ?? 0;
    message.etag = object.etag ?? new Uint8Array(0);
    message.contentType = object.contentType ?? "";
    message.body = object.body ?? new Uint8Array(0);
    return message;
  },
};

function createBaseHeader(): Header {
  return { uri: "", contentType: "", method: "", statusCode: 0, userFields: [] };
}

export const Header = {
  encode(message: Header, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.uri !== "") {
      writer.uint32(10).string(message.uri);
    }
    if (message.contentType !== "") {
      writer.uint32(18).string(message.contentType);
    }
    if (message.method !== "") {
      writer.uint32(26).string(message.method);
    }
    if (message.statusCode !== 0) {
      writer.uint32(32).sint32(message.statusCode);
    }
    for (const v of message.userFields) {
      UserField.encode(v!, writer.uint32(50).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): Header {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseHeader();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.uri = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.contentType = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.method = reader.string();
          continue;
        case 4:
          if (tag !== 32) {
            break;
          }

          message.statusCode = reader.sint32();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.userFields.push(UserField.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): Header {
    return {
      uri: isSet(object.uri) ? String(object.uri) : "",
      contentType: isSet(object.contentType) ? String(object.contentType) : "",
      method: isSet(object.method) ? String(object.method) : "",
      statusCode: isSet(object.statusCode) ? Number(object.statusCode) : 0,
      userFields: Array.isArray(object?.userFields) ? object.userFields.map((e: any) => UserField.fromJSON(e)) : [],
    };
  },

  toJSON(message: Header): unknown {
    const obj: any = {};
    if (message.uri !== "") {
      obj.uri = message.uri;
    }
    if (message.contentType !== "") {
      obj.contentType = message.contentType;
    }
    if (message.method !== "") {
      obj.method = message.method;
    }
    if (message.statusCode !== 0) {
      obj.statusCode = Math.round(message.statusCode);
    }
    if (message.userFields?.length) {
      obj.userFields = message.userFields.map((e) => UserField.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<Header>, I>>(base?: I): Header {
    return Header.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<Header>, I>>(object: I): Header {
    const message = createBaseHeader();
    message.uri = object.uri ?? "";
    message.contentType = object.contentType ?? "";
    message.method = object.method ?? "";
    message.statusCode = object.statusCode ?? 0;
    message.userFields = object.userFields?.map((e) => UserField.fromPartial(e)) || [];
    return message;
  },
};

function createBaseUserField(): UserField {
  return { key: "", value: new Uint8Array(0) };
}

export const UserField = {
  encode(message: UserField, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.key !== "") {
      writer.uint32(10).string(message.key);
    }
    if (message.value.length !== 0) {
      writer.uint32(18).bytes(message.value);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): UserField {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUserField();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.key = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.value = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): UserField {
    return {
      key: isSet(object.key) ? String(object.key) : "",
      value: isSet(object.value) ? bytesFromBase64(object.value) : new Uint8Array(0),
    };
  },

  toJSON(message: UserField): unknown {
    const obj: any = {};
    if (message.key !== "") {
      obj.key = message.key;
    }
    if (message.value.length !== 0) {
      obj.value = base64FromBytes(message.value);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<UserField>, I>>(base?: I): UserField {
    return UserField.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<UserField>, I>>(object: I): UserField {
    const message = createBaseUserField();
    message.key = object.key ?? "";
    message.value = object.value ?? new Uint8Array(0);
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
