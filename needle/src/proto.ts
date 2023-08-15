function part(start: number, end: number) {
  const arr: number[] = [];
  for (let i = start; i <= end; i++) {
    arr.push(i);
  }
  return arr;
}

/*
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/escape
"The escape() function replaces all characters with escape sequences, with the exception 
of ASCII word characters (A–Z, a–z, 0–9, _) and @\*_+-./"
*/
function escape(bytes: Uint8Array): string {
  const VALID_CODES = [
    ...part(65, 90) /* A-Z */,
    ...part(98, 122) /* a-z */,
    ...part(48, 57) /* 0-9 */,
    64 /* @ */,
    42 /* * */,
    95 /* _ */,
    43 /* + */,
    45 /* - */,
    46 /* . */,
    47 /* / */,
  ];

  let str = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    // str += `\\0${bytes[i].toString(8).padStart(2, "0")}`;
    str += String.fromCharCode(bytes[i]);
    // if (VALID_CODES.includes(bytes[i])) {
    //   str += String.fromCharCode(bytes[i]);
    // } else {
    //   str +=
    //     String.fromCharCode(92) + `0${bytes[i].toString(8).padStart(2, "0")}`;
    // }
  }
  return str;
}

export function protoToJson(obj: any): any {
  const res: any = {};
  const keys = Object.keys(obj);
  for (const key of keys) {
    console.log(`${key}=${typeof obj[key]} ${obj[key] instanceof Uint8Array}`);
    if (obj[key] instanceof Uint8Array) {
      res[key] = escape(obj[key]);
    } else if (typeof obj[key] === "object") {
      res[key] = protoToJson(obj[key]);
    } else {
      res[key] = obj[key];
    }
  }
  return res;
}
