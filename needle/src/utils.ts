export function arrayToHex(arr: ArrayBuffer): string {
  let str = "";
  const uintArr = new Uint8Array(arr);
  for (let i = 0; i < uintArr.byteLength; i++) {
    str += uintArr[i].toString(16).padStart(2, "0");
  }
  return str;
}
