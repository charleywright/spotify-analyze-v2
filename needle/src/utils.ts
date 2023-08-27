export function arrayToHex(arr: Uint8Array): string {
  let str = "";
  for (let i = 0; i < arr.byteLength; i++) {
    str += arr[i].toString(16).padStart(2, "0");
  }
  return str;
}

export function arrayToText(arr: Uint8Array): string {
  let str = "";
  for (let i = 0; i < arr.byteLength; i++) {
    str += String.fromCharCode(arr[i]);
  }
  return str;
}
