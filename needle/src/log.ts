export enum Color {
  BLACK = 30,
  RED = 31,
  GREEN = 32,
  YELLOW = 33,
  BLUE = 34,
  MAGENTA = 35,
  CYAN = 36,
  WHITE = 37,
}
export function color_code(c: Color, bright?: boolean): string {
  return `\x1b[${c};${bright === undefined ? 1 : 0}${
    bright === undefined ? 0 : bright ? 1 : 2
  }m`;
}
export const RST_COL_CODE = "\x1b[m";

function padding(message: string) {
  return new Array(Math.max(128 - message.length, 0)).join(" ");
}

export function status(message: string) {
  console.log(
    `\r${color_code(Color.GREEN, true)}[STATUS] ${message}${padding(
      message
    )}${RST_COL_CODE}`
  );
}

export function info(message: string) {
  console.log(
    `\r${color_code(Color.WHITE, true)}[INFO] ${message}${padding(
      message
    )}${RST_COL_CODE}`
  );
}

export function warn(message: string) {
  console.log(
    `\r${color_code(Color.YELLOW, true)}[WARN] ${message}${padding(
      message
    )}${RST_COL_CODE}`
  );
}

export function error(message: string) {
  console.error(
    `\r${color_code(Color.RED, true)}[ERROR] ${message}${padding(
      message
    )}${RST_COL_CODE}`
  );
}
