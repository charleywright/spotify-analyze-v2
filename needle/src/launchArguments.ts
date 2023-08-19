export default class LaunchArguments {
  static serverKey: string = "0";
  static shnAddr1: string = "0";
  static shnAddr2: string = "0";

  static shannonLogInvalidCalls = false;
  static shannonLogCallStacks = false;
  static shannonDisableSafeCallers = false;
  static shannonDisableParsing = false;

  static init(launchArgs: any) {
    Object.assign(this, launchArgs);
  }

  static relocate(moduleBase: NativePointer) {
    this.serverKey = moduleBase.add(ptr(this.serverKey)).toString();
    this.shnAddr1 = moduleBase.add(ptr(this.shnAddr1)).toString();
    this.shnAddr2 = moduleBase.add(ptr(this.shnAddr2)).toString();
  }
}
