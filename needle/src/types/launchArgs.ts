export type LaunchArgs = {
  serverKey: string;
  shnAddr1: string;
  shnAddr2: string;

  shannonLogInvalidCalls?: boolean;
  shannonLogCallStacks?: boolean;
  shannonDisableSafeCallers?: boolean;
};
