import type { Collector } from "../../types.ts";
import { systemCpu, systemMem, systemDisk, systemNet } from "./system.ts";
import { fileTail, sqlCollector, commandRead } from "./file_sql_cmd.ts";

export const builtinCollectors: Collector[] = [
  systemCpu,
  systemMem,
  systemDisk,
  systemNet,
  fileTail,
  sqlCollector,
  commandRead,
];
