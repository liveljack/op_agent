/**
 * 危险模式规则表
 *
 * PolicyGuard 基于这些正则判断命令 / SQL / 路径的风险等级。
 * 命中即按 risk 等级处理：destructive 默认阻断，write 需确认，read 放行。
 *
 * 写类规则细分（kind 字段）：
 * - "file"    ：文件写，目标路径可提取，由 PolicyGuard 按 scratch(/tmp)/dev-null 分区判定
 * - "system"  ：系统状态变更（服务/进程/包管理/挂载/数据源等），永不享受 scratch 豁免；
 *               缺省值即 system（保守：新增规则不标 kind 时按最严处理）
 *
 * 注意：正则是保守的——宁可误报要求确认，也不漏放破坏性操作。
 */

export type Risk = 'read' | 'write' | 'destructive';

/** 写类规则细分 */
export type WriteKind = 'file' | 'system';

export interface DangerPattern {
  /** 规则名，用于审计与提示 */
  name: string;
  risk: Risk;
  pattern: RegExp;
  /** file=文件写（目标可提取做 scratch 判定）；缺省 system=命中即走 allowWrite 逻辑 */
  kind?: WriteKind;
}

/** 输出丢弃设备：写它等价于不产生任何状态变化 */
export const NULL_DEVICE = '/dev/null';

/**
 * 破坏性命令模式：命中即视为 destructive。
 * 默认（无 --allow-destructive）直接阻断；开启后仍需二次确认 + 审计。
 */
export const DESTRUCTIVE_COMMAND_PATTERNS: DangerPattern[] = [
  {
    name: 'rm_recursive',
    risk: 'destructive',
    pattern: /\brm\b[^|;&]*(-[a-z]*[rR][a-z]*f?|--recursive)/,
  },
  {
    name: 'rm_force_root',
    risk: 'destructive',
    pattern: /\brm\b[^|;&]*-[^|;&]*f\b[^|;&]*\s+\/(\s|$|\*)/,
  },
  { name: 'mkfs', risk: 'destructive', pattern: /\bmkfs(\.|\s)/ },
  // of=/dev/null 是丢弃语义，排除之（of= 其他 /dev/ 设备仍拦）
  {
    name: 'dd_to_device',
    risk: 'destructive',
    pattern: /\bdd\b[^|;&]*\bof\s*=\s*\/dev\/(?!null\b)/,
  },
  { name: 'shred', risk: 'destructive', pattern: /\bshred\b/ },
  { name: 'redirect_to_device', risk: 'destructive', pattern: />\s*\/dev\/(sd|nvme|vd|hd|disk)/ },
  { name: 'fork_bomb', risk: 'destructive', pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}/ },
  { name: 'killall_system', risk: 'destructive', pattern: /\bkill(all)?\s+-9?\s+-1\b/ },
  {
    name: 'chmod_system',
    risk: 'destructive',
    pattern: /\bchmod\s+(-R\s+)?777\s+\/(boot|etc|usr|bin|sbin|root|var)\b/,
  },
  { name: 'iptables_flush', risk: 'destructive', pattern: /\biptables\s+(-F|--flush)\b/ },
  { name: 'history_purge', risk: 'destructive', pattern: /\bhistory\s+-c\b/ },
  {
    name: 'shutdown_halt',
    risk: 'destructive',
    pattern: /\b(shutdown|halt|poweroff|reboot|init\s+0|init\s+6)\b/,
  },
  // —— 删除绕过：非 rm 命令的删除路径 ——
  { name: 'find_delete', risk: 'destructive', pattern: /\bfind\b[^|;&]*-delete\b/ },
  {
    name: 'find_exec_rm',
    risk: 'destructive',
    pattern: /\bfind\b[^|;&]*-exec\s+([a-z/]*rm|sh|bash)\b/,
  },
  { name: 'xargs_rm', risk: 'destructive', pattern: /\bxargs\s+([a-z/]*rm|sh|bash)\b/ },
  // —— 混淆执行：管道/解码/eval 喂给 shell ——
  { name: 'pipe_to_shell', risk: 'destructive', pattern: /\|\s*(sh|bash|zsh)\b/ },
  // (?<!-) 排除 --eval 等标志参数误报（mongosh/node --eval 是惯用法）
  { name: 'eval_exec', risk: 'destructive', pattern: /(?<!-)\beval\s/ },
  { name: 'base64_to_shell', risk: 'destructive', pattern: /\bbase64\b[^|;&]*\|\s*(sh|bash)\b/ },
  { name: 'command_subst_shell', risk: 'destructive', pattern: /\$\([^)]*\b(rm|sh|bash)\b/ },
  // —— 解释器删除：python/perl/node/ruby（-c/-e 参数体内任意位置匹配）——
  {
    name: 'python_remove',
    risk: 'destructive',
    pattern: /\bpython[0-9]?\s+-c\b[\s\S]*?\b(os\.remove|os\.unlink|shutil\.rmtree)\b/i,
  },
  { name: 'perl_unlink', risk: 'destructive', pattern: /\bperl\s+-e\b[\s\S]*?\bunlink\b/i },
  {
    name: 'node_remove',
    risk: 'destructive',
    pattern: /\bnode\s+-e\b[\s\S]*?\b(unlinkSync|rmSync|rmdirSync)\b/i,
  },
  {
    name: 'ruby_remove',
    risk: 'destructive',
    pattern: /\bruby\s+-e\b[\s\S]*?\b(File\.delete|FileUtils\.rm)\b/i,
  },
];

/**
 * 危险 SQL 模式：检测命令中嵌入的 SQL（psql -c / mysql -e / sqlite3）。
 */
export const DESTRUCTIVE_SQL_PATTERNS: DangerPattern[] = [
  { name: 'drop', risk: 'destructive', pattern: /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i },
  { name: 'truncate', risk: 'destructive', pattern: /\bTRUNCATE\b/i },
  { name: 'delete_without_where', risk: 'destructive', pattern: /\bDELETE\s+FROM\b[^;]*(;|$)/i },
  { name: 'alter_drop', risk: 'destructive', pattern: /\bALTER\s+\w+\s+.*\bDROP\b/i },
  { name: 'drop_column', risk: 'destructive', pattern: /\bALTER\s+\w+\s+DROP\s+(COLUMN|TABLE)\b/i },
];

/**
 * 写类 SQL 模式：对数据源写入/修改数据（INSERT/UPDATE/CREATE/ALTER 等）。
 * 只读模式一律阻断（--allow-write 时需确认）；SELECT 等读不受影响。
 */
export const WRITE_SQL_PATTERNS: DangerPattern[] = [
  { name: 'insert', risk: 'write', pattern: /\bINSERT\s+(INTO|OVERWRITE)\b/i },
  { name: 'update_set', risk: 'write', pattern: /\bUPDATE\s+[\w."`]+\s+SET\b/i },
  // SHOW CREATE TABLE/VIEW 是只读元数据查询：CREATE 前紧邻 SHOW 时不算写
  {
    name: 'create_obj',
    risk: 'write',
    pattern:
      /(?<!\bSHOW\s)\bCREATE\s+(OR\s+REPLACE\s+)?(TABLE|INDEX|VIEW|MATERIALIZED|DATABASE|SCHEMA|TRIGGER|FUNCTION|PROCEDURE|USER|ROLE|EXTENSION|TYPE|SEQUENCE)\b/i,
  },
  {
    name: 'alter_obj',
    risk: 'write',
    pattern: /\bALTER\s+(TABLE|INDEX|VIEW|SEQUENCE|USER|ROLE|DATABASE|SCHEMA)\b/i,
  },
  { name: 'replace_into', risk: 'write', pattern: /\bREPLACE\s+INTO\b/i },
  { name: 'merge_into', risk: 'write', pattern: /\bMERGE\s+INTO\b/i },
  { name: 'grant_revoke', risk: 'write', pattern: /\b(GRANT|REVOKE)\b/i },
  { name: 'load_data', risk: 'write', pattern: /\bLOAD\s+DATA\b/i },
  { name: 'copy_from', risk: 'write', pattern: /\bCOPY\s+[\w."]+\s+FROM\b/i },
  { name: 'select_into', risk: 'write', pattern: /\bSELECT\b[^;]*\bINTO\b/i },
];

/**
 * NoSQL 数据源写命令：redis-cli / mongosh 的写操作。
 * 只读模式一律阻断；读命令（GET/KEYS/SCAN/find）不受影响。
 */
export const DATA_SOURCE_WRITE_PATTERNS: DangerPattern[] = [
  {
    name: 'redis_write',
    risk: 'write',
    // 排除只读参数中的写动词误报：--scan --pattern "SET*"、KEYS "SET*"、SCAN MATCH SET* 等。
    // tempered dot：写动词前不允许出现 --scan/--pattern/--key(s)/KEYS/SCAN…MATCH 参数段。
    pattern:
      /\bredis-cli\b(?:(?!\s(?:--?(?:scan|pattern|key|keys)\b|KEYS\b|SCAN\b[^|;&]*?\bMATCH\b))[\s\S])*?\b(FLUSHALL|FLUSHDB|SETNX|MSET|SET|DEL|UNLINK|HSET|HMSET|HDEL|LPUSH|RPUSH|LSET|LPOP|RPOP|SADD|SPOP|SREM|ZADD|ZREM|RENAME|COPY|MOVE|EXPIRE|PERSIST|APPEND|INCR|DECR|GETDEL|GETSET|CONFIG\s+SET)\b/i,
  },
  {
    name: 'mongo_write',
    risk: 'write',
    // 前缀匹配 mongo / mongosh 两种客户端（mongod 守护进程不含 \b 边界，不误伤）
    pattern:
      /\bmongo(?:sh)?\b[\s\S]*?\b(insertOne|insertMany|updateOne|updateMany|replaceOne|deleteOne|deleteMany|findAndModify|findOneAndUpdate|findOneAndDelete|findOneAndReplace|bulkWrite|dropDatabase|dropIndexes|createCollection|renameCollection|createIndex|mapReduce|drop|remove)\b/i,
  },
];

/**
 * 写类命令模式：命中即视为 write（需确认；--allow-write 关闭时阻断）。
 * kind="file" 的规则由 PolicyGuard 提取写目标做 scratch(/tmp)/dev-null 分区；
 * 其余（system 类）命中即走 allowWrite 逻辑，永不享受 scratch 豁免。
 */
export const WRITE_COMMAND_PATTERNS: DangerPattern[] = [
  // —— 系统状态变更（system 类）——
  {
    name: 'systemctl_restart_stop',
    risk: 'write',
    pattern: /\bsystemctl\s+(restart|stop|start|reload|enable|disable)\b/,
  },
  {
    name: 'service_action',
    risk: 'write',
    pattern: /\bservice\s+\S+\s+(restart|stop|start|reload)\b/,
  },
  { name: 'kill', risk: 'write', pattern: /\bkill(all)?\s+-?\d/ },
  {
    name: 'pkg_install',
    risk: 'write',
    pattern:
      /\b(apt|apt-get|yum|dnf|zypper|pacman|apk|snap|brew)\s+(install|remove|purge|erase|add|del|uninstall)\b/,
  },
  {
    name: 'pip_npm_install',
    risk: 'write',
    pattern: /\b(pip|pip3|npm|yarn|pnpm|bun|gem|cargo|go)\s+(install|uninstall|remove|add)\b/,
  },
  { name: 'mount_umount', risk: 'write', pattern: /\b(umount|mount)\b/ },
  // crontab 任何非 -l 用法都可能改 crontab（-e 编辑、<file> 安装）
  { name: 'crontab_edit', risk: 'write', pattern: /\bcrontab\b(?!\s+-l\b)/ },
  // —— 文件写（file 类：目标可提取，按 scratch 分区判定）——
  { name: 'redirect_write', risk: 'write', kind: 'file', pattern: /(>>?|tee)\s*\S/ },
  { name: 'dd_write', risk: 'write', kind: 'file', pattern: /\bdd\b[^|;&]*\bof\s*=/ },
  { name: 'mv_cp_overwrite', risk: 'write', kind: 'file', pattern: /\b(mv|cp|install)\b/ },
  {
    name: 'ln_symlink',
    risk: 'write',
    kind: 'file',
    pattern: /\bln\b[^|;&]*(-[a-zA-Z]*s|--symbolic)/,
  },
  { name: 'touch_file', risk: 'write', kind: 'file', pattern: /\btouch\b/ },
  { name: 'mkdir_dir', risk: 'write', kind: 'file', pattern: /\bmkdir\b/ },
  { name: 'sed_inplace', risk: 'write', kind: 'file', pattern: /\bsed\b[^|;&]*\s(-i|--in-place)/ },
  { name: 'rsync_write', risk: 'write', kind: 'file', pattern: /\brsync\b/ },
  { name: 'truncate_file', risk: 'write', kind: 'file', pattern: /\btruncate\b/ },
  // 非递归 rm（递归/强制根删除已被 destructive 层先拦）
  { name: 'rm_single', risk: 'write', kind: 'file', pattern: /\brm\b/ },
  // chmod/chown 目标在 scratch 内可用（chmod +x /tmp/x.sh 工作流必需）
  { name: 'chmod_chown', risk: 'write', kind: 'file', pattern: /\b(chmod|chown|chgrp)\b/ },
  // —— 解释器写文件（file 类：提取引号内路径字面量；变量路径无可提取目标 → 保守阻断）——
  {
    name: 'python_open_write',
    risk: 'write',
    kind: 'file',
    pattern: /\bopen\s*\(\s*[^,()]*,\s*['"][awx+]/,
  },
  {
    name: 'node_write_file',
    risk: 'write',
    kind: 'file',
    pattern: /\b((write|append)FileSync|fs\.writeFile\w*)\s*\(/,
  },
  {
    name: 'ruby_file_write',
    risk: 'write',
    kind: 'file',
    pattern: /\bFile\.(write|binwrite)\s*\(|\bFile\.open\s*\([^)]*['"][aw]/,
  },
];

/**
 * 硬保护区路径：写入/删除一律阻断，即使用 --allow-write / --allow-destructive 也不放行。
 * 这些路径被改写会破坏系统或凭据安全。
 * 注意 /dev/null 被排除（输出丢弃语义，无状态变化）。
 */
export const PROTECTED_PATH_PATTERNS: RegExp[] = [
  /^\/boot(\/|$)/,
  /^\/proc(\/|$)/,
  /^\/sys(\/|$)/,
  /^\/dev(?!\/null$)(\/|$)/,
  /^\/etc\/(shadow|passwd|group|sudoers|gshadow)(\b|$)/,
  /^\/etc\/ssh\//,
  /^\/root\/\.ssh\//,
  /^\/var\/lib\/(dpkg|rpm)\//,
];

/**
 * 用户敏感文件：硬保护（覆盖 ~/.ssh、shell 配置等）。
 * 运行时按 home 目录展开。
 */
export const PROTECTED_HOME_RELATIVE: RegExp[] = [
  /\.ssh(\/|$)/,
  /\.bashrc$/,
  /\.bash_profile$/,
  /\.profile$/,
  /\.bash_history$/,
  /\.zshrc$/,
  /\.config\/(keychain|gnupg)(\/|$)/,
];
