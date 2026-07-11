/**
 * 危险模式规则表
 *
 * PolicyGuard 基于这些正则判断命令 / SQL / 路径的风险等级。
 * 命中即按 risk 等级处理：destructive 默认阻断，write 需确认，read 放行。
 *
 * 注意：正则是保守的——宁可误报要求确认，也不漏放破坏性操作。
 */

export type Risk = "read" | "write" | "destructive";

export interface DangerPattern {
  /** 规则名，用于审计与提示 */
  name: string;
  risk: Risk;
  pattern: RegExp;
}

/**
 * 破坏性命令模式：命中即视为 destructive。
 * 默认（无 --allow-destructive）直接阻断；开启后仍需二次确认 + 审计。
 */
export const DESTRUCTIVE_COMMAND_PATTERNS: DangerPattern[] = [
  { name: "rm_recursive", risk: "destructive", pattern: /\brm\b[^|;&]*(-[a-z]*[rR][a-z]*f?|--recursive)/ },
  { name: "rm_force_root", risk: "destructive", pattern: /\brm\b[^|;&]*-[^|;&]*f\b[^|;&]*\s+\/(\s|$|\*)/ },
  { name: "mkfs", risk: "destructive", pattern: /\bmkfs(\.|\s)/ },
  { name: "dd_to_device", risk: "destructive", pattern: /\bdd\b[^|;&]*\bof\s*=\s*\/dev\// },
  { name: "shred", risk: "destructive", pattern: /\bshred\b/ },
  { name: "redirect_to_device", risk: "destructive", pattern: />\s*\/dev\/(sd|nvme|vd|hd|disk)/ },
  { name: "fork_bomb", risk: "destructive", pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}/ },
  { name: "killall_system", risk: "destructive", pattern: /\bkill(all)?\s+-9?\s+-1\b/ },
  { name: "chmod_system", risk: "destructive", pattern: /\bchmod\s+(-R\s+)?777\s+\/(boot|etc|usr|bin|sbin|root|var)\b/ },
  { name: "iptables_flush", risk: "destructive", pattern: /\biptables\s+(-F|--flush)\b/ },
  { name: "history_purge", risk: "destructive", pattern: /\bhistory\s+-c\b/ },
  { name: "shutdown_halt", risk: "destructive", pattern: /\b(shutdown|halt|poweroff|reboot|init\s+0|init\s+6)\b/ },
  // —— 删除绕过：非 rm 命令的删除路径 ——
  { name: "find_delete", risk: "destructive", pattern: /\bfind\b[^|;&]*-delete\b/ },
  { name: "find_exec_rm", risk: "destructive", pattern: /\bfind\b[^|;&]*-exec\s+([a-z/]*rm|sh|bash)\b/ },
  { name: "xargs_rm", risk: "destructive", pattern: /\bxargs\s+([a-z/]*rm|sh|bash)\b/ },
  // —— 混淆执行：管道/解码/eval 喂给 shell ——
  { name: "pipe_to_shell", risk: "destructive", pattern: /\|\s*(sh|bash|zsh)\b/ },
  { name: "eval_exec", risk: "destructive", pattern: /\beval\s/ },
  { name: "base64_to_shell", risk: "destructive", pattern: /\bbase64\b[^|;&]*\|\s*(sh|bash)\b/ },
  { name: "command_subst_shell", risk: "destructive", pattern: /\$\([^)]*\b(rm|sh|bash)\b/ },
  // —— 解释器删除：python/perl/node/ruby（-c/-e 参数体内任意位置匹配）——
  { name: "python_remove", risk: "destructive", pattern: /\bpython[0-9]?\s+-c\b[\s\S]*?\b(os\.remove|os\.unlink|shutil\.rmtree)\b/i },
  { name: "perl_unlink", risk: "destructive", pattern: /\bperl\s+-e\b[\s\S]*?\bunlink\b/i },
  { name: "node_remove", risk: "destructive", pattern: /\bnode\s+-e\b[\s\S]*?\b(unlinkSync|rmSync|rmdirSync)\b/i },
  { name: "ruby_remove", risk: "destructive", pattern: /\bruby\s+-e\b[\s\S]*?\b(File\.delete|FileUtils\.rm)\b/i },
];

/**
 * 危险 SQL 模式：检测命令中嵌入的 SQL（psql -c / mysql -e / sqlite3）。
 */
export const DESTRUCTIVE_SQL_PATTERNS: DangerPattern[] = [
  { name: "drop", risk: "destructive", pattern: /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i },
  { name: "truncate", risk: "destructive", pattern: /\bTRUNCATE\b/i },
  { name: "delete_without_where", risk: "destructive", pattern: /\bDELETE\s+FROM\b[^;]*(;|$)/i },
  { name: "alter_drop", risk: "destructive", pattern: /\bALTER\s+\w+\s+.*\bDROP\b/i },
  { name: "drop_column", risk: "destructive", pattern: /\bALTER\s+\w+\s+DROP\s+(COLUMN|TABLE)\b/i },
];

/**
 * 写类命令模式：命中即视为 write（需确认；--allow-write 关闭时阻断）。
 */
export const WRITE_COMMAND_PATTERNS: DangerPattern[] = [
  { name: "systemctl_restart_stop", risk: "write", pattern: /\bsystemctl\s+(restart|stop|start|reload|enable|disable)\b/ },
  { name: "service_action", risk: "write", pattern: /\bservice\s+\S+\s+(restart|stop|start|reload)\b/ },
  { name: "kill", risk: "write", pattern: /\bkill(all)?\s+-?\d/ },
  { name: "pkg_install", risk: "write", pattern: /\b(apt|apt-get|yum|dnf|zypper|pacman)\s+(install|remove|purge|erase)\b/ },
  { name: "pip_npm_install", risk: "write", pattern: /\b(pip|pip3|npm|yarn|pnpm|bun)\s+(install|uninstall|remove|add)\b/ },
  { name: "chmod_chown", risk: "write", pattern: /\b(chmod|chown|chgrp)\b/ },
  { name: "mount_umount", risk: "write", pattern: /\b(umount|mount)\b/ },
  { name: "redirect_write", risk: "write", pattern: /(>>?|tee)\s*\S/ },
  { name: "mv_cp_overwrite", risk: "write", pattern: /\b(mv|cp)\b[^|;&]*\s\/?[\w./-]+\s+\/?[\w./-]+\s*$/ },
  { name: "dd_write", risk: "write", pattern: /\bdd\b[^|;&]*\bof\s*=/ },
  { name: "crontab_edit", risk: "write", pattern: /\bcrontab\s+-[er]/ },
];

/**
 * 硬保护区路径：写入/删除一律阻断，即使用 --allow-write / --allow-destructive 也不放行。
 * 这些路径被改写会破坏系统或凭据安全。
 */
export const PROTECTED_PATH_PATTERNS: RegExp[] = [
  /^\/boot(\/|$)/,
  /^\/proc(\/|$)/,
  /^\/sys(\/|$)/,
  /^\/dev(\/|$)/,
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
