/**
 * 内置技能加载
 *
 * 使用 pi 官方 loadSkillsFromDir 扫描 skillsDir 下的 SKILL.md，
 * 返回标准 Skill 对象注入 ResourceLoader。
 */

import { existsSync } from "node:fs";
import { loadSkillsFromDir, type Skill } from "@earendil-works/pi-coding-agent";

export function loadBuiltinSkills(skillsDir: string): Skill[] {
  if (!existsSync(skillsDir)) return [];
  const { skills, diagnostics } = loadSkillsFromDir({
    dir: skillsDir,
    source: "opagent-builtin",
  });
  for (const d of diagnostics) {
    if (d.type === "error" || d.type === "warning") {
      console.warn(`[opagent] 技能加载 ${d.type}: ${d.message}`);
    }
  }
  return skills;
}
