#!/usr/bin/env bash
#
# install_opagent.sh —— 在 Ubuntu / Debian 上一键安装并配置 op-agent
#
# 用法:
#   sudo bash install_opagent.sh                 # 推荐: 以 root 执行(会写 apt 源与全局 npm 包)
#   bash install_opagent.sh                      # 非 root 时, 系统命令自动加 sudo
#   sudo bash install_opagent.sh --update        # 仅把 op-agent 更新到最新版(不动 node/bun/配置)
#
# 可选环境变量覆盖(不改脚本即可替换参数):
#   DEEPSEEK_API_KEY=sk-xxxx bash install_opagent.sh
#
# 关于包名(踩坑记录):
#   包发布在 npm 官方源上, 名字是 @xianzongwendao/op-agent(带作用域)。
#   写成 "xianzongwendao/op-agent"(缺 @) 会被 npm 当成 GitHub 简写, 改用 SSH 拉取
#   (git+ssh://git@github.com/...) 并在无 SSH key 时报 "Permission denied (publickey)"。
#   修复: 脚本会在 main() 开头自动把 owner/repo 改写成 @owner/repo, 并打 WARN 日志。
#   若要装 Git 版本, 必须显式用 HTTPS: npm i -g git+https://github.com/liveljack/op_agent.git
#   包提供的可执行命令名是 opagent(不是 op-agent)。
#   NODE_SETUP_URL=... NODE_MAJOR=22 OP_AGENT_PKG=@xianzongwendao/op-agent bash install_opagent.sh
#
# 等价于手工执行的命令:
#   curl -fsSL https://mirrors.ustc.edu.cn/nodesource/deb/setup_22.x | sudo -E bash -
#   apt-get install -y nodejs
#   npm install -g bun
#   npm install -g @xianzongwendao/op-agent      # 注意: 必须带 @xianzongwendao/ 作用域
#   npm install -g @xianzongwendao/op-agent@latest   # --update 的等价命令(仅升级包)
#   mkdir -p ~/.op_agent
#   echo 'DEEPSEEK_API_KEY=sk-xxxx' > ~/.op_agent/.env
#   chmod 600 ~/.op_agent/.env
#
set -euo pipefail

# ==================================================================
# 可配置项
# ==================================================================
NODE_SETUP_URL="${NODE_SETUP_URL:-https://mirrors.ustc.edu.cn/nodesource/deb/setup_22.x}"
NODE_MAJOR="${NODE_MAJOR:-22}"
OP_AGENT_PKG="${OP_AGENT_PKG:-@xianzongwendao/op-agent}"
OP_AGENT_CMD="${OP_AGENT_CMD:-opagent}"
# npm 源不可用时的备用源(必须显式 HTTPS; 写 owner/repo 简写会走 SSH 认证失败)
OP_AGENT_FALLBACK_GIT="${OP_AGENT_FALLBACK_GIT:-git+https://github.com/liveljack/op_agent.git}"
# ==================================================================
# DeepSeek 密钥来源(优先级): 环境变量 > 脚本同目录 .opagent_secret 文件 > 下方内置值
#   1) DEEPSEEK_API_KEY=sk-xxx bash install_opagent.sh
#   2) echo 'DEEPSEEK_API_KEY=sk-xxx' > .opagent_secret   (与脚本同目录, 建议加入 .gitignore)
#   3) 内置默认值
# ⚠ 本脚本内置的是明文密钥: 若所在目录是 git 仓库, 提交前务必把"本文件或密钥"
#   加入 .gitignore, 否则密钥会进入版本库历史(泄漏后需立即到平台吊销重签)。
# ==================================================================
OP_AGENT_SECRET_FILE="${OP_AGENT_SECRET_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.opagent_secret}"
if [ -z "${DEEPSEEK_API_KEY:-}" ] && [ -f "$OP_AGENT_SECRET_FILE" ]; then
    DEEPSEEK_API_KEY="$(grep -m1 '^DEEPSEEK_API_KEY=' "$OP_AGENT_SECRET_FILE" 2>/dev/null | cut -d= -f2- || true)"
    [ -n "${DEEPSEEK_API_KEY:-}" ] && echo "已从 ${OP_AGENT_SECRET_FILE} 读取 DEEPSEEK_API_KEY" >&2
fi
DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-sk-fd57dc6d85f446cf99165ca422b9c31e}"

# ==================================================================
# 日志 / 工具函数
# ==================================================================
log() {
    local message="$1"
    local type="${2:-info}"
    local timestamp color endcolor="\033[0m"
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    case "$type" in
        info)    color="\033[38;5;79m" ;;
        success) color="\033[1;32m" ;;
        warn)    color="\033[1;33m" ;;
        error)   color="\033[1;31m" ;;
        *)       color="\033[1;34m" ;;
    esac
    echo -e "${color}${timestamp} - ${message}${endcolor}"
}

die() {
    log "$1" "error"
    exit "${2:-1}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ==================================================================
# 包名 / URL 规范化(防止把 owner/repo 简写当 GitHub SSH 拉取)
# ------------------------------------------------------------------
# npm 解析规则: 不带 "/" 是普通包名; 带 "/" 但不带 "@" 前缀的,
#   一律按 GitHub 简写处理 → git+ssh://git@github.com/<owner>/<repo>.git
#   没有 SSH key 时就会报 "Permission denied (publickey)"。
# 本函数: 把 "owner/repo" 自动补成 "@owner/repo", 已带 @ 的保持原样;
#         若是 git+ssh:// / git@ 形式, 强制改写为 git+https://。
# ==================================================================
normalize_npm_pkg_name() {
    local pkg="$1"
    # 已经是 scoped 包(@xxx/yyy) 或没有斜杠 → 原样返回
    if [[ "$pkg" == @*/* ]] || [[ "$pkg" != */* ]]; then
        printf '%s' "$pkg"
        return 0
    fi
    # 带斜杠但不是 scoped → 视为 GitHub 简写, 自动补 @
    local fixed="@${pkg}"
    log "包名 '${pkg}' 缺 @ 作用域, npm 会当 GitHub 简写改用 SSH 拉取(无 SSH key 会失败)." "warn"
    log "已自动改写为 '${fixed}', 该写法会从 npm 官方源下载." "warn"
    printf '%s' "$fixed"
}

normalize_git_url() {
    local url="$1"
    # git+ssh://  →  git+https://
    if [[ "$url" == git+ssh://* ]]; then
        local fixed="${url#git+ssh://}"
        # ssh://git@github.com/owner/repo.git → git+https://github.com/owner/repo.git
        fixed="git+https://${fixed#git@}"
        log "备用 Git 源从 SSH 改写为 HTTPS: ${fixed}" "warn"
        printf '%s' "$fixed"
        return 0
    fi
    # git@github.com:owner/repo.git  →  git+https://github.com/owner/repo.git
    if [[ "$url" == git@*:* ]]; then
        local rest host_path path_part fixed
        rest="${url#git@}"               # github.com:owner/repo.git
        host_path="${rest%%:*}"          # github.com
        path_part="${rest#*:}"           # owner/repo.git
        fixed="git+https://${host_path}/${path_part}"
        log "备用 Git 源从 SSH 改写为 HTTPS: ${fixed}" "warn"
        printf '%s' "$fixed"
        return 0
    fi
    # ssh://user@host/...  →  https://host/...
    if [[ "$url" == ssh://* ]]; then
        local fixed
        fixed="https://${url#ssh://}"
        # 去掉 user@ 部分(若存在)
        fixed="https://${fixed#*@}"
        log "备用 Git 源从 SSH 改写为 HTTPS: ${fixed}" "warn"
        printf '%s' "$fixed"
        return 0
    fi
    printf '%s' "$url"
}

# 非 root 时给系统级命令加 sudo
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    command_exists sudo || die "非 root 用户且未安装 sudo, 请以 root 身份运行本脚本"
    SUDO="sudo"
fi

# 定位真实用户的家目录(sudo 执行时 $HOME 可能是 /root)
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)"
[ -n "$TARGET_HOME" ] || TARGET_HOME="$(eval echo "~${TARGET_USER}")"
[ -n "$TARGET_HOME" ] || die "无法确定用户 ${TARGET_USER} 的家目录"
OP_AGENT_DIR="${OP_AGENT_DIR:-${TARGET_HOME}/.op_agent}"
ENV_FILE="${OP_AGENT_DIR}/.env"

# 在 main 之前先做规范化, 避免下面 install_op_agent 走到错误分支
OP_AGENT_PKG="$(normalize_npm_pkg_name "$OP_AGENT_PKG")"
OP_AGENT_FALLBACK_GIT="$(normalize_git_url "$OP_AGENT_FALLBACK_GIT")"

# ==================================================================
# 幂等 / 参数解析
# ------------------------------------------------------------------
# 默认行为: 已安装且版本匹配 → 跳过该步(打印一行绿色日志说明原因)
# 强制全量: --all / --force / -f  或  环境变量 FORCE_REINSTALL=1
# ==================================================================
print_usage() {
    cat <<'EOF'
用法: sudo bash install_opagent.sh [选项]

选项:
  -a, --all, --force    强制全量重装(忽略已安装的 node / bun / op-agent)
  -u, --update          仅更新 op-agent 到最新版本(跳过 node/bun 安装与配置写入)
  -h, --help            显示本帮助

环境变量:
  DEEPSEEK_API_KEY=sk-xxx        密钥(优先于脚本同目录 .opagent_secret)
  OP_AGENT_PKG=@xianzongwendao/op-agent   自定义包名
  OP_AGENT_FALLBACK_GIT=git+https://...   自定义备用 Git 源
  NODE_SETUP_URL=...             自定义 NodeSource 镜像脚本
  NODE_MAJOR=22                  自定义 Node 大版本
  FORCE_REINSTALL=1              等价于 --all

示例:
  sudo bash install_opagent.sh                    # 幂等安装(跳过已存在项)
  sudo bash install_opagent.sh --update           # 仅更新 op-agent 到最新版
  sudo bash install_opagent.sh --all              # 强制全量重装
  FORCE_REINSTALL=1 sudo bash install_opagent.sh # 同上
EOF
}

FORCE_REINSTALL="${FORCE_REINSTALL:-0}"
UPDATE_MODE="${UPDATE_MODE:-0}"
# 解析位置参数(支持 --all / --force / -f / -u / --update / -h / --help)
while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all|--force|-f) FORCE_REINSTALL=1; shift ;;
        -u|--update)          UPDATE_MODE=1; shift ;;
        -h|--help)            print_usage; exit 0 ;;
        --)                   shift; break ;;
        -*)                   log "未知选项: $1(忽略)" "warn"; shift ;;
        *)                    shift ;;    # 忽略位置参数
    esac
done

# (跳过开关已移除, 改用 main 里的 if 判定直接打印日志)

# ==================================================================
# 1. 环境检查
# ==================================================================
check_os() {
    log "检查操作系统…" "info"
    if [ ! -f /etc/debian_version ]; then
        die "本脚本仅支持 Debian / Ubuntu 系发行版(未找到 /etc/debian_version)"
    fi
    local arch
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64|arm64) log "系统: $(. /etc/os-release && echo "$PRETTY_NAME")  架构: ${arch}" "success" ;;
        *) die "不支持的架构: ${arch}(NodeSource 仅支持 amd64 / arm64)" ;;
    esac
}

# ==================================================================
# 2. apt 前置依赖
# ==================================================================
install_pre_reqs() {
    log "安装前置依赖 (apt-transport-https ca-certificates curl gnupg)…" "info"
    $SUDO apt-get update -y || die "apt-get update 失败"
    $SUDO apt-get install -y apt-transport-https ca-certificates curl gnupg \
        || die "前置依赖安装失败"
}

# ==================================================================
# 3. 配置 NodeSource 软件源(USTC 镜像脚本) 并安装 Node.js
# ==================================================================
setup_node_repo() {
    log "配置 Node.js ${NODE_MAJOR} 软件源: ${NODE_SETUP_URL}" "info"
    # 用临时文件下载, 避免管道中断导致半截脚本被执行
    local tmp_setup
    tmp_setup="$(mktemp /tmp/nodesource_setup.XXXXXX.sh)"
    curl -fsSL "$NODE_SETUP_URL" -o "$tmp_setup" || die "下载 NodeSource 安装脚本失败: ${NODE_SETUP_URL}"
    bash -n "$tmp_setup" || { rm -f "$tmp_setup"; die "下载到的 NodeSource 脚本语法校验失败(镜像内容可能异常)"; }
    if [ -n "$SUDO" ]; then
        # -E 保留环境变量; 若 sudoers 不允许则退回普通执行
        if ! $SUDO -E bash "$tmp_setup"; then
            log "sudo -E 执行失败, 退回 sudo bash 重试" "warn"
            $SUDO bash "$tmp_setup" || { rm -f "$tmp_setup"; die "执行 NodeSource 安装脚本失败"; }
        fi
    else
        bash "$tmp_setup" || { rm -f "$tmp_setup"; die "执行 NodeSource 安装脚本失败"; }
    fi
    rm -f "$tmp_setup"
    log "NodeSource 软件源配置完成" "success"
}

install_node() {
    log "安装 Node.js…" "info"
    $SUDO apt-get install -y nodejs || die "Node.js 安装失败"
    hash -r 2>/dev/null || true
    command_exists node || die "node 命令不可用, 安装未成功"
    command_exists npm  || die "npm 命令不可用, 安装未成功"
    local node_ver npm_ver
    node_ver="$(node -v)"
    npm_ver="$(npm -v)"
    log "Node.js 版本: ${node_ver}   npm 版本: ${npm_ver}" "success"
    case "$node_ver" in
        v${NODE_MAJOR}.*) : ;;
        *) log "注意: 期望 Node.js v${NODE_MAJOR}.x, 实际为 ${node_ver}" "warn" ;;
    esac
}

# 幂等判定: node + npm + 主版本号匹配 → 已就位
node_already_installed() {
    command_exists node && command_exists npm || return 1
    local cur
    cur="$(node -v 2>/dev/null || true)"
    case "$cur" in
        v${NODE_MAJOR}.*) return 0 ;;
        *)                 return 1 ;;
    esac
}
# ==================================================================
# 4. 安装 bun 与 op-agent(全局 npm 包)
# ==================================================================
install_bun() {
    log "安装 bun…" "info"
    if command_exists bun; then
        log "bun 已存在($(bun --version)), 执行升级安装" "warn"
    fi
    $SUDO npm install -g bun || die "bun 安装失败"
    hash -r 2>/dev/null || true
    if command_exists bun; then
        log "bun 版本: $(bun --version)" "success"
    else
        log "警告: bun 已安装但不在 PATH, 新开终端后可用" "warn"
    fi
}

# 幂等判定: bun 命令存在
bun_already_installed() {
    command_exists bun
}

install_op_agent() {
    log "安装 op-agent: ${OP_AGENT_PKG}…" "info"
    # 二次确认包名安全(防止函数被外部覆盖后还是带了斜杠无 @)
    OP_AGENT_PKG="$(normalize_npm_pkg_name "$OP_AGENT_PKG")"
    OP_AGENT_FALLBACK_GIT="$(normalize_git_url "$OP_AGENT_FALLBACK_GIT")"

    if ! $SUDO npm install -g "$OP_AGENT_PKG"; then
        log "npm 源安装失败, 尝试 Git(HTTPS) 备用源: ${OP_AGENT_FALLBACK_GIT}" "warn"
        $SUDO npm install -g "$OP_AGENT_FALLBACK_GIT" \
            || die "op-agent 安装失败(npm 源与 Git 备用源均失败)"
    fi
    hash -r 2>/dev/null || true
    if command_exists "$OP_AGENT_CMD"; then
        log "op-agent 安装完成: $(command -v "$OP_AGENT_CMD")" "success"
    else
        log "op-agent 包已安装, 但未找到 '${OP_AGENT_CMD}' 命令, 请检查包提供的 bin 名称" "warn"
    fi
}

# 幂等判定: opagent 可执行已存在
op_agent_already_installed() {
    command_exists "$OP_AGENT_CMD"
}

# 已安装的 op-agent 版本号: 取 npm ls -g 输出中最后一个 @ 之后的部分
# 例: "├── @xianzongwendao/op-agent@0.3.0" → "0.3.0"; 未安装时输出为空
installed_op_agent_version() {
    local line
    line="$($SUDO npm ls -g "$OP_AGENT_PKG" --depth=0 2>/dev/null \
        | grep -F -- "${OP_AGENT_PKG}@" | head -n1 || true)"
    [ -n "$line" ] || return 0
    printf '%s' "${line##*@}"
}

# 更新 op-agent 到最新版本: 复用 install_op_agent(npm install -g 默认装 latest,
# 已安装时即原地升级), 不触碰 node/bun 与 ~/.op_agent 配置
update_op_agent() {
    local cur_ver new_ver
    cur_ver="$(installed_op_agent_version)"
    if [ -n "$cur_ver" ]; then
        log "当前 op-agent 版本: ${cur_ver}, 检查更新…" "info"
    else
        log "未检测到已安装的 op-agent(按包名查询), 将执行安装" "warn"
    fi
    install_op_agent
    hash -r 2>/dev/null || true
    new_ver="$(installed_op_agent_version)"
    if [ -n "$cur_ver" ] && [ "$cur_ver" = "$new_ver" ]; then
        log "op-agent 已是最新版本: ${new_ver}" "success"
    else
        log "op-agent 版本: ${cur_ver:-无} → ${new_ver:-未知}" "success"
    fi
}

# ==================================================================
# 5. 写入配置 ~/.op_agent/.env
# ==================================================================
configure_env() {
    log "配置 op-agent: ${ENV_FILE}" "info"
    $SUDO mkdir -p "$OP_AGENT_DIR" || die "创建目录失败: ${OP_AGENT_DIR}"

    # 已存在则备份, 避免覆盖旧配置
    if [ -f "$ENV_FILE" ]; then
        local backup tmp_new
        backup="${ENV_FILE}.bak.$(date '+%Y%m%d%H%M%S')"
        $SUDO cp -p "$ENV_FILE" "$backup" && log "已备份原配置到 ${backup}" "warn"
        # 保留其它键, 仅替换/新增 DEEPSEEK_API_KEY(不用 sed -i, 兼容 GNU/BSD)
        tmp_new="$(mktemp /tmp/op_agent_env.XXXXXX)"
        $SUDO grep -v '^DEEPSEEK_API_KEY=' "$ENV_FILE" > "$tmp_new" 2>/dev/null || true
        printf 'DEEPSEEK_API_KEY=%s\n' "$DEEPSEEK_API_KEY" >> "$tmp_new"
        $SUDO cp "$tmp_new" "$ENV_FILE" || { rm -f "$tmp_new"; die "写入 ${ENV_FILE} 失败"; }
        rm -f "$tmp_new"
    else
        printf 'DEEPSEEK_API_KEY=%s\n' "$DEEPSEEK_API_KEY" | $SUDO tee "$ENV_FILE" >/dev/null \
            || die "写入 ${ENV_FILE} 失败"
    fi

    $SUDO chmod 600 "$ENV_FILE" || die "设置 ${ENV_FILE} 权限失败"
    # 用 sudo 创建的文件属主会变成 root → 必须改回真实用户,
    # 否则普通用户运行 opagent 时无法在 ~/.op_agent 下写 audit.db / monitors.yaml
    if { [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; } && [ "$TARGET_USER" != "root" ]; then
        $SUDO chown -R "${TARGET_USER}:$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")" \
            "$OP_AGENT_DIR" 2>/dev/null || true
        log "已将 ${OP_AGENT_DIR} 属主改回 ${TARGET_USER}" "info"
    fi
    log "配置写入完成(权限 600)" "success"
}

# ==================================================================
# 6. 安装结果校验
# ==================================================================
# 官方离线自检(不调用 LLM)。以真实用户身份运行, 避免 root 在 /root/.op_agent 下建库
run_self_test() {
    local -a cmd=()
    if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ] && command_exists sudo; then
        cmd=(sudo -u "$TARGET_USER" -H)
    fi
    if command_exists timeout; then
        cmd+=(timeout 60)
    fi
    cmd+=("$OP_AGENT_CMD" --self-test)

    local logfile="/tmp/opagent_self_test.log"
    if "${cmd[@]}" >"$logfile" 2>&1; then
        log "离线自检通过: ${OP_AGENT_CMD} --self-test" "success"
        return 0
    fi
    log "离线自检未通过, 完整输出见 ${logfile}" "warn"
    tail -n 15 "$logfile" 2>/dev/null || true
    return 1
}

verify() {
    log "================ 校验安装结果 ================" "info"
    local ok=0

    if command_exists node; then
        echo "  node      : $(node -v)   ($(command -v node))"
    else
        echo "  node      : 未找到"; ok=1
    fi

    if command_exists npm; then
        echo "  npm       : $(npm -v)   ($(command -v npm))"
    else
        echo "  npm       : 未找到"; ok=1
    fi

    if command_exists bun; then
        echo "  bun       : $(bun --version)"
    else
        echo "  bun       : 未找到(可能需新开终端刷新 PATH)"; ok=1
    fi

    if command_exists "$OP_AGENT_CMD"; then
        echo "  ${OP_AGENT_CMD} : $(command -v "$OP_AGENT_CMD")"
        run_self_test || ok=1
    else
        echo "  ${OP_AGENT_CMD} : 未找到"; ok=1
    fi

    if [ -f "$ENV_FILE" ]; then
        local perm key
        perm="$(stat -c '%a %U' "$ENV_FILE" 2>/dev/null || stat -f '%Lp %Su' "$ENV_FILE")"
        key="$($SUDO grep -c '^DEEPSEEK_API_KEY=' "$ENV_FILE" || true)"
        echo "  ${ENV_FILE} : 权限/属主 ${perm}, DEEPSEEK_API_KEY 条目 ${key} 条"
        [ "$key" = "1" ] || { echo "  ✗ 配置条目异常"; ok=1; }
    else
        echo "  ${ENV_FILE} : 未找到"; ok=1
    fi

    if [ "$ok" -eq 0 ]; then
        log "全部检查通过 ✔" "success"
    else
        log "部分检查未通过, 请查看上面的 ✗/未找到 项" "error"
    fi
    return "$ok"
}

# ==================================================================
# 主流程
# ==================================================================
main() {
    log "开始安装 op-agent (用户: ${TARGET_USER}, 家目录: ${TARGET_HOME})" "info"
    log "最终包名: ${OP_AGENT_PKG}    备用 Git 源: ${OP_AGENT_FALLBACK_GIT}" "info"
    if [ "$FORCE_REINSTALL" = "1" ]; then
        log "检测到 --all / FORCE_REINSTALL=1, 将强制全量重装" "warn"
    else
        log "默认幂等模式: 已安装的 node / bun / op-agent 将自动跳过(传 --all 强制全量)" "info"
    fi

    # ---- 更新模式: 仅升级 op-agent 包, 不动 node/bun 与 ~/.op_agent 配置 ----
    if [ "$UPDATE_MODE" = "1" ]; then
        log "更新模式(--update): 仅把 op-agent 升级到最新版, 跳过 node/bun 安装与配置写入" "info"
        command_exists npm || die "npm 不可用, 请先执行完整安装: sudo bash $0"
        update_op_agent
        verify
        log "更新完成。" "success"
        return 0
    fi

    check_os
    install_pre_reqs

    # Node.js: 软件源只在需要新装时重配(避免重复 apt 源追加)
    if node_already_installed; then
        if [ "$FORCE_REINSTALL" = "1" ]; then
            log "Node.js 已存在但检测到 --all, 重新配置源并升级" "warn"
            setup_node_repo
            install_node
        else
            log "跳过 Node.js 安装(已存在 v${NODE_MAJOR}.x: $(node -v) @ $(command -v node))" "success"
        fi
    else
        log "未检测到 Node.js v${NODE_MAJOR}.x, 开始配置源并安装" "info"
        setup_node_repo
        install_node
    fi

    # bun: 依赖 npm 存在, 所以放在 install_node 之后
    if bun_already_installed; then
        if [ "$FORCE_REINSTALL" = "1" ]; then
            log "bun 已存在但检测到 --all, 执行升级安装" "warn"
            install_bun
        else
            log "跳过 bun 安装(已存在: $(bun --version) @ $(command -v bun))" "success"
        fi
    else
        install_bun
    fi

    # op-agent
    if op_agent_already_installed; then
        if [ "$FORCE_REINSTALL" = "1" ]; then
            log "${OP_AGENT_CMD} 已存在但检测到 --all, 执行升级安装" "warn"
            install_op_agent
        else
            log "跳过 op-agent 安装(已存在 ${OP_AGENT_CMD}: $(command -v "$OP_AGENT_CMD"))" "success"
        fi
    else
        install_op_agent
    fi

    # .env 写入天然幂等(备份 + 仅替换 DEEPSEEK_API_KEY), 始终执行
    configure_env
    verify
    log "安装完成。新开一个终端(或执行 source ~/.bashrc)后即可使用。" "success"
}

main "$@"
