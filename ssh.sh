#!/usr/bin/env bash
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
LOCAL_OVERRIDE_FILE="${SSHD_DROPIN_DIR}/99-local.conf"
DEFAULT_KEY_DIR="/root/.ssh"

usage() {
  cat <<'USAGE'
用法: $0 [选项]
  (无参数)        进入交互式菜单
  -u <用户名>     为指定用户创建/更新 SSH 密钥并写入 authorized_keys
  -k <路径>       自定义私钥保存路径 (默认: /root/.ssh/<用户名>_id_ed25519)
  -f              强制重新生成密钥
  -K              将 sshd 切换为仅密钥登录 (禁用密码)
  -P              将 sshd 切换为仅密码登录 (禁用密钥)
  -R <策略>       设置 root SSH 登录策略: yes|no|prohibit-password
  -E              直接启用 root 密码登录并交互式设置密码
  -m              直接打开交互菜单
  -h              显示本帮助

可以组合 -u/-k/-f 与 -K/-P/-R/-E，一次完成密钥生成和登录策略切换。
USAGE
}

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "[!] 需要 root 权限运行此脚本。" >&2
    exit 1
  fi
}

get_home_dir() {
  local user=$1
  local home
  home=$(eval echo "~${user}") || true
  if [[ ! -d $home ]]; then
    echo "[!] 无法获取用户 ${user} 的家目录。" >&2
    exit 1
  fi
  printf '%s' "$home"
}

reload_sshd() {
  disable_ssh_socket_activation
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^sshd\\.service'; then
      systemctl unmask sshd >/dev/null 2>&1 || true
      systemctl enable sshd >/dev/null 2>&1 || true
      systemctl restart sshd
    else
      systemctl unmask ssh >/dev/null 2>&1 || true
      systemctl enable ssh >/dev/null 2>&1 || true
      systemctl restart ssh
    fi
  else
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
  fi
}

disable_ssh_socket_activation() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  local unit
  for unit in ssh.socket sshd.socket; do
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "$unit"; then
      echo "[*] 已尝试停用并屏蔽 $unit，避免其接管 SSH 监听端口。"
      systemctl stop "$unit" 2>/dev/null || true
      systemctl disable "$unit" >/dev/null 2>&1 || true
      systemctl mask "$unit" >/dev/null 2>&1 || true
    fi
  done
}

verify_ssh_listen_port() {
  local port=$1
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi

  if ss -tlnp 2>/dev/null | awk -v p=":$port" '
    /LISTEN/ && /sshd/ && $4 ~ (p"$") { found=1 }
    END { exit found ? 0 : 1 }
  '; then
    echo "[*] 监听校验通过：sshd 正在端口 $port 上监听。"
  else
    echo "[!] 监听校验失败：未发现 sshd 监听端口 $port。" >&2
    echo "[!] 当前 sshd 监听如下：" >&2
    ss -tlnp 2>/dev/null | awk '/LISTEN/ && /sshd/ { print "    " $0 }' >&2 || true
    echo "[!] 若仍看到 :22，请检查是否被 ssh.socket/sshd.socket 或防火墙规则影响。" >&2
  fi
}

backup_sshd_config() {
  local backup_file="${SSHD_CONFIG}.bak.$(date +%F)"
  cp "$SSHD_CONFIG" "$backup_file"
  echo "[*] 已备份 sshd_config -> $backup_file"
}

ensure_sshd_dropin_dir() {
  install -d -m 755 "$SSHD_DROPIN_DIR"
}

ensure_dropin_priority() {
  local include_line="Include /etc/ssh/sshd_config.d/*.conf"
  local include_regex='^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config[.]d/[*][.]conf([[:space:]]+(#.*)?)?$'

  if [[ ! -f $SSHD_CONFIG ]]; then
    echo "[!] 未找到 sshd_config ($SSHD_CONFIG)。" >&2
    exit 1
  fi

  local -a include_lines=()
  mapfile -t include_lines < <(awk -v regex="$include_regex" '$0 ~ regex { print NR }' "$SSHD_CONFIG")

  if (( ${#include_lines[@]} == 0 )); then
    printf '\n%s\n' "$include_line" >> "$SSHD_CONFIG"
    echo "[*] 已在 sshd_config 末尾添加 Include /etc/ssh/sshd_config.d/*.conf。"
    return
  fi

  local last_include_line_index=$(( ${#include_lines[@]} - 1 ))
  local last_include_line=${include_lines[$last_include_line_index]}
  if awk -v start=$((last_include_line + 1)) '
    NR >= start {
      if ($0 !~ /^[[:space:]]*(#.*)?$/) {
        found = 1
        exit 0
      }
    }
    END { exit found ? 0 : 1 }
  ' "$SSHD_CONFIG" >/dev/null; then
    local tmp
    tmp=$(mktemp)
    awk -v regex="$include_regex" '$0 ~ regex { next } { print }' "$SSHD_CONFIG" > "$tmp"
    printf '\n%s\n' "$include_line" >> "$tmp"
    cat "$tmp" > "$SSHD_CONFIG"
    rm -f "$tmp"
    echo "[*] 已将 Include /etc/ssh/sshd_config.d/*.conf 移至 sshd_config 末尾以确保优先生效。"
  fi
}

sanitize_main_sshd_options() {
  local entries_array_name=$1
  local -n entries="$entries_array_name"
  local -a files=()

  files+=("$SSHD_CONFIG")
  if [[ -d $SSHD_DROPIN_DIR ]]; then
    while IFS= read -r -d '' file; do
      files+=("$file")
    done < <(find "$SSHD_DROPIN_DIR" -maxdepth 1 -type f -name '*.conf' -print0 | sort -z)
  fi

  local python_script
  read -r -d '' python_script <<'PY'
import sys
from pathlib import Path

skip = Path(sys.argv[1])
key_count = int(sys.argv[2])
keys = [sys.argv[3 + i] for i in range(key_count)]
files = [Path(p) for p in sys.argv[3 + key_count:]]

updated_any = False
for path in files:
    if not path.exists() or path == skip:
        continue

    lines = path.read_text(encoding='utf-8').splitlines()
    updated = False
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        lower = stripped.lower()
        for key in keys:
            if lower.startswith(key.lower()):
                lines[idx] = '# ' + line
                updated = True
                break

    if updated:
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        print(f'[*] {path} 中存在冲突项，已自动注释。')
        updated_any = True

if not updated_any:
    print('[*] 未在其他配置文件中发现会覆盖策略的条目。')
PY

  python3 -c "$python_script" "$LOCAL_OVERRIDE_FILE" "${#entries[@]}" "${entries[@]}" "${files[@]}"
}

verify_sshd_mode() {
  local mode=$1
  local dump
  if ! dump=$(sshd -T 2>/dev/null); then
    echo "[!] 无法通过 sshd -T 验证配置，跳过一致性检查。" >&2
    return 0
  fi

  local expect_pub expect_pass expect_kbd expect_chal expect_root
  case "$mode" in
    key-only)
      expect_pub="yes"
      expect_pass="no"
      expect_kbd="no"
      expect_chal="no"
      expect_root="prohibit-password"
      ;;
    password-only)
      expect_pub="no"
      expect_pass="yes"
      expect_kbd="no"
      expect_chal="no"
      expect_root="yes"
      ;;
    *)
      return 0
      ;;
  esac

  local mismatches=0
  check_expectation() {
    local key=$1
    local expected=$2
    local actual
    actual=$(printf '%s\n' "$dump" | awk -v k="$key" '$1==k { print $2; exit }')
    if [[ -z $actual ]]; then
      echo "[*] sshd -T 未输出 $key，可能因使用旧版 OpenSSH 或 Match 规则，跳过校验。"
      return
    fi
    if [[ $actual != $expected ]]; then
      echo "[!] sshd -T 显示 $key=$actual (期望 $expected)。" >&2
      mismatches=1
    fi
  }

  check_expectation "pubkeyauthentication" "$expect_pub"
  check_expectation "passwordauthentication" "$expect_pass"
  check_expectation "kbdinteractiveauthentication" "$expect_kbd"
  check_expectation "challengeresponseauthentication" "$expect_chal"
  check_expectation "permitrootlogin" "$expect_root"

  if (( mismatches == 0 )); then
    echo "[*] sshd -T 验证：当前策略与 $mode 设置一致。"
  else
    echo "[!] 检测到 sshd 仍沿用旧策略，请手动检查 /etc/ssh/sshd_config。" >&2
  fi
}

update_sshd_option_in_file() {
  local file=$1
  local key=$2
  local value=$3

  local python_script
  read -r -d '' python_script <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]

if not path.exists():
    path.write_text(f"# --- 本地覆盖：root 登录策略 ---\n{key} {value}\n", encoding="utf-8")
    print(f"[*] 已创建 {path} 并写入 {key} {value}")
    sys.exit(0)

lines = path.read_text(encoding="utf-8").splitlines()
updated = False
for i, line in enumerate(lines):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    if stripped.lower().startswith(key.lower()):
        lines[i] = f"{key} {value}"
        updated = True
        break

if not updated:
    lines.append(f"{key} {value}")

path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"[*] 已在 {path} 中设置 {key} {value}")
PY

  python3 -c "$python_script" "$file" "$key" "$value"
}

normalize_root_login_policy() {
  local policy=$1
  case "${policy,,}" in
    yes|y)
      printf '%s' "yes"
      ;;
    no|n)
      printf '%s' "no"
      ;;
    prohibit-password|without-password|keys-only|key-only|pubkey)
      printf '%s' "prohibit-password"
      ;;
    *)
      return 1
      ;;
  esac
}

verify_root_login_policy() {
  local expected=$1
  local dump
  if ! dump=$(sshd -T 2>/dev/null); then
    echo "[!] 无法通过 sshd -T 验证配置，跳过 root 登录校验。" >&2
    return 0
  fi
  local actual
  actual=$(printf '%s\n' "$dump" | awk '$1=="permitrootlogin" { print $2; exit }')
  if [[ -z $actual ]]; then
    echo "[*] sshd -T 未输出 permitrootlogin，可能因旧版 OpenSSH 或 Match 规则，跳过校验。"
    return 0
  fi
  if [[ $actual != "$expected" ]]; then
    echo "[!] sshd -T 显示 permitrootlogin=$actual (期望 $expected)。" >&2
    return 1
  fi
  echo "[*] sshd -T 验证：permitrootlogin=$expected。"
}

apply_root_login_policy() {
  local policy=$1
  local normalized
  if ! normalized=$(normalize_root_login_policy "$policy"); then
    echo "[!] root 登录策略无效: $policy (仅支持 yes|no|prohibit-password)。"
    return 1
  fi

  backup_sshd_config
  ensure_sshd_dropin_dir
  ensure_dropin_priority

  local sanitized_keys=(PermitRootLogin)
  sanitize_main_sshd_options sanitized_keys

  update_sshd_option_in_file "$LOCAL_OVERRIDE_FILE" "PermitRootLogin" "$normalized"

  if ! sshd -t; then
    echo "[!] sshd 配置检测失败，未应用 root 登录策略。" >&2
    return 1
  fi

  reload_sshd
  verify_root_login_policy "$normalized" || true

  if [[ $normalized == "yes" ]]; then
    echo "[*] root SSH 登录已启用 (允许密码)。"
    echo "[*] 注意：如需密码登录，请确保 PasswordAuthentication yes 且已设置 root 密码。"
  elif [[ $normalized == "prohibit-password" ]]; then
    echo "[*] root SSH 登录已启用 (仅允许密钥)。"
  else
    echo "[*] root SSH 登录已禁用。"
  fi
}

enable_root_password_login() {
  local set_password=${1:-1}
  backup_sshd_config
  ensure_sshd_dropin_dir
  ensure_dropin_priority

  local sanitized_keys=(PermitRootLogin PasswordAuthentication)
  sanitize_main_sshd_options sanitized_keys

  update_sshd_option_in_file "$LOCAL_OVERRIDE_FILE" "PermitRootLogin" "yes"
  update_sshd_option_in_file "$LOCAL_OVERRIDE_FILE" "PasswordAuthentication" "yes"

  if ! sshd -t; then
    echo "[!] sshd 配置检测失败，未启用 root 密码登录。" >&2
    return 1
  fi

  reload_sshd
  verify_root_login_policy "yes" || true

  echo "[*] 已启用 root 密码登录 (PermitRootLogin yes + PasswordAuthentication yes)。"
  if [[ $set_password -eq 1 ]]; then
    echo "[*] 现在将交互式设置 root 密码。"
    passwd root
  else
    echo "[*] 已跳过 root 密码修改。"
  fi
}

validate_ssh_port() {
  local port=$1
  if [[ ! $port =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if (( port < 1 || port > 65535 )); then
    return 1
  fi
}

apply_ssh_port() {
  local port=$1

  if ! validate_ssh_port "$port"; then
    echo "[!] SSH 端口无效: $port (必须是 1-65535 的整数)。" >&2
    return 1
  fi

  backup_sshd_config
  ensure_sshd_dropin_dir
  ensure_dropin_priority

  local sanitized_keys=(Port)
  sanitize_main_sshd_options sanitized_keys
  update_sshd_option_in_file "$SSHD_CONFIG" "Port" "$port"
  update_sshd_option_in_file "$LOCAL_OVERRIDE_FILE" "Port" "$port"

  if ! sshd -t; then
    echo "[!] sshd 配置检测失败，未修改 SSH 端口。" >&2
    return 1
  fi

  reload_sshd

  local dump actual_port
  if dump=$(sshd -T 2>/dev/null); then
    actual_port=$(printf '%s\n' "$dump" | awk '$1=="port" { print $2; exit }')
    if [[ -n $actual_port && $actual_port != "$port" ]]; then
      echo "[!] sshd -T 显示 port=$actual_port (期望 $port)。请检查是否有 Match 规则覆盖。" >&2
    fi
  fi

  verify_ssh_listen_port "$port"

  echo "[*] SSH 端口已设置为 $port。"
}

apply_ssh_mode() {
  local mode=$1
  backup_sshd_config
  ensure_sshd_dropin_dir
  ensure_dropin_priority
  local sanitized_keys=(
    PermitRootLogin
    PasswordAuthentication
    ChallengeResponseAuthentication
    KbdInteractiveAuthentication
    PubkeyAuthentication
  )
  sanitize_main_sshd_options sanitized_keys

  case "$mode" in
    key-only)
      cat >"$LOCAL_OVERRIDE_FILE" <<'EOF'
# --- 本地覆盖：仅允许密钥登录 ---
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
AuthorizedKeysFile .ssh/authorized_keys
EOF
      ;;
    password-only)
      cat >"$LOCAL_OVERRIDE_FILE" <<'EOF'
# --- 本地覆盖：仅允许密码登录 ---
PubkeyAuthentication no
PasswordAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin yes
EOF
      ;;
    *)
      echo "[!] 未知模式: $mode" >&2
      return 1
      ;;
  esac

  if ! sshd -t; then
    echo "[!] sshd 配置检测失败，未应用新策略。" >&2
    return 1
  fi

  reload_sshd
  verify_sshd_mode "$mode"

  case "$mode" in
    key-only)
      echo "[*] 已切换为仅使用密钥登录。"
      ;;
    password-only)
      echo "[*] 已切换为仅使用密码登录。"
      ;;
  esac
}

configure_key_for_user() {
  local username=$1
  local key_path=${2:-}
  local force_recreate=${3:-0}

  if ! id "$username" >/dev/null 2>&1; then
    echo "[!] 用户 ${username} 不存在。" >&2
    return 1
  fi

  local home_dir
  home_dir=$(get_home_dir "$username")
  local ssh_dir="$home_dir/.ssh"
  local key_owner
  key_owner=$(id -gn "$username")

  install -d -m 700 -o "$username" -g "$key_owner" "$ssh_dir"

  if [[ -z $key_path ]]; then
    key_path="${DEFAULT_KEY_DIR}/${username}_id_ed25519"
  fi

  local key_dir
  key_dir=$(dirname "$key_path")
  if [[ ! -d $key_dir ]]; then
    install -d -m 700 -o root -g root "$key_dir"
  fi

  if [[ -f $key_path && $force_recreate -eq 0 ]]; then
    echo "[*] 密钥 $key_path 已存在，使用 -f 可强制重新生成。"
    if [[ ! -f ${key_path}.pub ]]; then
      echo "[!] 找不到 ${key_path}.pub，请使用 -f 重新生成。" >&2
      return 1
    fi
  else
    rm -f "$key_path" "$key_path.pub"
    ssh-keygen -t ed25519 -N "" -f "$key_path" -C "${username}@$(hostname -f 2>/dev/null || hostname)" >/dev/null
    chmod 600 "$key_path"
    chmod 644 "$key_path.pub"
  fi

  local authorized_file="$ssh_dir/authorized_keys"
  if [[ $force_recreate -eq 1 && -f $authorized_file ]]; then
    cp "$authorized_file" "${authorized_file}.bak.$(date +%F-%H%M%S)"
  fi

  if [[ $force_recreate -eq 1 ]]; then
    cat "$key_path.pub" > "$authorized_file"
  else
    cat "$key_path.pub" >> "$authorized_file"
    sort -u "$authorized_file" -o "$authorized_file"
  fi

  chown "$username:$key_owner" "$authorized_file"
  chmod 600 "$authorized_file"

  cat <<INFO
[+] 已完成：
    私钥: $key_path
    公钥: ${key_path}.pub
    公钥已写入: $ssh_dir/authorized_keys
INFO
}

menu_generate_key() {
  local username key_path force_answer force_flag=0
  read -rp $'请输入要配置的系统用户名 (默认: root): ' username
  if [[ -z $username ]]; then
    username="root"
    echo "[*] 未输入用户名，默认使用 root。"
  fi
  read -rp "自定义私钥保存路径(留空使用默认 ${DEFAULT_KEY_DIR}/${username}_id_ed25519): " key_path
  read -rp $'若密钥已存在是否覆盖? (y/N): ' force_answer
  if [[ ${force_answer,,} =~ ^y ]]; then
    force_flag=1
  fi
  if configure_key_for_user "$username" "$key_path" "$force_flag"; then
    echo "[+] 密钥处理完成。"
  else
    echo "[!] 密钥处理失败，请检查输入。" >&2
  fi
}

interactive_menu() {
  while true; do
    cat <<'MENU'
================ SSH 管理菜单 ================
1) 创建/更新密钥并写入 authorized_keys
2) root 密码/端口设置
3) 切换为仅密钥登录 (禁用密码)
4) 切换为仅密码登录 (禁用密钥)
5) 退出
==============================================
MENU
    read -rp "请选择操作 [1-5]: " choice
    case "$choice" in
      1)
        menu_generate_key
        ;;
      2)
        local sub_choice new_port
        cat <<'SUBMENU'
----------- root 密码/端口设置 -----------
1) 修改 root 密码 (可选同时修改 SSH 端口)
2) 仅修改 SSH 端口
3) 返回上一级
-----------------------------------------
SUBMENU
        read -rp "请选择操作 [1-3]: " sub_choice
        case "$sub_choice" in
          1)
            if enable_root_password_login 1; then
              local also_change_port
              read -rp "是否同时修改 SSH 端口? (y/N): " also_change_port
              if [[ ${also_change_port,,} =~ ^y ]]; then
                read -rp "请输入新的 SSH 端口(1-65535): " new_port
                if apply_ssh_port "$new_port"; then
                  echo "[+] root 密码与 SSH 端口均已修改。"
                else
                  echo "[!] root 密码已修改，但 SSH 端口修改失败。" >&2
                fi
              else
                echo "[+] root 密码登录已启用，密码已更新。"
              fi
            else
              echo "[!] 操作失败，请查看上方错误信息。" >&2
            fi
            ;;
          2)
            read -rp "请输入新的 SSH 端口(1-65535): " new_port
            if apply_ssh_port "$new_port"; then
              echo "[+] SSH 端口修改完成。"
            else
              echo "[!] SSH 端口修改失败，请查看上方错误信息。" >&2
            fi
            ;;
          3)
            echo "[*] 已返回上一级。"
            ;;
          *)
            echo "[!] 无效选择。" >&2
            ;;
        esac
        ;;
      3)
        if apply_ssh_mode "key-only"; then
          echo "[+] SSH 已设置为仅密钥登录。"
        else
          echo "[!] 切换失败，请查看上方错误信息。" >&2
        fi
        ;;
      4)
        if apply_ssh_mode "password-only"; then
          echo "[+] SSH 已设置为仅密码登录。"
        else
          echo "[!] 切换失败，请查看上方错误信息。" >&2
        fi
        ;;
      5)
        echo "完成。"
        break
        ;;
      *)
        echo "[!] 无效选择。" >&2
        ;;
    esac
    echo
  done
}

main() {
  require_root

  if [[ $# -eq 0 ]]; then
    interactive_menu
    exit 0
  fi

  local username=""
  local key_path=""
  local force_recreate=0
  local desired_mode=""
  local root_login_policy=""
  local enable_root_password=0

  while getopts ":u:k:fhKPmR:E" opt; do
    case "$opt" in
      u) username=$OPTARG ;;
      k) key_path=$OPTARG ;;
      f) force_recreate=1 ;;
      K)
        if [[ -n $desired_mode ]]; then
          echo "[!] 不能同时指定 -K 和 -P。" >&2
          exit 1
        fi
        desired_mode="key-only"
        ;;
      P)
        if [[ -n $desired_mode ]]; then
          echo "[!] 不能同时指定 -K 和 -P。" >&2
          exit 1
        fi
        desired_mode="password-only"
        ;;
      R)
        root_login_policy=$OPTARG
        ;;
      E)
        enable_root_password=1
        ;;
      m)
        interactive_menu
        exit 0
        ;;
      h)
        usage
        exit 0
        ;;
      :)
        echo "[!] 选项 -$OPTARG 需要参数。" >&2
        exit 1
        ;;
      \?)
        echo "[!] 无效选项: -$OPTARG" >&2
        exit 1
        ;;
    esac
  done

  if [[ -n $username ]]; then
    configure_key_for_user "$username" "$key_path" "$force_recreate"
  fi

  if [[ -n $desired_mode ]]; then
    apply_ssh_mode "$desired_mode"
  fi

  if [[ -n $root_login_policy ]]; then
    apply_root_login_policy "$root_login_policy"
  fi

  if [[ $enable_root_password -eq 1 ]]; then
    enable_root_password_login
  fi

  if [[ -z $username && -z $desired_mode && -z $root_login_policy && $enable_root_password -eq 0 ]]; then
    echo "[!] 未指定任何操作，请查看 -h 帮助或直接运行脚本进入菜单。" >&2
    exit 1
  fi
}

main "$@"
