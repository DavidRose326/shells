#!/bin/bash
# =================================================================
#               通用 Shell 脚本函数库 (lib_utils.sh) v1.3
#
# 描述: 包含一系列可重用的、通用的 bash 函数，每个函数都包含依赖检查。
# 用法: 在你的主脚本中使用 'source ./lib_utils.sh' 来引入这些函数。
#       输入 'help' 查看所有可用函数及其用法。
# =================================================================

# --- 帮助系统 ---
help() {
    echo -e "\033[36m通用 Shell 脚本函数库 (lib_utils.sh) 使用帮助\033[0m"
    echo -e "\033[32m用法: 在脚本中 source 本文件后，可直接调用以下函数\033[0m"
    echo "================================================================"
    echo -e "\033[34m[日志和消息打印函数]\033[0m"
    echo "error_exit <消息> [退出码]  - 打印错误消息并退出脚本"
    echo "success_msg <消息>         - 打印成功消息"
    echo "warning_msg <消息>         - 打印警告消息"
    echo "info_msg <消息>            - 打印信息消息"
    echo "debug_msg <消息>           - 打印调试消息(需设置 DEBUG=1)"

    echo -e "\n\033[34m[系统与网络工具函数]\033[0m"
    echo "get_system_arch            - 获取系统架构(x86_64-linux/aarch64-linux等)"
    echo "get_os_info                - 获取系统发行版信息"
    echo "get_latest_github_release <owner/repo> - 获取GitHub仓库最新版本号"
    echo "check_network_connection   - 检查网络连接状态"
    echo "get_public_ip              - 获取公网IP地址"

    echo -e "\n\033[34m[证书管理函数]\033[0m"
    echo "install_acme_sh <email>    - 安装acme.sh证书工具"
    echo "issue_acme_cert <domain> <cert_path> <key_path> [reload_cmd] [owner] [group] - 申请Let's Encrypt证书"
    echo "generate_self_signed_cert <domain> <cert_path> <key_path> [owner] [group] - 生成自签名证书"

    echo -e "\n\033[34m[文件与目录操作函数]\033[0m"
    echo "backup_file <文件路径> [备份目录] - 安全备份文件"
    echo "set_directory_permissions <目录> [dir_mode] [file_mode] [owner] [group] - 递归设置目录权限"

    echo -e "\n\033[34m[软件包管理函数]\033[0m"
    echo "install_dependencies <包1> <包2>... - 安装系统依赖包"
    echo "ensure_command <命令> [包名] - 确保命令可用，自动安装缺失命令"

    echo -e "\n\033[34m[进程管理函数]\033[0m"
    echo "is_process_running <进程名> - 检查进程是否在运行"
    echo "restart_service <服务名>   - 重启系统服务"

    echo -e "\n\033[34m[用户管理函数]\033[0m"
    echo "create_system_user <用户名> [shell] - 创建系统用户"

    echo -e "\n\033[34m[安全相关函数]\033[0m"
    echo "generate_random_string [长度] - 生成随机字符串"
    echo "validate_ip <IP地址>       - 验证IP地址格式"

    echo -e "\n\033[33m输入 'help <函数名>' 查看具体函数用法示例\033[0m"
}

show_function_help() {
    local func_name="$1"
    case "$func_name" in
        "error_exit")
            echo -e "\033[36merror_exit <消息> [退出码]\033[0m"
            echo "功能: 打印红色错误消息并退出脚本"
            echo "示例:"
            echo "  error_exit \"配置文件不存在\" 1"
            echo "  error_exit \"权限不足\" 2"
            ;;
        "success_msg")
            echo -e "\033[36msuccess_msg <消息>\033[0m"
            echo "功能: 打印绿色成功消息"
            echo "示例:"
            echo "  success_msg \"安装完成\""
            ;;
        "warning_msg")
            echo -e "\033[36mwarning_msg <消息>\033[0m"
            echo "功能: 打印黄色警告消息"
            echo "示例:"
            echo "  warning_msg \"使用默认配置\""
            ;;
        "info_msg")
            echo -e "\033[36minfo_msg <消息>\033[0m"
            echo "功能: 打印蓝色信息消息"
            echo "示例:"
            echo "  info_msg \"正在下载文件...\""
            ;;
        "debug_msg")
            echo -e "\033[36mdebug_msg <消息>\033[0m"
            echo "功能: 打印紫色调试消息(需设置 DEBUG=1)"
            echo "示例:"
            echo "  export DEBUG=1"
            echo "  debug_msg \"变量值: \$var\""
            ;;
        "get_system_arch")
            echo -e "\033[36mget_system_arch\033[0m"
            echo "功能: 获取系统架构"
            echo "输出: x86_64-linux/aarch64-linux/armv7-linux"
            echo "示例:"
            echo "  arch=\$(get_system_arch)"
            echo "  echo \"系统架构: \$arch\""
            ;;
        "get_os_info")
            echo -e "\033[36mget_os_info\033[0m"
            echo "功能: 获取系统发行版信息"
            echo "示例:"
            echo "  os_info=\$(get_os_info)"
            echo "  echo \"系统信息: \$os_info\""
            ;;
        "get_latest_github_release")
            echo -e "\033[36mget_latest_github_release <owner/repo>\033[0m"
            echo "功能: 获取GitHub仓库的最新发布版本号"
            echo "依赖: curl, grep, sed"
            echo "示例:"
            echo "  version=\$(get_latest_github_release \"owner/repo\")"
            echo "  echo \"最新版本: \$version\""
            ;;
        "check_network_connection")
            echo -e "\033[36mcheck_network_connection\033[0m"
            echo "功能: 检查网络连接状态"
            echo "返回: 0-成功 1-失败"
            echo "示例:"
            echo "  if check_network_connection; then"
            echo "    echo \"网络正常\""
            echo "  else"
            echo "    error_exit \"网络连接失败\""
            echo "  fi"
            ;;
        "get_public_ip")
            echo -e "\033[36mget_public_ip\033[0m"
            echo "功能: 获取公网IP地址"
            echo "依赖: curl"
            echo "示例:"
            echo "  ip=\$(get_public_ip)"
            echo "  echo \"公网IP: \$ip\""
            ;;
        "install_acme_sh")
            echo -e "\033[36minstall_acme_sh <email>\033[0m"
            echo "功能: 安装acme.sh证书工具"
            echo "依赖: curl, socat"
            echo "示例:"
            echo "  install_acme_sh \"admin@example.com\""
            ;;
        "issue_acme_cert")
            echo -e "\033[36missue_acme_cert <domain> <cert_path> <key_path> [reload_cmd] [owner] [group]\033[0m"
            echo "功能: 使用acme.sh申请Let's Encrypt证书"
            echo "依赖: iptables"
            echo "示例:"
            echo "  issue_acme_cert \"example.com\" \\"
            echo "    \"/etc/ssl/example.com.crt\" \\"
            echo "    \"/etc/ssl/example.com.key\" \\"
            echo "    \"systemctl reload nginx\" \\"
            echo "    \"www-data\" \"www-data\""
            ;;
        "generate_self_signed_cert")
            echo -e "\033[36mgenerate_self_signed_cert <domain> <cert_path> <key_path> [owner] [group]\033[0m"
            echo "功能: 生成自签名证书"
            echo "依赖: openssl"
            echo "示例:"
            echo "  generate_self_signed_cert \"example.com\" \\"
            echo "    \"/etc/ssl/selfsigned.crt\" \\"
            echo "    \"/etc/ssl/selfsigned.key\" \\"
            echo "    \"nginx\" \"nginx\""
            ;;
        "backup_file")
            echo -e "\033[36mbackup_file <文件路径> [备份目录]\033[0m"
            echo "功能: 安全备份文件"
            echo "示例:"
            echo "  backup_file \"/etc/nginx/nginx.conf\""
            echo "  backup_file \"~/app/config.ini\" \"/backups\""
            ;;
        "set_directory_permissions")
            echo -e "\033[36mset_directory_permissions <目录> [dir_mode] [file_mode] [owner] [group]\033[0m"
            echo "功能: 递归设置目录权限和属主"
            echo "示例:"
            echo "  set_directory_permissions \"/var/www\" 750 640 \"www-data\" \"www-data\""
            ;;
        "install_dependencies")
            echo -e "\033[36minstall_dependencies <包1> <包2>...\033[0m"
            echo "功能: 自动检测系统并安装依赖包"
            echo "示例:"
            echo "  install_dependencies curl wget unzip"
            ;;
        "ensure_command")
            echo -e "\033[36mensure_command <命令> [包名]\033[0m"
            echo "功能: 确保命令可用，自动安装缺失命令"
            echo "示例:"
            echo "  ensure_command docker"
            echo "  ensure_command jq \"jq\""
            ;;
        "is_process_running")
            echo -e "\033[36mis_process_running <进程名>\033[0m"
            echo "功能: 检查进程是否在运行"
            echo "返回: 0-正在运行 1-未运行"
            echo "示例:"
            echo "  if is_process_running \"nginx\"; then"
            echo "    echo \"Nginx正在运行\""
            echo "  fi"
            ;;
        "restart_service")
            echo -e "\033[36mrestart_service <服务名>\033[0m"
            echo "功能: 重启系统服务"
            echo "示例:"
            echo "  restart_service nginx"
            ;;
        "create_system_user")
            echo -e "\033[36mcreate_system_user <用户名> [shell]\033[0m"
            echo "功能: 创建系统用户"
            echo "示例:"
            echo "  create_system_user \"appuser\" \"/bin/bash\""
            ;;
        "generate_random_string")
            echo -e "\033[36mgenerate_random_string [长度]\033[0m"
            echo "功能: 生成安全的随机字符串(默认32字符)"
            echo "依赖: openssl"
            echo "示例:"
            echo "  password=\$(generate_random_string 24)"
            echo "  echo \"生成密码: \$password\""
            ;;
        "validate_ip")
            echo -e "\033[36mvalidate_ip <IP地址>\033[0m"
            echo "功能: 验证IP地址格式"
            echo "返回: 0-有效 1-无效"
            echo "示例:"
            echo "  if validate_ip \"192.168.1.1\"; then"
            echo "    echo \"IP地址有效\""
            echo "  fi"
            ;;
        *)
            echo -e "\033[31m未找到函数 '$func_name' 的帮助信息\033[0m"
            echo "输入 'help' 查看所有可用函数"
            return 1
            ;;
    esac
    return 0
}

help_dispatcher() {
    if [ "$#" -eq 0 ]; then
        help
    else
        show_function_help "$1"
    fi
}

# 重命名help函数以便外部调用
help() {
    help_dispatcher "$@"
}

# --- 日志和消息打印函数 ---
error_exit() { echo -e "\033[31m[错误] ${1}\033[0m" >&2; exit "${2:-1}"; }
success_msg() { echo -e "\033[32m[成功] ${1}\033[0m"; }
warning_msg() { echo -e "\033[33m[警告] ${1}\033[0m"; }
info_msg() { echo -e "\033[34m[信息] ${1}\033[0m"; }
debug_msg() { [ "${DEBUG:-0}" -eq 1 ] && echo -e "\033[35m[调试] ${1}\033[0m"; }

# --- 内部工具函数 ---
_check_command() {
    if ! command -v "$1" >/dev/null; then
        echo "依赖命令 '$1' 未找到。" >&2
        return 1
    fi
}

_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "此功能需要 root 权限。" >&2
        return 1
    fi
}

# --- 系统与网络工具函数 ---

get_system_arch() {
    _check_command "uname" || return 1

    case $(uname -m) in
        x86_64) echo "x86_64-linux" ;;
        aarch64 | arm64) echo "aarch64-linux" ;;
        armv7l) echo "armv7-linux" ;;
        *) echo "不支持的系统架构: $(uname -m)" >&2; return 1 ;;
    esac
}

get_os_info() {
    _check_command "grep" || return 1
    _check_command "awk" || return 1

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID $VERSION_ID"
    elif [ -f /etc/centos-release ]; then
        awk '{print $1 " " $(NF-1)}' /etc/centos-release
    else
        echo "无法确定系统发行版" >&2
        return 1
    fi
}

get_latest_github_release() {
    _check_command "curl" || return 1
    _check_command "grep" || return 1
    _check_command "sed"  || return 1

    local repo="$1"
    if [ -z "$repo" ]; then echo "未提供 GitHub 仓库参数 (owner/repo)。" >&2; return 1; fi

    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local api_response; api_response=$(curl -m 10 -s "$api_url" 2>/dev/null)

    if [ -z "$api_response" ]; then echo "无法连接到 GitHub API: ${api_url}" >&2; return 1; fi
    if echo "$api_response" | grep -q "API rate limit exceeded"; then echo "GitHub API 速率限制。" >&2; return 1; fi

    local latest_version; latest_version=$(echo "$api_response" | grep '"tag_name":' | sed -E 's/.*"tag_name": "v?([^"]+)".*/\1/')

    if [[ -z "$latest_version" || ! "$latest_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
        echo "从 API 响应中未能解析出有效的版本号。" >&2
        return 1
    fi
    echo "$latest_version"
}

check_network_connection() {
    _check_command "curl" || return 1
    if ! curl -m 5 -s -I https://api.github.com >/dev/null; then return 1; fi
    return 0
}

get_public_ip() {
    _check_command "curl" || return 1

    local ip_services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://ident.me"
    )

    for service in "${ip_services[@]}"; do
        local ip; ip=$(curl -m 3 -s "$service")
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done

    echo "无法获取公网IP地址" >&2
    return 1
}

# --- 证书管理函数 ---

install_acme_sh() {
    _check_command "curl" || return 1
    _check_command "socat" || return 1

    local email="$1"
    if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        info_msg "正在安装 acme.sh..."
        curl -sS https://get.acme.sh | sh -s email="${email}" >/dev/null
        if [ $? -ne 0 ]; then echo "acme.sh 安装失败。" >&2; return 1; fi
        success_msg "acme.sh 安装成功。"
    fi
    return 0
}

issue_acme_cert() {
    _check_command "iptables" || return 1

    local domain="$1"
    local cert_path="$2"
    local key_path="$3"
    local reload_cmd="$4"
    local owner="${5:-root}"
    local group="${6:-root}"
    local acme_sh_path="$HOME/.acme.sh/acme.sh"

    if [ ! -f "$acme_sh_path" ]; then echo "acme.sh 未安装，请先调用 install_acme_sh。" >&2; return 1; fi
    if [ -z "$domain" ] || [ -z "$cert_path" ] || [ -z "$key_path" ]; then echo "申请 ACME 证书所需参数不足。" >&2; return 1; fi

    info_msg "正在使用 acme.sh 申请证书，请确保域名已正确解析到本机IP..."

    # 临时打开端口 80
    info_msg "临时打开防火墙端口 80 ..."
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1

    # 申请证书
    "$acme_sh_path" --issue --standalone -d "${domain}" --force
    local issue_status=$?

    # 关闭端口 80
    info_msg "关闭防火墙端口 80 ..."
    iptables -D INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1

    if [ ${issue_status} -ne 0 ]; then
        echo "证书申请失败。请检查域名解析、端口80占用及防火墙设置。" >&2
        return 1
    fi

    success_msg "证书申请成功！"
    info_msg "正在安装证书..."

    local cert_dir; cert_dir=$(dirname "${cert_path}")
    mkdir -p "${cert_dir}"

    local final_reload_cmd="chown -R ${owner}:${group} ${cert_dir} && chmod 750 ${cert_dir} && chmod 640 ${cert_dir}/*"
    if [ -n "$reload_cmd" ]; then
        final_reload_cmd="${final_reload_cmd} && ${reload_cmd}"
    fi

    "$acme_sh_path" --install-cert -d "${domain}" \
        --cert-file      "${cert_path}" \
        --key-file       "${key_path}" \
        --fullchain-file "${cert_dir}/fullchain.pem" \
        --reloadcmd      "${final_reload_cmd}" >/dev/null

    if [ $? -ne 0 ]; then echo "证书安装失败。" >&2; return 1; fi

    # 立即执行一次权限设置
    chown -R "${owner}:${group}" "${cert_dir}"
    chmod 750 "${cert_dir}"
    chmod 640 "${cert_dir}"/*

    success_msg "证书已安装并配置好自动续期。"
    return 0
}

generate_self_signed_cert() {
    _check_command "openssl" || return 1

    local domain="$1"
    local cert_path="$2"
    local key_path="$3"
    local owner="${4:-root}"
    local group="${5:-root}"

    if [ -z "$domain" ] || [ -z "$cert_path" ] || [ -z "$key_path" ]; then echo "生成自签名证书所需参数不足。" >&2; return 1; fi

    local cert_dir; cert_dir=$(dirname "${cert_path}")
    mkdir -p "${cert_dir}"

    info_msg "正在生成自签名证书..."
    openssl req -x509 -nodes -newkey rsa:4096 \
        -keyout "${key_path}" \
        -out "${cert_path}" \
        -days 3650 \
        -subj "/CN=${domain}" >/dev/null 2>&1

    if [ $? -ne 0 ] || [ ! -f "${cert_path}" ]; then echo "自签名证书生成失败。" >&2; return 1; fi

    # 设置权限
    chown -R "${owner}:${group}" "${cert_dir}"
    chmod 750 "${cert_dir}"
    chmod 640 "${cert_path}" "${key_path}"

    success_msg "自签名证书已生成。"
    warning_msg "客户端连接时，请务必配置 'skip-cert-verify: true' 或等效选项。"
    return 0
}

# --- 文件与目录操作函数 ---

backup_file() {
    local file_path="$1"
    local backup_dir="${2:-./backups}"

    if [ ! -f "$file_path" ]; then
        echo "文件不存在: $file_path" >&2
        return 1
    fi

    mkdir -p "$backup_dir"
    local timestamp; timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${backup_dir}/$(basename "$file_path").${timestamp}.bak"

    cp -p "$file_path" "$backup_file"

    if [ $? -eq 0 ]; then
        info_msg "文件已备份到: $backup_file"
        return 0
    else
        echo "文件备份失败" >&2
        return 1
    fi
}

set_directory_permissions() {
    local target_dir="$1"
    local dir_mode="${2:-750}"
    local file_mode="${3:-640}"
    local owner="${4:-root}"
    local group="${5:-root}"

    if [ ! -d "$target_dir" ]; then
        echo "目录不存在: $target_dir" >&2
        return 1
    fi

    _check_command "chown" || return 1
    _check_command "chmod" || return 1
    _check_command "find" || return 1

    info_msg "正在设置目录权限: $target_dir"

    chown -R "${owner}:${group}" "$target_dir"
    find "$target_dir" -type d -exec chmod "$dir_mode" {} \;
    find "$target_dir" -type f -exec chmod "$file_mode" {} \;

    success_msg "目录权限设置完成"
    return 0
}

# --- 软件包管理函数 ---

install_dependencies() {
    _check_root || return 1

    local packages=("$@")
    if [ ${#packages[@]} -eq 0 ]; then
        echo "未提供要安装的软件包列表" >&2
        return 1
    fi

    local os_info; os_info=$(get_os_info)
    local pkg_manager

    case $os_info in
        "ubuntu"* | "debian"*)
            pkg_manager="apt-get -qq install -y"
            apt-get update -qq
            ;;
        "centos"* | "rhel"*)
            pkg_manager="yum -q install -y"
            ;;
        "alpine"*)
            pkg_manager="apk add --quiet"
            ;;
        *)
            echo "不支持的发行版: $os_info" >&2
            return 1
            ;;
    esac

    info_msg "正在安装依赖包: ${packages[*]}"
    $pkg_manager "${packages[@]}" >/dev/null

    if [ $? -eq 0 ]; then
        success_msg "依赖包安装成功"
        return 0
    else
        echo "依赖包安装失败" >&2
        return 1
    fi
}

ensure_command() {
    local cmd="$1"
    local pkg="${2:-$cmd}"

    if ! command -v "$cmd" >/dev/null; then
        warning_msg "命令 $cmd 未找到，尝试安装..."
        install_dependencies "$pkg" || {
            error_exit "无法安装 $pkg 包"
            return 1
        }
    fi
    return 0
}

# --- 进程管理函数 ---

is_process_running() {
    local process_name="$1"
    if pgrep -x "$process_name" >/dev/null; then
        return 0
    else
        return 1
    fi
}

restart_service() {
    local service_name="$1"

    _check_root || return 1

    if ! is_process_running "$service_name"; then
        info_msg "服务 $service_name 未运行，正在启动..."
    else
        info_msg "正在重启服务 $service_name ..."
    fi

    if systemctl restart "$service_name" >/dev/null 2>&1; then
        success_msg "服务 $service_name 重启成功"
        return 0
    elif service "$service_name" restart >/dev/null 2>&1; then
        success_msg "服务 $service_name 重启成功"
        return 0
    else
        error_exit "无法重启服务 $service_name"
        return 1
    fi
}

# --- 用户管理函数 ---

create_system_user() {
    _check_root || return 1

    local username="$1"
    local shell="${2:-/usr/sbin/nologin}"

    if id "$username" &>/dev/null; then
        debug_msg "用户 $username 已存在"
        return 0
    fi

    info_msg "正在创建系统用户: $username"
    useradd -r -s "$shell" "$username"

    if [ $? -eq 0 ]; then
        success_msg "用户 $username 创建成功"
        return 0
    else
        error_exit "无法创建用户 $username"
        return 1
    fi
}

# --- 安全相关函数 ---

generate_random_string() {
    local length="${1:-32}"
    _check_command "openssl" || return 1

    openssl rand -base64 "$((length * 3 / 4))" | tr -d '\n=/' | head -c "$length"
}

validate_ip() {
    local ip="$1"
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# --- 初始化检查 ---
# 确保关键命令可用
ensure_command "curl"
ensure_command "grep"
ensure_command "sed"
