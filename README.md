# 通用 Shell 脚本函数库 (lib_utils.sh)

![version](https://img.shields.io/badge/version-1.4-blue)
![license](https://img.shields.io/badge/license-MIT-green)

一个可重用的 Bash 函数库，旨在简化、标准化和加速您的 Shell 脚本开发。通过引入 `lib_utils.sh`，您可以专注于业务逻辑，而不是重复编写基础功能代码。

## ✨ 核心特性

- **日志系统**: 提供 `info`, `success`, `warning`, `error`, `debug` 五级彩色日志输出，使脚本输出更清晰。
- **自文档化**: 内置 `help` 命令，可以查看所有可用函数列表及其详细用法和示例。
- **依赖自动处理**: `ensure_command` 和 `install_dependencies` 函数可自动检测并安装缺失的命令和软件包（支持 Debian/Ubuntu, CentOS/RHEL, Alpine）。
- **系统信息**: 轻松获取操作系统版本、系统架构、公网 IP 等信息。
- **健壮的错误处理**: `error_exit` 函数可中断脚本执行，防止错误蔓延。
- **常用工具封装**: 封装了证书申请、文件备份、权限设置、随机字符串/UUID生成等高频操作。
- **跨平台兼容**: 函数在设计时考虑了不同 Linux 发行版的兼容性。

## 目录

- [安装与使用](#-安装与使用)
- [快速入门示例](#-快速入门示例)
- [函数参考](#-函数参考)
  - [日志与消息](#日志与消息)
  - [系统与网络](#系统与网络)
  - [证书管理](#证书管理)
  - [文件与目录](#文件与目录)
  - [软件包管理](#软件包管理)
  - [进程管理](#进程管理)
  - [用户管理](#用户管理)
  - [安全与标识符](#安全与标识符)
- [如何贡献](#-如何贡献)
- [许可证](#-许可证)

## 🚀 安装与使用

1.  **下载函数库文件**

    通过 `git` 克隆:
    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
    ```
    或者直接下载:
    ```bash
    curl -O https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/lib_utils.sh
    ```

2.  **在你的脚本中引入**

    在你的主脚本开头，使用 `source` 命令引入 `lib_utils.sh`：

    ```bash
    #!/bin/bash

    # 引入函数库
    source ./lib_utils.sh

    # 现在你可以直接调用库中的所有函数
    info_msg "脚本启动成功，函数库已加载。"
    my_uuid=$(generate_uuid)
    success_msg "生成了一个新的 UUID: ${my_uuid}"
    ```

## 💡 快速入门示例

这是一个名为 `setup_app.sh` 的示例脚本，它演示了如何使用本函数库来完成一系列常见任务。

```bash
#!/bin/bash

# ======================================================
#            应用安装脚本 (setup_app.sh)
#  演示如何使用 lib_utils.sh 来简化脚本编写
# ======================================================

# 引入函数库，如果不存在则退出
if [ -f ./lib_utils.sh ]; then
    source ./lib_utils.sh
else
    echo "[错误] 函数库 lib_utils.sh 未找到！" >&2
    exit 1
fi

# --- 主逻辑开始 ---

# 1. 打印欢迎信息并检查 root 权限
info_msg "欢迎使用应用安装脚本..."
_check_root || error_exit "此脚本需要以 root 权限运行。"

# 2. 获取并显示系统信息
os_info=$(get_os_info)
arch=$(get_system_arch)
info_msg "检测到系统: ${os_info} (${arch})"

# 3. 确保必要的工具已安装 (例如：jq)
info_msg "正在检查并安装依赖工具..."
ensure_command "jq" "jq" || error_exit "安装 jq 失败。"

# 4. 生成一个随机密码用于数据库
db_password=$(generate_random_string 16)
info_msg "为数据库生成了一个随机密码。"
# 出于安全考虑，实际使用中不应直接打印密码
# success_msg "密码: ${db_password}" 

# 5. 创建一个系统用户来运行应用
info_msg "正在为应用创建系统用户 'apprunner'..."
create_system_user "apprunner"

# 6. 备份旧的配置文件
config_file="/etc/myapp/config.toml"
if [ -f "$config_file" ]; then
    info_msg "发现旧的配置文件，正在备份..."
    backup_file "$config_file" "/opt/backups"
else
    warning_msg "未找到旧的配置文件，将创建新的。"
    mkdir -p /etc/myapp
fi

# 7. 创建新的配置文件（此处为伪代码）
echo "# 新的配置文件" > "$config_file"
echo "database_password = \"${db_password}\"" >> "$config_file"
echo "server_id = \"$(generate_uuid)\"" >> "$config_file"

# 8. 设置正确的目录权限
info_msg "正在为应用目录 '/var/lib/myapp' 设置权限..."
mkdir -p /var/lib/myapp
set_directory_permissions "/var/lib/myapp" 750 640 "apprunner" "apprunner"

# 9. 一切顺利，打印成功信息
success_msg "应用环境配置完成！"

exit 0
```

---

## 📚 函数参考

使用 `help <函数名>` 可以获取更详细的实时帮助。

### 日志与消息

-   `error_exit <message> [exit_code]`
    打印红色错误消息并退出脚本。
-   `success_msg <message>`
    打印绿色成功消息。
-   `warning_msg <message>`
    打印黄色警告消息。
-   `info_msg <message>`
    打印蓝色信息消息。
-   `debug_msg <message>`
    当环境变量 `DEBUG=1` 时，打印紫色调试消息。

### 系统与网络

-   `get_system_arch`
    获取系统架构，如 `x86_64-linux`。
-   `get_os_info`
    获取系统发行版信息，如 `ubuntu 22.04` 或 `centos 7.9.2009`。
-   `get_latest_github_release <owner/repo>`
    获取指定 GitHub 仓库的最新发布版本号。
-   `check_network_connection`
    检查到 `api.github.com` 的网络连通性。
-   `get_public_ip`
    从公共服务获取本机的公网 IP 地址。

### 证书管理

-   `install_acme_sh <email>`
    安装 acme.sh 证书申请工具。
-   `issue_acme_cert <domain> <cert_path> <key_path> [reload_cmd] [owner] [group]`
    使用 acme.sh (standalone 模式) 申请 Let's Encrypt 证书并安装。
-   `generate_self_signed_cert <domain> <cert_path> <key_path> [owner] [group]`
    生成一个有效期为10年的自签名证书。

### 文件与目录

-   `backup_file <file_path> [backup_dir]`
    将文件备份到指定目录（默认为 `./backups`），并附带时间戳。
-   `set_directory_permissions <dir> [dir_mode] [file_mode] [owner] [group]`
    递归地为目录和文件设置权限及所有者。

### 软件包管理

-   `install_dependencies <pkg1> <pkg2> ...`
    使用系统包管理器（`apt`, `yum`, `apk`）安装一个或多个依赖包。
-   `ensure_command <command> [package_name]`
    确保一个命令可用，如果不可用，则尝试安装对应的包。

### 进程管理

-   `is_process_running <process_name>`
    通过 `pgrep` 检查一个进程是否正在运行。
-   `restart_service <service_name>`
    通过 `systemctl` 或 `service` 命令重启一个系统服务。

### 用户管理

-   `create_system_user <username> [shell]`
    创建一个系统用户（`useradd -r`），默认为 nologin shell。

### 安全与标识符

-   `generate_random_string [length]`
    使用 `openssl` 生成一个安全的、URL友好的随机字符串（默认32位）。
-   `generate_uuid`
    生成一个标准的 v4 UUID。优先使用 `uuidgen`，并有多种备选方案。
-   `validate_ip <ip_address>`
    验证一个字符串是否为合法的 IPv4 地址格式。

## 🤝 如何贡献

欢迎您为这个项目做出贡献！

1.  **Fork** 本仓库。
2.  创建一个新的分支 (`git checkout -b feature/your-new-feature`)。
3.  提交您的修改 (`git commit -am 'Add some feature'`)。
4.  将您的分支推送到远程仓库 (`git push origin feature/your-new-feature`)。
5.  创建一个新的 **Pull Request**。

如果您发现了 Bug 或有功能建议，请随时提交 [Issues](https://github.com/YOUR_USERNAME/YOUR_REPO/issues)。

## © 许可证

本项目基于 [MIT License](LICENSE) 许可证。
