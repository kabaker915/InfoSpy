# 🔍 InfoSpy - 轻量级资产侦察与风险提示工具

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

InfoSpy 是一个用于网络安全初期资产发现的多线程端口扫描器，支持服务识别、弱口令检测和 HTML 报告生成。
适用于授权环境下的快速资产梳理和基础风险排查。

## ✨ 功能特性

- 🚀 **多线程端口扫描** – 支持自定义端口范围，默认 26 个常见端口，可自定义并发线程数
- 🔍 **服务识别** – 自动获取 banner，识别 HTTP、SSH、SMTP、POP3、IMAP 等 25+ 种常见服务
- 🔐 **弱口令检测** – 支持 FTP、SSH、Redis 常见弱口令爆破（需显式启用 `--weak` 参数）
- 📊 **风险评级** – 内置端口风险规则库，支持弱口令后动态升级风险等级
- 📄 **HTML 报告** – 自动生成美观的风险评估报告，包含修复建议
- 🛡️ **安全设计** – 默认仅做无损扫描，弱口令检测不会发送恶意载荷

## 📦 安装

### 环境要求

- Python 3.12 或更高版本
- 推荐使用虚拟环境

### 克隆项目并安装依赖

```bash
git clone https://github.com/kabaker915/InfoSpy.git
cd InfoSpy

# 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# 安装依赖
pip install -r requirements.txt
```

## 🚀 使用方法

### 基础扫描（使用内置常见端口）

```bash
python -m infospy.scanner scanme.nmap.org
```

### 指定端口范围

```bash
python -m infospy.scanner scanme.nmap.org -p "22,80,443"
python -m infospy.scanner 192.168.1.1 -p "1-1000"
```

### 启用弱口令检测

```bash
python -m infospy.scanner scanme.nmap.org --weak
```

### 调整并发线程数（默认 20）

```bash
python -m infospy.scanner scanme.nmap.org -t 50 --weak
```

## 📊 输出示例

```
📡 使用默认常见端口: 共 26 个
🌐 目标解析: scanme.nmap.org -> 45.33.32.156
🔍 正在扫描 45.33.32.156，共 26 个端口（并发线程数: 20）
⚠️  弱口令检测已启用（仅对支持的服务）
```

## 🐳 Docker 方式

```bash
docker build -t infospy .
docker run infospy scanme.nmap.org
```

## 🪟 Windows 一键运行

从 Releases 下载 `infospy.exe`，然后在命令提示符中运行：

```bash
infospy.exe scanme.nmap.org
```

## 🧪 弱口令检测说明

| 服务 | 端口 | 默认字典 |
|------|------|----------|
| FTP | 21 | root/root, admin/admin, anonymous/anonymous 等 |
| SSH | 22 | root/root, root/123456, root/password |
| Redis | 6379 | 空密码及常见弱口令 |

- 必须添加 `--weak` 参数才会执行
- 每个连接设置超时（默认 3 秒），避免长时间阻塞
- 仅用于已获得授权的测试环境

## 📋 风险评级规则

内置 25+ 端口风险规则，涵盖高危、中危、低危、信息四个等级，弱口令检测成功会动态提升风险等级。

示例：
- 端口 445 (SMB) → 高危，提示永恒之蓝风险
- 端口 3306 (MySQL) → 中危，建议限制访问来源
- 端口 22 (SSH) → 信息，弱口令后提升为中危

## 📂 项目结构

```
InfoSpy/
├── .gitignore
├── .dockerignore
├── README.md
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── infospy/
│   ├── __init__.py
│   └── scanner.py          # 主程序
```

## 📌 未来计划

- 增加 MySQL、MongoDB、HTTP Basic Auth 弱口令检测
- 支持更多服务的版本探测

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 📄 许可证

MIT License

## ⚠️ 免责声明

本工具仅限用于授权的安全测试、个人学习或合法评估。使用者必须遵守当地法律法规，未经授权使用本工具进行扫描或弱口令尝试属于违法行为。作者不承担任何因滥用本工具造成的后果。
