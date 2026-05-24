# 🔍 InfoSpy - 轻量级资产侦察与风险提示工具

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

InfoSpy 是一个用于网络安全初期资产发现的异步端口扫描器，支持服务识别、弱口令检测、SSL 证书检测和多格式报告生成。适用于授权环境下的快速资产梳理和基础风险排查。

## ✨ 功能特性

- 🚀 **异步端口扫描** — 基于 asyncio 的高性能扫描，支持自定义端口范围和并发数
- 🔍 **服务识别** — 自动获取 banner，识别 HTTP、SSH、SMTP、POP3、IMAP 等 25+ 种常见服务
- 🔐 **弱口令检测** — 支持 FTP、SSH、Redis、MySQL、MongoDB、HTTP Basic Auth 弱口令爆破
- 🔒 **SSL 证书检测** — 检查 HTTPS 端口证书有效期、颁发者、过期状态
- 📊 **风险评级** — 内置端口风险规则库，支持弱口令后动态升级风险等级
- 📄 **多格式报告** — 支持 HTML、JSON、CSV 三种报告格式
- 📈 **进度条** — 使用 tqdm 实时显示扫描进度
- 🛡️ **安全设计** — 默认仅做无损扫描，弱口令检测不会发送恶意载荷

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

### 启用 SSL 证书检测

```bash
python -m infospy.scanner scanme.nmap.org --ssl
```

### 全功能扫描

```bash
python -m infospy.scanner scanme.nmap.org --weak --ssl
```

### 输出 JSON 报告

```bash
python -m infospy.scanner scanme.nmap.org -f json
```

### 输出 CSV 报告

```bash
python -m infospy.scanner scanme.nmap.org -f csv
```

### 调整并发线程数（默认 20）

```bash
python -m infospy.scanner scanme.nmap.org -t 50 --weak
```

### 使用同步模式（兼容性回退）

```bash
python -m infospy.scanner scanme.nmap.org --sync
```

### 自定义报告输出路径

```bash
python -m infospy.scanner scanme.nmap.org -o my_report.html
```

## 📊 输出示例

```
使用默认常见端口: 共 26 个
目标解析: scanme.nmap.org -> 45.33.32.156
正在扫描 45.33.32.156，共 26 个端口（并发: 20）
弱口令检测已启用
SSL 证书检测已启用

扫描进度: 100%|████████████████████| 26/26
扫描完成，发现 5 个开放端口。

SSL 检测: 100%|████████████████████| 2/2
  端口 443: 有效（180 天）

弱口令检测: 100%|████████████████████| 5/5

报告已保存: report_45.33.32.156_20260524_120000.html
```

## 🧪 弱口令检测说明

| 服务 | 端口 | 默认字典 |
|------|------|----------|
| FTP | 21 | root/root, admin/admin, anonymous/anonymous 等 |
| SSH | 22 | root/root, root/123456, root/password |
| Redis | 6379 | 空密码及常见弱口令 |
| MySQL | 3306 | root/root, admin/admin 等 |
| MongoDB | 27017 | root/root, 空密码等 |
| HTTP Basic Auth | 80/443/8080/8443 | admin/admin 等 |

- 必须添加 `--weak` 参数才会执行
- 每个连接设置超时（默认 3 秒），避免长时间阻塞
- 仅用于已获得授权的测试环境

## 🔒 SSL 证书检测说明

对所有 HTTPS 类端口（443、8443、993、995）自动检测：
- 证书主题和颁发者
- 有效期和剩余天数
- 过期状态和警告

## 📄 报告格式

| 格式 | 说明 | 参数 |
|------|------|------|
| HTML | 可视化网页报告（默认） | `-f html` |
| JSON | 结构化数据，便于程序处理 | `-f json` |
| CSV | 表格格式，可用 Excel 打开 | `-f csv` |

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

## 🐳 Docker 方式

```bash
docker build -t infospy .
docker run infospy scanme.nmap.org
```

## ⚠️ 免责声明

本工具仅限用于授权的安全测试、个人学习或合法评估。使用者必须遵守当地法律法规，未经授权使用本工具进行扫描或弱口令尝试属于违法行为。作者不承担任何因滥用本工具造成的后果。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 📄 许可证

MIT License
