# 🔍 InfoSpy - 轻量级资产侦察与风险提示工具

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

InfoSpy 是一个用于网络安全初期资产发现的异步端口扫描器，支持服务识别、弱口令检测、SSL 证书检测、Web 指纹识别、子域名枚举和多格式报告生成。适用于授权环境下的快速资产梳理和基础风险排查。

## ✨ 功能特性

- 🚀 **异步端口扫描** — 基于 asyncio 的高性能扫描，支持自定义端口范围和并发数
- 🔍 **服务识别** — 自动获取 banner，识别 25+ 种常见服务
- 🔐 **弱口令检测** — 支持 FTP、SSH、Redis、MySQL、MongoDB、HTTP Basic Auth、VNC、Telnet、Elasticsearch
- 🔒 **SSL 证书检测** — 检查证书有效期、颁发者、过期状态
- 🌐 **Web 指纹识别** — 识别 CMS、框架、WAF、Server 类型
- 🌏 **子域名枚举** — DNS 字典爆破 + crt.sh 证书透明度查询
- 📊 **风险评级** — 内置端口风险规则库，弱口令后动态升级风险等级
- 📄 **多格式报告** — 支持 HTML、JSON、CSV 三种格式
- 📝 **自定义字典** — 支持加载自定义用户名:密码字典文件
- ⚙️ **配置文件** — 支持 YAML 配置文件，命令行参数优先
- 📈 **进度条** — 使用 tqdm 实时显示扫描进度

## 📦 安装

```bash
git clone https://github.com/kabaker915/InfoSpy.git
cd InfoSpy
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

## 🚀 使用方法

### 基础扫描

```bash
python -m infospy.scanner scanme.nmap.org
```

### 全功能扫描

```bash
python -m infospy.scanner scanme.nmap.org --weak --ssl --web --subdomain
```

### 自定义端口

```bash
python -m infospy.scanner 192.168.1.1 -p "22,80,443"
python -m infospy.scanner 192.168.1.1 -p "1-1000"
```

### 使用自定义字典

```bash
python -m infospy.scanner scanme.nmap.org --weak -d my_dict.txt
```

字典格式（每行 `用户名:密码`）：
```
root:root
admin:admin123
test:test
```

### 输出不同格式

```bash
python -m infospy.scanner scanme.nmap.org -f json
python -m infospy.scanner scanme.nmap.org -f csv -o result.csv
```

### 使用配置文件

```bash
python -m infospy.scanner scanme.nmap.org -c config.yaml
```

配置文件示例：
```yaml
target: scanme.nmap.org
ports: "22,80,443"
threads: 30
weak: true
ssl: true
web: true
subdomain: true
format: html
dict: "my_dict.txt"
```

### 同步模式

```bash
python -m infospy.scanner scanme.nmap.org --sync
```

## 🧪 弱口令检测

| 服务 | 端口 | 说明 |
|------|------|------|
| FTP | 21 | 用户名:密码 字典 |
| SSH | 22 | 前 3 个常用组合 |
| Telnet | 23 | 前 3 个常用组合 |
| HTTP Basic Auth | 80/443/8080/8443 | 用户名:密码 字典 |
| MySQL | 3306 | 用户名:密码 字典 |
| VNC | 5900 | 常见密码 |
| Redis | 6379 | 空密码及常见弱口令 |
| MongoDB | 27017 | 用户名:密码 + 空密码 |
| Elasticsearch | 9200 | 无认证访问检测 |

## 🌐 Web 指纹识别

对 HTTP/HTTPS 端口自动检测：
- **CMS**: WordPress、Joomla、Drupal、Dedecms、Discuz、Typecho、Hexo、Hugo
- **框架**: Laravel、Django、Spring、ThinkPHP、Flask、Express、ASP.NET、Ruby on Rails
- **WAF**: Cloudflare、ModSecurity、长亭雷池、宝塔WAF、AWS WAF
- **Server**: Nginx、Apache、IIS、Caddy、LiteSpeed、Tomcat

## 🌏 子域名枚举

- **DNS 字典爆破** — 使用内置 200+ 子域名字典
- **crt.sh 查询** — 通过证书透明度日志发现子域名
- 仅对域名目标有效（IP 目标自动跳过）

## 📄 报告格式

| 格式 | 参数 | 说明 |
|------|------|------|
| HTML | `-f html` | 可视化网页报告（默认） |
| JSON | `-f json` | 结构化数据 |
| CSV | `-f csv` | Excel 可打开 |

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
│   ├── scanner.py           # 主程序
│   └── wordlist/
│       └── subdomains.txt   # 子域名字典
```

## 📋 命令行参数

| 参数 | 说明 |
|------|------|
| `target` | 目标 IP 或域名 |
| `-p, --ports` | 端口范围 |
| `-t, --threads` | 并发线程数（默认 20） |
| `--weak` | 启用弱口令检测 |
| `--ssl` | 启用 SSL 证书检测 |
| `--web` | 启用 Web 指纹识别 |
| `--subdomain` | 启用子域名枚举 |
| `-d, --dict` | 自定义字典文件 |
| `-f, --format` | 报告格式（html/json/csv） |
| `-o, --output` | 报告输出路径 |
| `-c, --config` | YAML 配置文件 |
| `--sync` | 使用同步模式 |

## ⚠️ 免责声明

本工具仅限用于授权的安全测试、个人学习或合法评估。使用者必须遵守当地法律法规，未经授权使用本工具属于违法行为。作者不承担任何因滥用本工具造成的后果。

## 📄 许可证

MIT License
