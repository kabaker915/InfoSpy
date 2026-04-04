# 🔍 InfoSpy

轻量级资产侦察与风险提示工具 - 多线程端口扫描、服务识别、弱口令检测、风险评级、HTML报告生成

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## ✨ 功能特性

- 🚀 **多线程端口扫描** – 支持自定义端口范围，默认 26 个常见端口
- 🔍 **服务识别** – 自动获取 banner，识别 25+ 种常见服务
- 🔐 **弱口令检测** – 支持 FTP、SSH、Redis 常见弱口令爆破
- 📊 **风险评级** – 内置端口风险规则库，支持弱口令后动态升级风险等级
- 📄 **HTML 报告** – 自动生成美观的风险评估报告，包含修复建议
- ⚙️ **灵活配置** – 可自定义端口、线程数，支持弱口令模式

## 📦 安装

```bash
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/InfoSpy.git
cd InfoSpy

# 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# 安装依赖
pip install paramiko
🚀 使用方法
基础扫描（默认端口）
bash
python -m infospy.scanner scanme.nmap.org
自定义端口
bash
python -m infospy.scanner 192.168.1.1 -p 22,80,443
python -m infospy.scanner 192.168.1.1 -p 1-1000
启用弱口令检测
bash
python -m infospy.scanner scanme.nmap.org --weak
调整并发线程数
bash
python -m infospy.scanner target.com -t 50 --weak
📊 输出示例
text
📡 使用默认常见端口: 共 26 个
🌐 目标解析: scanme.nmap.org -> 45.33.32.156
🔍 正在扫描 45.33.32.156，共 26 个端口（并发线程数: 20）
⚠️  弱口令检测已启用（仅对支持的服务）

✅ [1/26] 端口    22 开放 | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
✅ [2/26] 端口    80 开放 | HTTP/1.1 200 OK

✅ 扫描完成。发现 5 个开放端口。

🔐 开始弱口令检测...
  尝试 22 端口 (SSH) ...
    ❌ 未发现弱口令

📄 报告已保存: report_45.33.32.156_20260404_142657.html
📁 生成报告
运行后会生成 report_<IP>_<时间戳>.html，在浏览器中打开即可查看详细的风险分析和修复建议。

https://screenshot.png

🛠️ 支持的弱口令服务
服务	端口	默认字典
FTP	21	root/root, admin/admin, anonymous/anonymous 等
SSH	22	root/root, root/123456, root/password
Redis	6379	空密码及常见弱口令
📋 风险评级规则
内置 25+ 端口风险规则，涵盖高危、中危、低危、信息四个等级，弱口令检测成功会动态提升风险等级。

示例：

端口 445 (SMB) → 高危，提示永恒之蓝风险

端口 3306 (MySQL) → 中危，建议限制访问来源

端口 22 (SSH) → 信息，弱口令后提升为中危

🧪 测试环境
Python 3.8+

Windows / Linux / macOS

🤝 贡献
欢迎提交 Issue 和 Pull Request。

📄 许可证
MIT License

⚠️ 免责声明
本工具仅限用于授权安全测试，未经授权使用可能违反法律法规。使用者需自行承担相关责任。