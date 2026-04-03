# InfoSpy - 轻量级资产侦察与风险提示工具

InfoSpy 是一个用于网络安全初期资产发现的多线程端口扫描器，支持服务识别和 HTML 报告生成。

## 功能特性

- 多线程快速扫描常见端口（26个）
- 基于 Banner 的服务/版本识别（支持 SSH、HTTP、SMTP 等）
- 生成美观的 HTML 扫描报告
- 轻量级，仅依赖 Python 标准库

## 快速开始

### 环境要求
- Python 3.12 或更高版本

### 安装与使用

```bash
# 克隆项目
git clone https://github.com/kabaker915/InfoSpy.git
cd InfoSpy

# 创建虚拟环境（可选）
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 运行扫描
python -m infospy.scanner