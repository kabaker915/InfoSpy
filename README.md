# 🔍 InfoSpy - 轻量级资产侦察与风险提示工具 (1.1版本)

InfoSpy 是一个用于网络安全初期资产发现的多线程端口扫描器，支持服务识别、弱口令检测和 HTML 报告生成。  
适用于授权环境下的快速资产梳理和基础风险排查。

---

## ✨ 功能特性

- 🚀 **多线程端口扫描** – 可自定义端口范围和并发线程数，扫描效率高
- 🧬 **服务/Banner 识别** – 支持 HTTP、SSH、SMTP、POP3、IMAP 等常见服务的版本探测
- 🔐 **弱口令检测** – 支持 FTP、SSH、Redis（可扩展），需显式启用 `--weak` 参数
- 📄 **HTML 报告** – 自动生成带端口列表和弱口令结果的可视化报告
- 🎛️ **命令行友好** – 支持目标指定、端口范围、线程数等灵活参数
- 🛡️ **安全设计** – 默认仅做无损扫描，弱口令检测不会发送恶意载荷

---

## 📦 安装与使用

### 环境要求
- Python 3.12 或更高版本
- 推荐使用虚拟环境

### 克隆项目
```bash
git clone https://github.com/kabaker915/InfoSpy.git
cd InfoSpy
```

### 创建虚拟环境并安装依赖
```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

### 基础扫描（使用内置常见端口）
```bash
python -m infospy.scanner scanme.nmap.org
```

### 指定端口范围
```bash
python -m infospy.scanner scanme.nmap.org -p "22,80,443"
python -m infospy.scanner 192.168.1.1 -p "1-1000"
```

### 启用弱口令检测（仅对支持的服务）
```bash
python -m infospy.scanner scanme.nmap.org --weak
```

### 调整并发线程数（默认是20）
```bash
python -m infospy.scanner scanme.nmap.org -t 10
```

---

## 🧪 弱口令检测说明

- 支持服务：FTP（21）、SSH（22）、Redis（6379）
- 检测方式：使用内置常见用户名/密码字典（`WEAK_CREDENTIALS`）进行登录尝试
- 安全控制：
  - 必须添加 `--weak` 参数才会执行
  - 每个连接设置超时（默认3秒），避免长时间阻塞
  - 仅用于**已获得授权**的测试环境

如需添加更多服务（如 MySQL、MongoDB），只需在 `WEAK_CHECKERS` 字典中扩展即可。

---

## 📂 项目结构

```
InfoSpy/
├── .gitignore
├── README.md
├── infospy/
│   ├── __init__.py
│   └── scanner.py          # 主程序
└── requirements.txt        # 依赖列表
```

---

## 🛠️ 技术栈

- Python 3.12+
- 标准库：`socket`, `threading`, `argparse`, `datetime`, `ftplib`
- 第三方库：`paramiko` (SSH 客户端)

---

## 📌 未来计划

- [ ] 增加 MySQL、MongoDB、HTTP Basic Auth 弱口令检测
- [ ] 提供 Docker 镜像，支持一键运行
- [ ] 输出 JSON 格式结果，便于集成
- [ ] 编写单元测试

---

## ⚠️ 免责声明

本工具仅限用于**授权的安全测试、个人学习或合法评估**。  
使用者必须遵守当地法律法规，未经授权使用本工具进行扫描或弱口令尝试属于违法行为。  
作者不承担任何因滥用本工具造成的后果。

---

## 📬 联系与贡献

项目地址：[https://github.com/kabaker915/InfoSpy](https://github.com/kabaker915/InfoSpy)  
欢迎提交 Issue 或 Pull Request。