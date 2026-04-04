#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
InfoSpy - 轻量级资产侦察与风险提示工具
功能：多线程端口扫描、服务识别、弱口令检测、本地风险评级与修复建议、HTML报告生成
"""

import socket
import time
import argparse
import ftplib
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ========== 1. 配置区域 ==========
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 11211, 9200, 27018]

# 探测命令映射
PROBE_COMMANDS = {
    25: b"EHLO test\r\n",
    110: b"CAPA\r\n",
    143: b"A1 CAPABILITY\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
}

# 弱口令字典
WEAK_CREDENTIALS = [
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("user", "user"),
    ("test", "test"),
    ("ftp", "ftp"),
    ("anonymous", "anonymous"),
]

# 端口到服务名称
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    9200: "Elasticsearch", 27018: "MongoDB-Shard"
}

# 风险评级规则：端口 -> (等级, 风险说明, 修复建议)
RISK_RULES = {
    21: ("中危", "FTP 协议默认不加密，传输明文凭据和数据", "建议使用 SFTP 或 FTPS 替代，并限制访问来源 IP"),
    22: ("信息", "SSH 服务开放，建议使用密钥认证并禁用 root 登录", "配置强密码策略，定期更新 OpenSSH 版本"),
    23: ("高危", "Telnet 协议明文传输所有数据，极易被窃听", "立即禁用 Telnet，改用 SSH"),
    25: ("低危", "SMTP 邮件服务开放，可能被用于邮件伪造", "限制 SMTP 访问来源，启用 TLS 加密"),
    53: ("中危", "DNS 服务开放，可能被用于 DNS 放大攻击或信息泄露", "限制外部递归查询，启用 DNSSEC"),
    80: ("低危", "HTTP 服务开放，建议升级到 HTTPS", "配置 HSTS，防止中间人攻击"),
    110: ("中危", "POP3 协议默认不加密，凭据可能被窃听", "改用 POP3S (995) 或启用 SSL/TLS"),
    111: ("中危", "RPC 端口开放，可能暴露敏感信息", "使用防火墙限制访问来源"),
    135: ("中危", "RPC 服务开放，存在远程漏洞风险", "限制访问来源，及时打补丁"),
    139: ("中危", "NetBIOS 服务开放，可能泄露系统信息", "如非必要，关闭 SMBv1，限制访问"),
    143: ("中危", "IMAP 协议默认不加密，凭据可能被窃听", "改用 IMAPS (993) 或启用 SSL/TLS"),
    443: ("低危", "HTTPS 服务开放，应确保使用 TLS 1.2+", "配置强加密套件，定期更新证书"),
    445: ("高危", "SMB 服务开放，存在被勒索病毒或永恒之蓝漏洞利用风险", "限制访问来源，关闭 SMBv1，安装安全补丁"),
    993: ("低危", "IMAPS 服务开放，加密传输", "保持证书有效，禁用弱加密算法"),
    995: ("低危", "POP3S 服务开放，加密传输", "保持证书有效，禁用弱加密算法"),
    1723: ("中危", "PPTP VPN 协议存在已知漏洞（如 MS-CHAPv2）", "推荐改用 L2TP/IPsec 或 OpenVPN"),
    3306: ("中危", "MySQL 服务开放，存在弱口令或 SQL 注入风险", "限制访问来源，启用强密码，及时更新版本"),
    3389: ("高危", "RDP 服务开放，常被用于暴力破解或勒索软件入侵", "使用 VPN 访问，启用网络级别身份验证 (NLA)"),
    5900: ("中危", "VNC 服务开放，默认不加密，易被暴力破解", "使用 SSH 隧道或升级到 VNC over TLS"),
    6379: ("中危", "Redis 服务开放，可能未设置密码或存在未授权访问", "设置强密码，绑定本地或使用防火墙"),
    8080: ("低危", "HTTP 备用端口，建议升级到 HTTPS", "限制访问来源，启用身份验证"),
    8443: ("低危", "HTTPS 备用端口", "确保证书有效，禁用弱加密"),
    9200: ("中危", "Elasticsearch 服务开放，可能存在未授权访问", "配置 X-Pack 安全功能，限制访问来源"),
    11211: ("高危", "Memcached 服务开放，常被用于 DDoS 放大攻击", "禁止公网访问，使用防火墙限制来源"),
    27017: ("中危", "MongoDB 服务开放，可能存在未授权访问", "启用身份验证，绑定内网 IP，更新版本"),
    27018: ("中危", "MongoDB 分片服务开放", "同 27017 措施"),
}

DEFAULT_RISK = ("信息", "通用服务端口", "请根据实际业务评估风险，限制访问来源")

# ========== 2. 端口扫描 ==========
def scan_port(ip, port, timeout=2.0):
    """检测端口是否开放"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def get_banner(ip, port, timeout=4.0):
    """获取服务 Banner，使用 with 确保 socket 正确关闭"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            probe = PROBE_COMMANDS.get(port, b"")
            if probe:
                sock.send(probe)
                time.sleep(0.5)
            banner = b""
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                time.sleep(0.5)
                banner = sock.recv(1024)
            except ConnectionResetError:
                return "[Connection reset by peer]"
            if not banner:
                return "[No banner]"
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            banner_str = banner_str.split('\n')[0].split('\r')[0]
            if len(banner_str) > 100:
                banner_str = banner_str[:100] + "..."
            return banner_str if banner_str else "[Empty banner]"
    except socket.timeout:
        return "[Timeout]"
    except ConnectionRefusedError:
        return "[Connection refused]"
    except ConnectionResetError:
        return "[Connection reset]"
    except Exception as e:
        return f"[Error: {type(e).__name__}]"

def scan_and_identify(ip, port):
    """扫描端口并获取 banner"""
    if scan_port(ip, port):
        banner = get_banner(ip, port)
        return (port, banner)
    return None

# ========== 3. 弱口令检测 ==========
def check_ftp(ip, port, user, password, timeout=3):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        return False

def check_redis(ip, port, password, timeout=3):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if password:
            sock.send(f"AUTH {password}\r\n".encode())
            resp = sock.recv(1024).decode()
            if resp.startswith('+OK'):
                return True
        else:
            sock.send(b"PING\r\n")
            resp = sock.recv(1024).decode()
            if resp.startswith('+PONG'):
                return True
        return False
    except Exception:
        return False
    finally:
        if sock:
            sock.close()

def check_ssh(ip, port, user, password, timeout=5, retries=2):
    """
    增强版 SSH 弱口令检测：支持重试，更长超时，避免 banner 读取异常
    """
    for attempt in range(retries):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port, username=user, password=password,
                timeout=timeout,           # socket 超时
                banner_timeout=timeout,    # banner 读取超时
                allow_agent=False, look_for_keys=False
            )
            client.close()
            return True
        except (paramiko.SSHException, EOFError, socket.timeout) as e:
            if attempt == retries - 1:
                # 最后一次失败，静默返回
                return False
            time.sleep(1)   # 重试前等待
        except Exception:
            return False
    return False

WEAK_CHECKERS = {
    21: (check_ftp, 'ftp'),
    22: (check_ssh, 'ssh'),
    6379: (check_redis, 'redis'),
}

def test_weak_credentials(ip, port, service_type):
    """对指定服务进行弱口令测试，返回成功凭据列表"""
    success = []
    if service_type == 'ftp':
        for user, pwd in WEAK_CREDENTIALS:
            if check_ftp(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'ssh':
        # 只测试前3个最常用弱口令，避免过多请求触发连接限制
        for user, pwd in WEAK_CREDENTIALS[:3]:
            if check_ssh(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'redis':
        for _, pwd in WEAK_CREDENTIALS:
            if check_redis(ip, port, pwd):
                success.append(("default", pwd))
        if check_redis(ip, port, ""):
            success.append(("default", ""))
    return success

# ========== 4. 风险评级 ==========
def get_risk_info(port, weak_found=False):
    if port in RISK_RULES:
        level, description, advice = RISK_RULES[port]
    else:
        level, description, advice = DEFAULT_RISK
        service_name = SERVICE_NAMES.get(port, "未知服务")
        description = f"{service_name} 服务开放，需评估风险"
    if weak_found:
        if level == "信息":
            level = "中危"
        elif level == "低危":
            level = "中危"
        elif level == "中危":
            level = "高危"
        description += "（检测到弱口令，风险提升）"
        advice = "立即更改弱口令，并启用多因素认证。" + advice
    return level, description, advice

# ========== 5. 生成 HTML 报告 ==========
def generate_html_report(target_ip, open_ports_info, weak_results, scan_time):
    rows = ""
    for port, banner in open_ports_info:
        weak_found = port in weak_results and weak_results[port]
        risk_level, risk_desc, risk_advice = get_risk_info(port, weak_found)
        level_class = ""
        if risk_level == "严重":
            level_class = "critical"
        elif risk_level == "高危":
            level_class = "high"
        elif risk_level == "中危":
            level_class = "medium"
        elif risk_level == "低危":
            level_class = "low"
        else:
            level_class = "info"
        rows += f"""
        <tr>
            <td>{port}</td>
            <td>{banner}</td>
            <td class="{level_class}">{risk_level}</td>
            <td>{risk_desc}</td>
            <td>{risk_advice}</td>
        </tr>
        """

    weak_rows = ""
    for port, creds in weak_results.items():
        creds_str = ", ".join([f"{u}:{p}" for u, p in creds]) if creds else "无"
        weak_rows += f"<tr><td>{port}</td><td>{creds_str}</td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>InfoSpy 风险报告 - {target_ip}</title>
    <style>
        body {{ font-family: Arial; margin: 40px; background: #f0f2f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #2c3e50; border-left: 5px solid #3498db; padding-left: 15px; }}
        .info {{ background: #eef; padding: 10px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #3498db; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .footer {{ margin-top: 20px; font-size: 12px; color: #777; text-align: center; }}
        .critical {{ background-color: #8b0000; color: white; font-weight: bold; }}
        .high {{ background-color: #e74c3c; color: white; font-weight: bold; }}
        .medium {{ background-color: #f39c12; color: white; font-weight: bold; }}
        .low {{ background-color: #2ecc71; color: white; font-weight: bold; }}
        .info {{ background-color: #3498db; color: white; font-weight: bold; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 InfoSpy 安全风险评估报告</h1>
    <div class="info">
        <strong>目标：</strong> {target_ip}<br>
        <strong>扫描时间：</strong> {scan_time}<br>
        <strong>开放端口数：</strong> {len(open_ports_info)}
    </div>
    <h2>端口风险分析</h2>
    <table>
        <thead>
            <tr><th>端口</th><th>服务/Banner</th><th>风险等级</th><th>风险说明</th><th>修复建议</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    <h2>弱口令检测结果</h2>
    <table>
        <thead><tr><th>端口</th><th>成功凭据 (用户名:密码)</th></tr></thead>
        <tbody>{weak_rows}</tbody>
    </table>
    <div class="footer">本报告由 InfoSpy 生成 | 仅用于授权测试 | 风险评级基于内置规则</div>
</div>
</body>
</html>"""
    filename = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n📄 报告已保存: {filename}")

# ========== 6. 主扫描逻辑 ==========
def main(target_ip, port_list, max_workers=20, weak_mode=False):
    print(f"🔍 正在扫描 {target_ip}，共 {len(port_list)} 个端口（并发线程数: {max_workers}）")
    if weak_mode:
        print("⚠️  弱口令检测已启用（仅对支持的服务）")
    print()

    open_ports_info = []
    completed = 0
    total = len(port_list)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_and_identify, target_ip, port): port for port in port_list}
        for future in as_completed(future_to_port):
            completed += 1
            result = future.result()
            if result:
                port, banner = result
                open_ports_info.append((port, banner))
                print(f"✅ [{completed}/{total}] 端口 {port:5d} 开放 | {banner[:60]}")
            if completed % 10 == 0:
                print(f"📊 进度: {completed}/{total} ({completed*100//total}%)")

    print(f"\n✅ 扫描完成。发现 {len(open_ports_info)} 个开放端口。")

    weak_results = {}
    if weak_mode and open_ports_info:
        print("\n🔐 开始弱口令检测...")
        # 关键修复：等待 1 秒，避免触发 SSH 服务器的连接频率限制
        time.sleep(1)
        for port, _ in open_ports_info:
            if port in WEAK_CHECKERS:
                checker, stype = WEAK_CHECKERS[port]
                print(f"  尝试 {port} 端口 ({stype.upper()}) ...")
                success = test_weak_credentials(target_ip, port, stype)
                if success:
                    weak_results[port] = success
                    for user, pwd in success:
                        print(f"    ✅ 弱口令找到: {user}:{pwd}")
                else:
                    print(f"    ❌ 未发现弱口令")
            else:
                print(f"   ⚠️ 端口 {port} 暂不支持弱口令检测")

    generate_html_report(target_ip, open_ports_info, weak_results, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ========== 7. 命令行入口 ==========
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoSpy - 端口扫描与服务识别，支持弱口令检测和风险评级")
    parser.add_argument("target", help="目标 IP 或域名")
    parser.add_argument("-p", "--ports", help="端口范围，如 '22,80,443' 或 '1-1000'", default="")
    parser.add_argument("-t", "--threads", type=int, default=20, help="并发线程数 (默认 20)")
    parser.add_argument("--weak", action="store_true", help="启用弱口令检测（支持 FTP, SSH, Redis）")
    args = parser.parse_args()

    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            port_list = list(range(start, end+1))
        else:
            port_list = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
        print(f"📡 自定义端口列表: 共 {len(port_list)} 个端口")
    else:
        port_list = DEFAULT_PORTS
        print(f"📡 使用默认常见端口: 共 {len(port_list)} 个")

    try:
        ip = socket.gethostbyname(args.target)
        print(f"🌐 目标解析: {args.target} -> {ip}")
        target = ip
    except:
        target = args.target
        print(f"🌐 目标: {target}")

    main(target, port_list, max_workers=args.threads, weak_mode=args.weak)