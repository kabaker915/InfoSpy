#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
InfoSpy - 轻量级资产侦察与风险提示工具
功能：异步端口扫描、服务识别、弱口令检测、SSL证书检测、风险评级、多格式报告生成
"""

import asyncio
import socket
import ssl
import json
import csv
import time
import argparse
import ftplib
import html
import paramiko
import urllib3
from datetime import datetime
from typing import Optional

from tqdm.asyncio import tqdm as atqdm
from tqdm import tqdm

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== 1. 配置区域 ==========
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 11211, 9200, 27018]

PROBE_COMMANDS = {
    25: b"EHLO test\r\n",
    110: b"CAPA\r\n",
    143: b"A1 CAPABILITY\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
}

WEAK_CREDENTIALS = [
    ("root", "root"), ("root", "123456"), ("root", "password"),
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("user", "user"), ("test", "test"), ("ftp", "ftp"), ("anonymous", "anonymous"),
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
    9200: "Elasticsearch", 27018: "MongoDB-Shard"
}

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

SSL_PORTS = {443, 8443, 993, 995}

# ========== 2. 异步端口扫描 ==========
async def async_scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """异步检测端口是否开放"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def async_get_banner(ip: str, port: int, timeout: float = 4.0) -> str:
    """异步获取服务 Banner"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        probe = PROBE_COMMANDS.get(port, b"")
        if probe:
            writer.write(probe)
            await writer.drain()
            await asyncio.sleep(0.5)
        banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        if not banner:
            return "[No banner]"
        banner_str = banner.decode('utf-8', errors='ignore').strip()
        banner_str = banner_str.split('\n')[0].split('\r')[0]
        if len(banner_str) > 100:
            banner_str = banner_str[:100] + "..."
        return banner_str if banner_str else "[Empty banner]"
    except asyncio.TimeoutError:
        return "[Timeout]"
    except ConnectionRefusedError:
        return "[Connection refused]"
    except ConnectionResetError:
        return "[Connection reset]"
    except OSError as e:
        return f"[Error: {type(e).__name__}]"

async def async_scan_and_identify(ip: str, port: int, sem: asyncio.Semaphore) -> Optional[tuple[int, str]]:
    """异步扫描端口并获取 banner"""
    async with sem:
        if await async_scan_port(ip, port):
            banner = await async_get_banner(ip, port)
            return (port, banner)
        return None

# ========== 3. 同步端口扫描（回退模式） ==========
def sync_scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def sync_get_banner(ip: str, port: int, timeout: float = 4.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            probe = PROBE_COMMANDS.get(port, b"")
            if probe:
                sock.send(probe)
                time.sleep(0.5)
            banner = sock.recv(1024)
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
    except OSError as e:
        return f"[Error: {type(e).__name__}]"

def sync_scan_and_identify(ip: str, port: int) -> Optional[tuple[int, str]]:
    if sync_scan_port(ip, port):
        banner = sync_get_banner(ip, port)
        return (port, banner)
    return None

# ========== 4. 弱口令检测 ==========
def check_ftp(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    ftp = ftplib.FTP()
    try:
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        try:
            ftp.quit()
        except Exception:
            pass
        return False

def check_redis(ip: str, port: int, password: str, timeout: int = 3) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if password:
                sock.send(f"AUTH {password}\r\n".encode())
                resp = sock.recv(1024).decode()
                return resp.startswith('+OK')
            else:
                sock.send(b"PING\r\n")
                resp = sock.recv(1024).decode()
                return resp.startswith('+PONG')
    except Exception:
        return False

def check_ssh(ip: str, port: int, user: str, password: str, timeout: int = 5, retries: int = 2) -> bool:
    for attempt in range(retries):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=user, password=password,
                           timeout=timeout, banner_timeout=timeout,
                           allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except (paramiko.SSHException, EOFError, socket.timeout):
            if attempt == retries - 1:
                return False
            time.sleep(1)
        except Exception:
            return False
    return False

def check_mysql(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        import pymysql
        conn = pymysql.connect(host=ip, port=port, user=user, password=password,
                               connect_timeout=timeout)
        conn.close()
        return True
    except Exception:
        return False

def check_mongodb(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        from pymongo import MongoClient
        uri = f"mongodb://{user}:{password}@{ip}:{port}/"
        client = MongoClient(uri, serverSelectionTimeoutMS=timeout * 1000)
        client.server_info()
        client.close()
        return True
    except Exception:
        return False

def check_http_basic(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        import requests
        proto = "https" if port in (443, 8443) else "http"
        r = requests.get(f"{proto}://{ip}:{port}/", auth=(user, password),
                         timeout=timeout, verify=False)
        return r.status_code not in (401, 403)
    except Exception:
        return False

WEAK_CHECKERS = {
    21: (check_ftp, 'ftp'),
    22: (check_ssh, 'ssh'),
    80: (check_http_basic, 'http'),
    443: (check_http_basic, 'http'),
    6379: (check_redis, 'redis'),
    27017: (check_mongodb, 'mongodb'),
    3306: (check_mysql, 'mysql'),
    8080: (check_http_basic, 'http'),
    8443: (check_http_basic, 'http'),
}

def test_weak_credentials(ip: str, port: int, service_type: str) -> list[tuple[str, str]]:
    success = []
    if service_type == 'ftp':
        for user, pwd in WEAK_CREDENTIALS:
            if check_ftp(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'ssh':
        for user, pwd in WEAK_CREDENTIALS[:3]:
            if check_ssh(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'redis':
        for _, pwd in WEAK_CREDENTIALS:
            if check_redis(ip, port, pwd):
                success.append(("default", pwd))
        if check_redis(ip, port, ""):
            success.append(("default", ""))
    elif service_type == 'mysql':
        for user, pwd in WEAK_CREDENTIALS:
            if check_mysql(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'mongodb':
        for user, pwd in WEAK_CREDENTIALS:
            if check_mongodb(ip, port, user, pwd):
                success.append((user, pwd))
        if check_mongodb(ip, port, "", ""):
            success.append(("default", ""))
    elif service_type == 'http':
        for user, pwd in WEAK_CREDENTIALS:
            if check_http_basic(ip, port, user, pwd):
                success.append((user, pwd))
    return success

# ========== 5. SSL 证书检测 ==========
def check_ssl_cert(ip: str, port: int, timeout: int = 5) -> dict:
    """检测 SSL 证书信息"""
    result = {
        "port": port, "has_cert": False, "issuer": "", "subject": "",
        "not_before": "", "not_after": "", "days_remaining": 0,
        "is_expired": False, "tls_versions": [], "warnings": []
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                der_cert = ssl.DER_cert_to_PEM_cert(cert)
                # 用不验证的方式获取证书详情
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
        # 使用 openssl 解析证书
        import subprocess
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout",
             "-subject", "-issuer", "-dates"],
            input=cert, capture_output=True, timeout=10
        )
        if proc.returncode == 0:
            output = proc.stdout.decode()
            for line in output.strip().split('\n'):
                if line.startswith('subject='):
                    result["subject"] = line.split('=', 1)[1].strip()
                elif line.startswith('issuer='):
                    result["issuer"] = line.split('=', 1)[1].strip()
                elif line.startswith('notBefore='):
                    result["not_before"] = line.split('=', 1)[1].strip()
                elif line.startswith('notAfter='):
                    result["not_after"] = line.split('=', 1)[1].strip()
            result["has_cert"] = True
            # 计算剩余天数
            if result["not_after"]:
                try:
                    # 格式: "May 24 12:00:00 2026 GMT"
                    expiry = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                    delta = expiry - datetime.utcnow()
                    result["days_remaining"] = delta.days
                    result["is_expired"] = delta.days < 0
                except ValueError:
                    pass
    except FileNotFoundError:
        # openssl 不可用，用 Python ssl 模块解析
        try:
            ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx3.check_hostname = False
            ctx3.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx3.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        result["has_cert"] = True
                        subject = dict(x[0] for x in cert_dict.get('subject', ()))
                        issuer = dict(x[0] for x in cert_dict.get('issuer', ()))
                        result["subject"] = subject.get('commonName', '')
                        result["issuer"] = issuer.get('organizationName', '')
                        not_after = cert_dict.get('notAfter', '')
                        result["not_after"] = not_after
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                delta = expiry - datetime.utcnow()
                                result["days_remaining"] = delta.days
                                result["is_expired"] = delta.days < 0
                            except ValueError:
                                pass
        except Exception:
            pass
    except Exception as e:
        result["warnings"].append(f"检测失败: {type(e).__name__}")
    # 生成警告
    if result["has_cert"]:
        if result["is_expired"]:
            result["warnings"].append("证书已过期")
        elif result["days_remaining"] < 30:
            result["warnings"].append(f"证书将在 {result['days_remaining']} 天后过期")
    return result

# ========== 6. 风险评级 ==========
def get_risk_info(port: int, weak_found: bool = False) -> tuple[str, str, str]:
    if port in RISK_RULES:
        level, description, advice = RISK_RULES[port]
    else:
        level, description, advice = DEFAULT_RISK
        service_name = SERVICE_NAMES.get(port, "未知服务")
        description = f"{service_name} 服务开放，需评估风险"
    if weak_found:
        if level in ("信息", "低危"):
            level = "中危"
        elif level == "中危":
            level = "高危"
        description += "（检测到弱口令，风险提升）"
        advice = "立即更改弱口令，并启用多因素认证。" + advice
    return level, description, advice

# ========== 7. 报告生成 ==========
def generate_html_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                         weak_results: dict[int, list[tuple[str, str]]],
                         ssl_results: list[dict], scan_time: str,
                         output_path: Optional[str] = None) -> str:
    rows = ""
    for port, banner in open_ports_info:
        weak_found = port in weak_results and weak_results[port]
        risk_level, risk_desc, risk_advice = get_risk_info(port, weak_found)
        level_class = {"严重": "critical", "高危": "high", "中危": "medium", "低危": "low"}.get(risk_level, "info")
        rows += f"""<tr><td>{port}</td><td>{html.escape(banner)}</td><td class="{level_class}">{risk_level}</td><td>{html.escape(risk_desc)}</td><td>{html.escape(risk_advice)}</td></tr>"""

    weak_rows = ""
    for port, creds in weak_results.items():
        creds_str = ", ".join([f"{html.escape(u)}:{html.escape(p)}" for u, p in creds]) if creds else "无"
        weak_rows += f"<tr><td>{port}</td><td>{creds_str}</td></tr>"

    ssl_rows = ""
    for r in ssl_results:
        status = "已过期" if r["is_expired"] else f"有效（{r['days_remaining']} 天）"
        warn_str = ", ".join(r["warnings"]) if r["warnings"] else "无"
        ssl_rows += f"<tr><td>{r['port']}</td><td>{html.escape(r['subject'])}</td><td>{html.escape(r['issuer'])}</td><td>{status}</td><td>{html.escape(warn_str)}</td></tr>"

    safe_target = html.escape(target_ip)
    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>InfoSpy 风险报告 - {safe_target}</title>
<style>
body{{font-family:Arial;margin:40px;background:#f0f2f5}}
.container{{max-width:1200px;margin:auto;background:white;padding:20px;border-radius:10px}}
h1{{color:#2c3e50;border-left:5px solid #3498db;padding-left:15px}}
.info{{background:#eef;padding:10px;border-radius:5px;margin:20px 0}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#3498db;color:white}}
tr:nth-child(even){{background:#f9f9f9}}
.footer{{margin-top:20px;font-size:12px;color:#777;text-align:center}}
.critical{{background-color:#8b0000;color:white;font-weight:bold}}
.high{{background-color:#e74c3c;color:white;font-weight:bold}}
.medium{{background-color:#f39c12;color:white;font-weight:bold}}
.low{{background-color:#2ecc71;color:white;font-weight:bold}}
.info{{background-color:#3498db;color:white;font-weight:bold}}
</style></head><body><div class="container">
<h1>InfoSpy 安全风险评估报告</h1>
<div class="info"><strong>目标：</strong>{safe_target}<br><strong>扫描时间：</strong>{html.escape(scan_time)}<br><strong>开放端口数：</strong>{len(open_ports_info)}</div>
<h2>端口风险分析</h2>
<table><thead><tr><th>端口</th><th>服务/Banner</th><th>风险等级</th><th>风险说明</th><th>修复建议</th></tr></thead><tbody>{rows}</tbody></table>
<h2>弱口令检测结果</h2>
<table><thead><tr><th>端口</th><th>成功凭据</th></tr></thead><tbody>{weak_rows}</tbody></table>
<h2>SSL 证书检测</h2>
<table><thead><tr><th>端口</th><th>主题</th><th>颁发者</th><th>状态</th><th>警告</th></tr></thead><tbody>{ssl_rows}</tbody></table>
<div class="footer">本报告由 InfoSpy 生成 | 仅用于授权测试</div>
</div></body></html>"""

    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

def generate_json_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                         weak_results: dict[int, list[tuple[str, str]]],
                         ssl_results: list[dict], scan_time: str,
                         output_path: Optional[str] = None) -> str:
    data = {
        "target": target_ip,
        "scan_time": scan_time,
        "open_ports": [
            {"port": port, "banner": banner, "service": SERVICE_NAMES.get(port, "未知")}
            for port, banner in open_ports_info
        ],
        "weak_credentials": {
            str(port): [{"user": u, "password": p} for u, p in creds]
            for port, creds in weak_results.items()
        },
        "ssl_certificates": ssl_results,
    }
    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return output_path

def generate_csv_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                        weak_results: dict[int, list[tuple[str, str]]],
                        ssl_results: list[dict], scan_time: str,
                        output_path: Optional[str] = None) -> str:
    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["#", "端口", "服务", "Banner", "风险等级", "风险说明", "弱口令"])
        for i, (port, banner) in enumerate(open_ports_info, 1):
            weak_found = port in weak_results and weak_results[port]
            level, desc, _ = get_risk_info(port, weak_found)
            creds = ", ".join([f"{u}:{p}" for u, p in weak_results.get(port, [])]) if weak_found else ""
            writer.writerow([i, port, SERVICE_NAMES.get(port, "未知"), banner, level, desc, creds])
        if ssl_results:
            writer.writerow([])
            writer.writerow(["#", "端口", "主题", "颁发者", "状态", "剩余天数", "警告"])
            for i, r in enumerate(ssl_results, 1):
                status = "已过期" if r["is_expired"] else "有效"
                warns = "; ".join(r["warnings"]) if r["warnings"] else ""
                writer.writerow([i, r["port"], r["subject"], r["issuer"], status, r["days_remaining"], warns])
    return output_path

REPORT_GENERATORS = {
    "html": generate_html_report,
    "json": generate_json_report,
    "csv": generate_csv_report,
}

# ========== 8. 主扫描逻辑 ==========
async def async_main(target_ip: str, port_list: list[int], max_workers: int = 20,
                     weak_mode: bool = False, ssl_mode: bool = False,
                     output_format: str = "html", output_path: Optional[str] = None) -> None:
    print(f"正在扫描 {target_ip}，共 {len(port_list)} 个端口（并发: {max_workers}）")
    if weak_mode:
        print("弱口令检测已启用")
    if ssl_mode:
        print("SSL 证书检测已启用")
    print()

    sem = asyncio.Semaphore(max_workers)
    tasks = [async_scan_and_identify(target_ip, port, sem) for port in port_list]

    open_ports_info: list[tuple[int, str]] = []
    for coro in atqdm.as_completed(tasks, total=len(tasks), desc="扫描进度"):
        result = await coro
        if result:
            port, banner = result
            open_ports_info.append((port, banner))
            print(f"  端口 {port:5d} 开放 | {banner[:60]}")

    open_ports_info.sort(key=lambda x: x[0])
    print(f"\n扫描完成，发现 {len(open_ports_info)} 个开放端口。")

    # SSL 证书检测
    ssl_results: list[dict] = []
    if ssl_mode and open_ports_info:
        ssl_ports = [p for p, _ in open_ports_info if p in SSL_PORTS]
        if ssl_ports:
            print("\n开始 SSL 证书检测...")
            for port in tqdm(ssl_ports, desc="SSL 检测"):
                result = await asyncio.to_thread(check_ssl_cert, target_ip, port)
                ssl_results.append(result)
                status = "已过期" if result["is_expired"] else f"有效（{result['days_remaining']} 天）"
                print(f"  端口 {port}: {status}")

    # 弱口令检测
    weak_results: dict[int, list[tuple[str, str]]] = {}
    if weak_mode and open_ports_info:
        print("\n开始弱口令检测...")
        time.sleep(1)
        for port, _ in tqdm(open_ports_info, desc="弱口令检测"):
            if port in WEAK_CHECKERS:
                _, stype = WEAK_CHECKERS[port]
                success = await asyncio.to_thread(test_weak_credentials, target_ip, port, stype)
                if success:
                    weak_results[port] = success
                    for user, pwd in success:
                        print(f"    弱口令找到: {user}:{pwd}")

    # 生成报告
    generator = REPORT_GENERATORS[output_format]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = await asyncio.to_thread(generator, target_ip, open_ports_info, weak_results, ssl_results, scan_time, output_path)
    print(f"\n报告已保存: {out}")

def sync_main(target_ip: str, port_list: list[int], max_workers: int = 20,
              weak_mode: bool = False, ssl_mode: bool = False,
              output_format: str = "html", output_path: Optional[str] = None) -> None:
    print(f"正在扫描 {target_ip}，共 {len(port_list)} 个端口（并发线程数: {max_workers}）")
    if weak_mode:
        print("弱口令检测已启用")
    if ssl_mode:
        print("SSL 证书检测已启用")
    print()

    from concurrent.futures import ThreadPoolExecutor, as_completed

    open_ports_info: list[tuple[int, str]] = []
    completed = 0
    total = len(port_list)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(sync_scan_and_identify, target_ip, port): port for port in port_list}
        for future in tqdm(as_completed(future_to_port), total=total, desc="扫描进度"):
            completed += 1
            result = future.result()
            if result:
                port, banner = result
                open_ports_info.append((port, banner))
                print(f"  端口 {port:5d} 开放 | {banner[:60]}")

    open_ports_info.sort(key=lambda x: x[0])
    print(f"\n扫描完成，发现 {len(open_ports_info)} 个开放端口。")

    ssl_results: list[dict] = []
    if ssl_mode and open_ports_info:
        ssl_ports = [p for p, _ in open_ports_info if p in SSL_PORTS]
        if ssl_ports:
            print("\n开始 SSL 证书检测...")
            for port in tqdm(ssl_ports, desc="SSL 检测"):
                result = check_ssl_cert(target_ip, port)
                ssl_results.append(result)
                status = "已过期" if result["is_expired"] else f"有效（{result['days_remaining']} 天）"
                print(f"  端口 {port}: {status}")

    weak_results: dict[int, list[tuple[str, str]]] = {}
    if weak_mode and open_ports_info:
        print("\n开始弱口令检测...")
        time.sleep(1)
        for port, _ in tqdm(open_ports_info, desc="弱口令检测"):
            if port in WEAK_CHECKERS:
                _, stype = WEAK_CHECKERS[port]
                success = test_weak_credentials(target_ip, port, stype)
                if success:
                    weak_results[port] = success
                    for user, pwd in success:
                        print(f"    弱口令找到: {user}:{pwd}")

    generator = REPORT_GENERATORS[output_format]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = generator(target_ip, open_ports_info, weak_results, ssl_results, scan_time, output_path)
    print(f"\n报告已保存: {out}")

# ========== 9. 命令行入口 ==========
def parse_ports(ports_str: str) -> list[int]:
    ports = []
    if '-' in ports_str:
        parts = ports_str.split('-')
        if len(parts) != 2:
            raise ValueError(f"无效的端口范围格式: {ports_str}")
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError(f"端口号必须在 1-65535 范围内: {ports_str}")
        if start > end:
            raise ValueError(f"端口范围起始值不能大于结束值: {ports_str}")
        ports = list(range(start, end + 1))
    else:
        for p in ports_str.split(','):
            p = p.strip()
            if not p:
                continue
            port_num = int(p)
            if not (1 <= port_num <= 65535):
                raise ValueError(f"端口号必须在 1-65535 范围内: {port_num}")
            ports.append(port_num)
    return ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoSpy - 端口扫描与服务识别，支持弱口令检测、SSL 证书检测和风险评级")
    parser.add_argument("target", help="目标 IP 或域名")
    parser.add_argument("-p", "--ports", help="端口范围，如 '22,80,443' 或 '1-1000'", default="")
    parser.add_argument("-t", "--threads", type=int, default=20, help="并发线程数 (默认 20)")
    parser.add_argument("--weak", action="store_true", help="启用弱口令检测（支持 FTP, SSH, Redis, MySQL, MongoDB, HTTP）")
    parser.add_argument("--ssl", action="store_true", help="启用 SSL 证书检测")
    parser.add_argument("-f", "--format", choices=["html", "json", "csv"], default="html", help="报告输出格式 (默认 html)")
    parser.add_argument("-o", "--output", help="自定义报告输出路径", default="")
    parser.add_argument("--sync", action="store_true", help="使用同步模式扫描（不使用异步）")
    args = parser.parse_args()

    if args.ports:
        try:
            port_list = parse_ports(args.ports)
        except ValueError as e:
            print(f"端口参数错误: {e}")
            exit(1)
        print(f"自定义端口列表: 共 {len(port_list)} 个端口")
    else:
        port_list = DEFAULT_PORTS
        print(f"使用默认常见端口: 共 {len(port_list)} 个")

    try:
        ip = socket.gethostbyname(args.target)
        print(f"目标解析: {args.target} -> {ip}")
        target = ip
    except (socket.gaierror, OSError):
        target = args.target
        print(f"目标: {target}")

    output = args.output if args.output else None

    if args.sync:
        sync_main(target, port_list, max_workers=args.threads, weak_mode=args.weak,
                  ssl_mode=args.ssl, output_format=args.format, output_path=output)
    else:
        asyncio.run(async_main(target, port_list, max_workers=args.threads, weak_mode=args.weak,
                               ssl_mode=args.ssl, output_format=args.format, output_path=output))
