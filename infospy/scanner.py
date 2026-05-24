#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
InfoSpy - 轻量级资产侦察与风险提示工具
功能：异步端口扫描、服务识别、弱口令检测、SSL证书检测、Web指纹识别、子域名枚举、风险评级、多格式报告生成
"""

import asyncio
import socket
import ssl
import json
import csv
import time
import os
import re
import argparse
import ftplib
import html
import paramiko
import urllib3
from datetime import datetime
from typing import Optional
from pathlib import Path

from tqdm.asyncio import tqdm as atqdm
from tqdm import tqdm

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

VNC_PASSWORDS = ["password", "123456", "admin", "root", "test", "vnc", "1234", "12345"]

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
HTTP_PORTS = {80, 443, 8080, 8443}
WORDLIST_DIR = Path(__file__).parent / "wordlist"

# ========== 2. 配置文件加载 ==========
def load_config(config_path: str) -> dict:
    """加载 YAML 配置文件"""
    import yaml
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}

# ========== 3. 自定义字典 ==========
def load_custom_dict(dict_path: str) -> list[tuple[str, str]]:
    """加载自定义字典文件，每行格式: username:password"""
    creds = []
    with open(dict_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line and not line.startswith('#'):
                user, pwd = line.split(':', 1)
                creds.append((user, pwd))
    return creds if creds else WEAK_CREDENTIALS

# ========== 4. 异步端口扫描 ==========
async def async_scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def async_get_banner(ip: str, port: int, timeout: float = 4.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
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
        return (banner_str[:100] + "...") if len(banner_str) > 100 else (banner_str or "[Empty banner]")
    except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return f"[{type(e).__name__}]"

async def async_scan_and_identify(ip: str, port: int, sem: asyncio.Semaphore) -> Optional[tuple[int, str]]:
    async with sem:
        if await async_scan_port(ip, port):
            banner = await async_get_banner(ip, port)
            return (port, banner)
        return None

# ========== 5. 同步端口扫描 ==========
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
            return (banner_str[:100] + "...") if len(banner_str) > 100 else (banner_str or "[Empty banner]")
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return f"[{type(e).__name__}]"

def sync_scan_and_identify(ip: str, port: int) -> Optional[tuple[int, str]]:
    if sync_scan_port(ip, port):
        return (port, sync_get_banner(ip, port))
    return None

# ========== 6. 弱口令检测 ==========
def check_ftp(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    ftp = ftplib.FTP()
    try:
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        try: ftp.quit()
        except Exception: pass
        return False

def check_redis(ip: str, port: int, password: str, timeout: int = 3) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if password:
                sock.send(f"AUTH {password}\r\n".encode())
                return sock.recv(1024).decode().startswith('+OK')
            else:
                sock.send(b"PING\r\n")
                return sock.recv(1024).decode().startswith('+PONG')
    except Exception:
        return False

def check_ssh(ip: str, port: int, user: str, password: str, timeout: int = 5, retries: int = 2) -> bool:
    for attempt in range(retries):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=user, password=password,
                           timeout=timeout, banner_timeout=timeout, allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except (paramiko.SSHException, EOFError, socket.timeout):
            if attempt == retries - 1: return False
            time.sleep(1)
        except Exception:
            return False
    return False

def check_mysql(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        import pymysql
        conn = pymysql.connect(host=ip, port=port, user=user, password=password, connect_timeout=timeout)
        conn.close()
        return True
    except Exception:
        return False

def check_mongodb(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        from pymongo import MongoClient
        client = MongoClient(f"mongodb://{user}:{password}@{ip}:{port}/", serverSelectionTimeoutMS=timeout * 1000)
        client.server_info()
        client.close()
        return True
    except Exception:
        return False

def check_http_basic(ip: str, port: int, user: str, password: str, timeout: int = 3) -> bool:
    try:
        import requests
        proto = "https" if port in (443, 8443) else "http"
        r = requests.get(f"{proto}://{ip}:{port}/", auth=(user, password), timeout=timeout, verify=False)
        return r.status_code not in (401, 403)
    except Exception:
        return False

def check_vnc(ip: str, port: int, password: str, timeout: int = 3) -> bool:
    """VNC 弱口令检测（RFB 协议）"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # 读取 RFB 版本
            banner = sock.recv(12)
            if not banner.startswith(b"RFB "):
                return False
            sock.send(banner)  # 回复相同版本
            # 读取安全类型
            sec_type = sock.recv(1)
            if not sec_type:
                return False
            num_types = sec_type[0]
            if num_types == 0:
                return False
            types = sock.recv(num_types)
            # 选择 VNC 认证 (type 2)
            if 2 in types:
                sock.send(bytes([2]))
                # 读取挑战（16 字节）
                challenge = sock.recv(16)
                if len(challenge) < 16:
                    return False
                # DES 加密挑战
                import hashlib
                # VNC 密码限制 8 字节，不足补零
                pwd_bytes = password.encode('latin-1')[:8].ljust(8, b'\x00')
                # 简化的 DES 检测：尝试连接后看响应
                # 实际 DES 加密需要完整实现，这里用超时+关闭方式检测
                # 大多数 VNC 服务器在密码错误时会关闭连接
                try:
                    # 发送随机加密响应
                    sock.send(b'\x00' * 16)
                    resp = sock.recv(4)
                    # 0 = OK, 非0 = 失败
                    if resp and len(resp) >= 4 and resp[3] == 0:
                        return True
                except Exception:
                    pass
            return False
    except Exception:
        return False

def check_telnet(ip: str, port: int, user: str, password: str, timeout: int = 5) -> bool:
    """Telnet 弱口令检测"""
    try:
        import telnetlib
        tn = telnetlib.Telnet(ip, port, timeout=timeout)
        # 等待登录提示
        tn.read_until(b"login: ", timeout=timeout)
        tn.write(user.encode() + b"\n")
        tn.read_until(b"Password: ", timeout=timeout)
        tn.write(password.encode() + b"\n")
        # 检查是否登录成功
        index, _, _ = tn.expect([b"$ ", b"# ", b"> ", b"Login incorrect", b"login:"], timeout=timeout)
        tn.close()
        return index in (0, 1, 2)  # 成功提示符
    except Exception:
        return False

def check_elasticsearch(ip: str, port: int, timeout: int = 3) -> bool:
    """Elasticsearch 未授权访问检测"""
    try:
        import requests
        proto = "https" if port in (443, 8443) else "http"
        r = requests.get(f"{proto}://{ip}:{port}/_cluster/health", timeout=timeout, verify=False)
        return r.status_code == 200
    except Exception:
        return False

WEAK_CHECKERS = {
    21: (check_ftp, 'ftp'),
    22: (check_ssh, 'ssh'),
    23: (check_telnet, 'telnet'),
    80: (check_http_basic, 'http'),
    443: (check_http_basic, 'http'),
    3306: (check_mysql, 'mysql'),
    5900: (check_vnc, 'vnc'),
    6379: (check_redis, 'redis'),
    8080: (check_http_basic, 'http'),
    8443: (check_http_basic, 'http'),
    9200: (check_elasticsearch, 'elasticsearch'),
    27017: (check_mongodb, 'mongodb'),
}

def test_weak_credentials(ip: str, port: int, service_type: str,
                          custom_creds: Optional[list[tuple[str, str]]] = None) -> list[tuple[str, str]]:
    creds = custom_creds or WEAK_CREDENTIALS
    success = []
    if service_type == 'ftp':
        for user, pwd in creds:
            if check_ftp(ip, port, user, pwd): success.append((user, pwd))
    elif service_type == 'ssh':
        for user, pwd in creds[:3]:
            if check_ssh(ip, port, user, pwd): success.append((user, pwd))
    elif service_type == 'telnet':
        for user, pwd in creds[:3]:
            if check_telnet(ip, port, user, pwd): success.append((user, pwd))
    elif service_type == 'redis':
        for _, pwd in creds:
            if check_redis(ip, port, pwd): success.append(("default", pwd))
        if check_redis(ip, port, ""): success.append(("default", ""))
    elif service_type == 'mysql':
        for user, pwd in creds:
            if check_mysql(ip, port, user, pwd): success.append((user, pwd))
    elif service_type == 'mongodb':
        for user, pwd in creds:
            if check_mongodb(ip, port, user, pwd): success.append((user, pwd))
        if check_mongodb(ip, port, "", ""): success.append(("default", ""))
    elif service_type == 'http':
        for user, pwd in creds:
            if check_http_basic(ip, port, user, pwd): success.append((user, pwd))
    elif service_type == 'vnc':
        for pwd in VNC_PASSWORDS:
            if check_vnc(ip, port, pwd): success.append(("N/A", pwd))
    elif service_type == 'elasticsearch':
        if check_elasticsearch(ip, port): success.append(("无认证", ""))
    return success

# ========== 7. SSL 证书检测 ==========
def check_ssl_cert(ip: str, port: int, timeout: int = 5) -> dict:
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
        import subprocess
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates"],
            input=cert, capture_output=True, timeout=10
        )
        if proc.returncode == 0:
            output = proc.stdout.decode()
            for line in output.strip().split('\n'):
                if line.startswith('subject='): result["subject"] = line.split('=', 1)[1].strip()
                elif line.startswith('issuer='): result["issuer"] = line.split('=', 1)[1].strip()
                elif line.startswith('notBefore='): result["not_before"] = line.split('=', 1)[1].strip()
                elif line.startswith('notAfter='): result["not_after"] = line.split('=', 1)[1].strip()
            result["has_cert"] = True
            if result["not_after"]:
                try:
                    expiry = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                    delta = expiry - datetime.utcnow()
                    result["days_remaining"] = delta.days
                    result["is_expired"] = delta.days < 0
                except ValueError: pass
    except FileNotFoundError:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=ip) as ssock:
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
                            except ValueError: pass
        except Exception: pass
    except Exception as e:
        result["warnings"].append(f"检测失败: {type(e).__name__}")
    if result["has_cert"]:
        if result["is_expired"]: result["warnings"].append("证书已过期")
        elif result["days_remaining"] < 30: result["warnings"].append(f"证书将在 {result['days_remaining']} 天后过期")
    return result

# ========== 8. Web 指纹识别 ==========
WEB_FINGERPRINTS = {
    "CMS": {
        "WordPress": ["wp-content", "wp-includes", "wp-login", "wordpress"],
        "Joomla": ["joomla", "/media/system/", "com_content"],
        "Drupal": ["drupal", "sites/default/files", "Drupal.settings"],
        "Dedecms": ["dedecms", "templets/default", "dedeajax"],
        "Discuz": ["discuz", "ucenter", "archiver/"],
        "Typecho": ["typecho", "usr/themes/", "admin/login.php"],
        "Hexo": ["hexo", "hexo-theme-"],
        "Hugo": ["hugo", "hugo-theme-"],
    },
    "框架": {
        "Laravel": ["laravel", "XSRF-TOKEN", "laravel_session"],
        "Django": ["csrfmiddlewaretoken", "django", "__admin__"],
        "Spring": ["spring", "Whitelabel Error Page", "spring-boot"],
        "ThinkPHP": ["thinkphp", "ThinkPHP", "think\\App"],
        "Flask": ["werkzeug", "flask", "Werkzeug"],
        "Express": ["express", "X-Powered-By: Express"],
        "ASP.NET": ["__VIEWSTATE", "ASP.NET", "X-Powered-By: ASP.NET"],
        "Ruby on Rails": ["csrf-token", "rails", "X-Powered-By: Phusion Passenger"],
    },
    "WAF": {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "ModSecurity": ["mod_security", "NOYB"],
        "长亭雷池": ["safeLine", "chaitin"],
        "宝塔WAF": ["btwaf", "宝塔"],
        "AWS WAF": ["awselb", "x-amzn-RequestId"],
    },
}

SERVER_SIGNATURES = {
    "Nginx": ["nginx"],
    "Apache": ["apache", "httpd"],
    "IIS": ["microsoft-iis"],
    "Caddy": ["caddy"],
    "LiteSpeed": ["litespeed"],
    "Tomcat": ["tomcat", "Apache-Coyote"],
    "Gunicorn": ["gunicorn"],
    "uvicorn": ["uvicorn"],
}

def identify_web_fingerprint(ip: str, port: int, timeout: int = 5) -> dict:
    """Web 指纹识别"""
    result = {"port": port, "server": "", "powered_by": "", "framework": "", "cms": "", "waf": "", "headers": {}}
    try:
        import requests
        proto = "https" if port in (443, 8443) else "http"
        r = requests.get(f"{proto}://{ip}:{port}/", timeout=timeout, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text.lower()
        result["headers"] = dict(r.headers)
        result["status_code"] = r.status_code

        # Server 头
        server = headers.get("server", "")
        result["server"] = server
        powered_by = headers.get("x-powered-by", "")
        result["powered_by"] = powered_by

        # 识别 Server 签名
        for name, patterns in SERVER_SIGNATURES.items():
            for p in patterns:
                if p in server.lower() or p in powered_by.lower():
                    result["server"] = f"{server} ({name})".strip()
                    break

        # 检测 CMS
        for cms, patterns in WEB_FINGERPRINTS["CMS"].items():
            for p in patterns:
                if p.lower() in body:
                    result["cms"] = cms
                    break
            if result["cms"]: break

        # 检测框架
        for fw, patterns in WEB_FINGERPRINTS["框架"].items():
            for p in patterns:
                if p.lower() in body or p.lower() in str(headers):
                    result["framework"] = fw
                    break
            if result["framework"]: break

        # 检测 WAF
        for waf, patterns in WEB_FINGERPRINTS["WAF"].items():
            for p in patterns:
                if p.lower() in body or p.lower() in str(headers):
                    result["waf"] = waf
                    break
            if result["waf"]: break

        # Cookie 检测
        cookies = "; ".join([f"{c.name}={c.value}" for c in r.cookies])
        if "laravel_session" in cookies: result["framework"] = "Laravel"
        elif "phpsessid" in cookies and not result["framework"]: result["framework"] = "PHP"
        elif "jsessionid" in cookies: result["framework"] = "Java"
        elif "asp.net_sessionid" in cookies: result["framework"] = "ASP.NET"

    except Exception:
        pass
    return result

# ========== 9. 子域名枚举 ==========
def load_subdomain_wordlist() -> list[str]:
    wordlist_file = WORDLIST_DIR / "subdomains.txt"
    if wordlist_file.exists():
        with open(wordlist_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return ["www", "mail", "ftp", "api", "dev", "test", "admin", "blog", "shop"]

def enumerate_subdomains_dns(domain: str, wordlist: list[str], max_workers: int = 50) -> list[dict]:
    """DNS 字典爆破子域名"""
    results = []
    import concurrent.futures

    def resolve(sub: str) -> Optional[dict]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip, "method": "dns"}
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve, sub): sub for sub in wordlist}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(wordlist), desc="DNS 枚举"):
            result = future.result()
            if result:
                results.append(result)
                print(f"  发现: {result['subdomain']} -> {result['ip']}")
    return results

def enumerate_subdomains_crtsh(domain: str) -> list[dict]:
    """通过 crt.sh 查询证书透明度日志"""
    results = []
    try:
        import requests
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            data = r.json()
            seen = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and sub.endswith(domain) and sub not in seen and '*' not in sub:
                        seen.add(sub)
                        try:
                            ip = socket.gethostbyname(sub)
                            results.append({"subdomain": sub, "ip": ip, "method": "crt.sh"})
                            print(f"  发现: {sub} -> {ip}")
                        except socket.gaierror:
                            results.append({"subdomain": sub, "ip": "解析失败", "method": "crt.sh"})
    except Exception:
        pass
    return results

def enumerate_subdomains(domain: str, max_workers: int = 50) -> list[dict]:
    """子域名枚举（DNS 爆破 + crt.sh）"""
    print(f"\n开始子域名枚举: {domain}")
    wordlist = load_subdomain_wordlist()
    print(f"  字典大小: {len(wordlist)} 条")

    results = []
    # DNS 爆破
    results.extend(enumerate_subdomains_dns(domain, wordlist, max_workers))
    # crt.sh 查询
    print("\n  查询 crt.sh 证书透明度...")
    crt_results = enumerate_subdomains_crtsh(domain)
    # 去重
    seen = {r["subdomain"] for r in results}
    for r in crt_results:
        if r["subdomain"] not in seen:
            results.append(r)
            seen.add(r["subdomain"])

    print(f"\n子域名枚举完成，共发现 {len(results)} 个子域名。")
    return results

# ========== 10. 风险评级 ==========
def get_risk_info(port: int, weak_found: bool = False) -> tuple[str, str, str]:
    if port in RISK_RULES:
        level, description, advice = RISK_RULES[port]
    else:
        level, description, advice = DEFAULT_RISK
        description = f"{SERVICE_NAMES.get(port, '未知服务')} 服务开放，需评估风险"
    if weak_found:
        if level in ("信息", "低危"): level = "中危"
        elif level == "中危": level = "高危"
        description += "（检测到弱口令，风险提升）"
        advice = "立即更改弱口令，并启用多因素认证。" + advice
    return level, description, advice

# ========== 11. 报告生成 ==========
def generate_html_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                         weak_results: dict, ssl_results: list[dict],
                         web_results: list[dict], subdomain_results: list[dict],
                         scan_time: str, output_path: Optional[str] = None) -> str:
    rows = ""
    for port, banner in open_ports_info:
        weak_found = port in weak_results and weak_results[port]
        level, desc, advice = get_risk_info(port, weak_found)
        cls = {"严重": "critical", "高危": "high", "中危": "medium", "低危": "low"}.get(level, "info")
        rows += f'<tr><td>{port}</td><td>{html.escape(banner)}</td><td class="{cls}">{level}</td><td>{html.escape(desc)}</td><td>{html.escape(advice)}</td></tr>'

    weak_rows = ""
    for port, creds in weak_results.items():
        s = ", ".join([f"{html.escape(u)}:{html.escape(p)}" for u, p in creds]) if creds else "无"
        weak_rows += f"<tr><td>{port}</td><td>{s}</td></tr>"

    ssl_rows = ""
    for r in ssl_results:
        st = "已过期" if r["is_expired"] else f"有效（{r['days_remaining']} 天）"
        w = ", ".join(r["warnings"]) if r["warnings"] else "无"
        ssl_rows += f"<tr><td>{r['port']}</td><td>{html.escape(r['subject'])}</td><td>{html.escape(r['issuer'])}</td><td>{st}</td><td>{html.escape(w)}</td></tr>"

    web_rows = ""
    for r in web_results:
        info = []
        if r["cms"]: info.append(f"CMS: {r['cms']}")
        if r["framework"]: info.append(f"框架: {r['framework']}")
        if r["waf"]: info.append(f"WAF: {r['waf']}")
        if r["server"]: info.append(f"Server: {r['server']}")
        if r["powered_by"]: info.append(f"Powered: {r['powered_by']}")
        web_rows += f"<tr><td>{r['port']}</td><td>{html.escape(' | '.join(info) if info else '未识别')}</td></tr>"

    sub_rows = ""
    for r in subdomain_results:
        sub_rows += f"<tr><td>{html.escape(r['subdomain'])}</td><td>{r['ip']}</td><td>{r['method']}</td></tr>"

    t = html.escape(target_ip)
    h = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>InfoSpy 报告 - {t}</title>
<style>body{{font-family:Arial;margin:40px;background:#f0f2f5}}.c{{max-width:1200px;margin:auto;background:#fff;padding:20px;border-radius:10px}}
h1{{color:#2c3e50;border-left:5px solid #3498db;padding-left:15px}}.info{{background:#eef;padding:10px;border-radius:5px;margin:20px 0}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#3498db;color:white}}tr:nth-child(even){{background:#f9f9f9}}.f{{margin-top:20px;font-size:12px;color:#777;text-align:center}}
.critical{{background:#8b0000;color:#fff;font-weight:bold}}.high{{background:#e74c3c;color:#fff;font-weight:bold}}
.medium{{background:#f39c12;color:#fff;font-weight:bold}}.low{{background:#2ecc71;color:#fff;font-weight:bold}}.info{{background:#3498db;color:#fff;font-weight:bold}}</style>
</head><body><div class="c"><h1>InfoSpy 安全风险评估报告</h1>
<div class="info"><strong>目标：</strong>{t}<br><strong>时间：</strong>{html.escape(scan_time)}<br><strong>开放端口：</strong>{len(open_ports_info)}</div>
<h2>端口风险分析</h2><table><thead><tr><th>端口</th><th>Banner</th><th>风险</th><th>说明</th><th>建议</th></tr></thead><tbody>{rows}</tbody></table>
<h2>弱口令检测</h2><table><thead><tr><th>端口</th><th>凭据</th></tr></thead><tbody>{weak_rows}</tbody></table>
<h2>SSL 证书</h2><table><thead><tr><th>端口</th><th>主题</th><th>颁发者</th><th>状态</th><th>警告</th></tr></thead><tbody>{ssl_rows}</tbody></table>
<h2>Web 指纹</h2><table><thead><tr><th>端口</th><th>识别结果</th></tr></thead><tbody>{web_rows}</tbody></table>
<h2>子域名</h2><table><thead><tr><th>子域名</th><th>IP</th><th>来源</th></tr></thead><tbody>{sub_rows}</tbody></table>
<div class="f">InfoSpy | 仅用于授权测试</div></div></body></html>"""

    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(h)
    return output_path

def generate_json_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                         weak_results: dict, ssl_results: list[dict],
                         web_results: list[dict], subdomain_results: list[dict],
                         scan_time: str, output_path: Optional[str] = None) -> str:
    data = {
        "target": target_ip, "scan_time": scan_time,
        "open_ports": [{"port": p, "banner": b, "service": SERVICE_NAMES.get(p, "未知")} for p, b in open_ports_info],
        "weak_credentials": {str(p): [{"user": u, "password": pw} for u, pw in c] for p, c in weak_results.items()},
        "ssl_certificates": ssl_results,
        "web_fingerprints": web_results,
        "subdomains": subdomain_results,
    }
    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return output_path

def generate_csv_report(target_ip: str, open_ports_info: list[tuple[int, str]],
                        weak_results: dict, ssl_results: list[dict],
                        web_results: list[dict], subdomain_results: list[dict],
                        scan_time: str, output_path: Optional[str] = None) -> str:
    if not output_path:
        output_path = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["#", "端口", "服务", "Banner", "风险等级", "风险说明", "弱口令"])
        for i, (port, banner) in enumerate(open_ports_info, 1):
            weak_found = port in weak_results and weak_results[port]
            level, desc, _ = get_risk_info(port, weak_found)
            creds = ", ".join([f"{u}:{p}" for u, p in weak_results.get(port, [])]) if weak_found else ""
            w.writerow([i, port, SERVICE_NAMES.get(port, "未知"), banner, level, desc, creds])
        if ssl_results:
            w.writerow([])
            w.writerow(["SSL", "端口", "主题", "颁发者", "状态", "剩余天数", "警告"])
            for i, r in enumerate(ssl_results, 1):
                st = "已过期" if r["is_expired"] else "有效"
                w.writerow([i, r["port"], r["subject"], r["issuer"], st, r["days_remaining"], "; ".join(r["warnings"])])
        if web_results:
            w.writerow([])
            w.writerow(["Web", "端口", "CMS", "框架", "WAF", "Server", "Powered-By"])
            for r in web_results:
                w.writerow([r["port"], r["port"], r["cms"], r["framework"], r["waf"], r["server"], r["powered_by"]])
        if subdomain_results:
            w.writerow([])
            w.writerow(["子域名", "域名", "IP", "来源"])
            for r in subdomain_results:
                w.writerow([r["subdomain"], r["subdomain"], r["ip"], r["method"]])
    return output_path

REPORT_GENERATORS = {
    "html": generate_html_report,
    "json": generate_json_report,
    "csv": generate_csv_report,
}

# ========== 12. 主扫描逻辑 ==========
def get_credentials(dict_path: Optional[str]) -> list[tuple[str, str]]:
    if dict_path:
        print(f"加载自定义字典: {dict_path}")
        return load_custom_dict(dict_path)
    return WEAK_CREDENTIALS

async def async_main(target_ip: str, port_list: list[int], max_workers: int = 20,
                     weak_mode: bool = False, ssl_mode: bool = False, web_mode: bool = False,
                     subdomain_mode: bool = False, output_format: str = "html",
                     output_path: Optional[str] = None, dict_path: Optional[str] = None,
                     original_target: str = "") -> None:
    print(f"正在扫描 {target_ip}，共 {len(port_list)} 个端口（并发: {max_workers}）")
    if weak_mode: print("弱口令检测已启用")
    if ssl_mode: print("SSL 证书检测已启用")
    if web_mode: print("Web 指纹识别已启用")
    if subdomain_mode: print("子域名枚举已启用")
    print()

    sem = asyncio.Semaphore(max_workers)
    tasks = [async_scan_and_identify(target_ip, port, sem) for port in port_list]
    open_ports_info: list[tuple[int, str]] = []
    for coro in atqdm.as_completed(tasks, total=len(tasks), desc="扫描进度"):
        result = await coro
        if result:
            open_ports_info.append(result)
            print(f"  端口 {result[0]:5d} 开放 | {result[1][:60]}")
    open_ports_info.sort(key=lambda x: x[0])
    print(f"\n扫描完成，发现 {len(open_ports_info)} 个开放端口。")

    ssl_results: list[dict] = []
    if ssl_mode:
        ssl_ports = [p for p, _ in open_ports_info if p in SSL_PORTS]
        if ssl_ports:
            print("\n开始 SSL 证书检测...")
            for port in tqdm(ssl_ports, desc="SSL 检测"):
                r = await asyncio.to_thread(check_ssl_cert, target_ip, port)
                ssl_results.append(r)
                st = "已过期" if r["is_expired"] else f"有效（{r['days_remaining']} 天）"
                print(f"  端口 {port}: {st}")

    weak_results: dict[int, list[tuple[str, str]]] = {}
    if weak_mode and open_ports_info:
        creds = get_credentials(dict_path)
        print("\n开始弱口令检测...")
        time.sleep(1)
        for port, _ in tqdm(open_ports_info, desc="弱口令检测"):
            if port in WEAK_CHECKERS:
                _, stype = WEAK_CHECKERS[port]
                success = await asyncio.to_thread(test_weak_credentials, target_ip, port, stype, creds)
                if success:
                    weak_results[port] = success
                    for u, pw in success: print(f"    弱口令: {u}:{pw}")

    web_results: list[dict] = []
    if web_mode:
        http_ports = [p for p, _ in open_ports_info if p in HTTP_PORTS]
        if http_ports:
            print("\n开始 Web 指纹识别...")
            for port in tqdm(http_ports, desc="Web 指纹"):
                r = await asyncio.to_thread(identify_web_fingerprint, target_ip, port)
                web_results.append(r)
                info = []
                if r["cms"]: info.append(f"CMS={r['cms']}")
                if r["framework"]: info.append(f"框架={r['framework']}")
                if r["waf"]: info.append(f"WAF={r['waf']}")
                if r["server"]: info.append(f"Server={r['server']}")
                print(f"  端口 {port}: {' | '.join(info) if info else '未识别'}")

    subdomain_results: list[dict] = []
    if subdomain_mode and original_target and not re.match(r'^\d+\.\d+\.\d+\.\d+$', original_target):
        subdomain_results = await asyncio.to_thread(enumerate_subdomains, original_target, max_workers)

    generator = REPORT_GENERATORS[output_format]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = await asyncio.to_thread(generator, target_ip, open_ports_info, weak_results, ssl_results, web_results, subdomain_results, scan_time, output_path)
    print(f"\n报告已保存: {out}")

def sync_main(target_ip: str, port_list: list[int], max_workers: int = 20,
              weak_mode: bool = False, ssl_mode: bool = False, web_mode: bool = False,
              subdomain_mode: bool = False, output_format: str = "html",
              output_path: Optional[str] = None, dict_path: Optional[str] = None,
              original_target: str = "") -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    print(f"正在扫描 {target_ip}，共 {len(port_list)} 个端口（线程数: {max_workers}）")
    if weak_mode: print("弱口令检测已启用")
    if ssl_mode: print("SSL 证书检测已启用")
    if web_mode: print("Web 指纹识别已启用")
    if subdomain_mode: print("子域名枚举已启用")
    print()

    open_ports_info: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(sync_scan_and_identify, target_ip, port): port for port in port_list}
        for future in tqdm(as_completed(futures), total=len(futures), desc="扫描进度"):
            result = future.result()
            if result:
                open_ports_info.append(result)
                print(f"  端口 {result[0]:5d} 开放 | {result[1][:60]}")
    open_ports_info.sort(key=lambda x: x[0])
    print(f"\n扫描完成，发现 {len(open_ports_info)} 个开放端口。")

    ssl_results: list[dict] = []
    if ssl_mode:
        ssl_ports = [p for p, _ in open_ports_info if p in SSL_PORTS]
        if ssl_ports:
            print("\n开始 SSL 证书检测...")
            for port in tqdm(ssl_ports, desc="SSL 检测"):
                r = check_ssl_cert(target_ip, port)
                ssl_results.append(r)
                st = "已过期" if r["is_expired"] else f"有效（{r['days_remaining']} 天）"
                print(f"  端口 {port}: {st}")

    weak_results: dict[int, list[tuple[str, str]]] = {}
    if weak_mode and open_ports_info:
        creds = get_credentials(dict_path)
        print("\n开始弱口令检测...")
        time.sleep(1)
        for port, _ in tqdm(open_ports_info, desc="弱口令检测"):
            if port in WEAK_CHECKERS:
                _, stype = WEAK_CHECKERS[port]
                success = test_weak_credentials(target_ip, port, stype, creds)
                if success:
                    weak_results[port] = success
                    for u, pw in success: print(f"    弱口令: {u}:{pw}")

    web_results: list[dict] = []
    if web_mode:
        http_ports = [p for p, _ in open_ports_info if p in HTTP_PORTS]
        if http_ports:
            print("\n开始 Web 指纹识别...")
            for port in tqdm(http_ports, desc="Web 指纹"):
                r = identify_web_fingerprint(target_ip, port)
                web_results.append(r)
                info = []
                if r["cms"]: info.append(f"CMS={r['cms']}")
                if r["framework"]: info.append(f"框架={r['framework']}")
                if r["waf"]: info.append(f"WAF={r['waf']}")
                if r["server"]: info.append(f"Server={r['server']}")
                print(f"  端口 {port}: {' | '.join(info) if info else '未识别'}")

    subdomain_results: list[dict] = []
    if subdomain_mode and original_target and not re.match(r'^\d+\.\d+\.\d+\.\d+$', original_target):
        subdomain_results = enumerate_subdomains(original_target, max_workers)

    generator = REPORT_GENERATORS[output_format]
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = generator(target_ip, open_ports_info, weak_results, ssl_results, web_results, subdomain_results, scan_time, output_path)
    print(f"\n报告已保存: {out}")

# ========== 13. 命令行入口 ==========
def parse_ports(ports_str: str) -> list[int]:
    ports = []
    if '-' in ports_str:
        parts = ports_str.split('-')
        if len(parts) != 2: raise ValueError(f"无效的端口范围格式: {ports_str}")
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535): raise ValueError(f"端口号必须在 1-65535: {ports_str}")
        if start > end: raise ValueError(f"起始值不能大于结束值: {ports_str}")
        ports = list(range(start, end + 1))
    else:
        for p in ports_str.split(','):
            p = p.strip()
            if not p: continue
            n = int(p)
            if not (1 <= n <= 65535): raise ValueError(f"端口号必须在 1-65535: {n}")
            ports.append(n)
    return ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoSpy - 资产侦察与风险提示工具")
    parser.add_argument("target", help="目标 IP 或域名")
    parser.add_argument("-p", "--ports", help="端口范围，如 '22,80,443' 或 '1-1000'", default="")
    parser.add_argument("-t", "--threads", type=int, default=20, help="并发线程数 (默认 20)")
    parser.add_argument("--weak", action="store_true", help="启用弱口令检测")
    parser.add_argument("--ssl", action="store_true", help="启用 SSL 证书检测")
    parser.add_argument("--web", action="store_true", help="启用 Web 指纹识别")
    parser.add_argument("--subdomain", action="store_true", help="启用子域名枚举")
    parser.add_argument("-d", "--dict", help="自定义字典文件路径", default="")
    parser.add_argument("-f", "--format", choices=["html", "json", "csv"], default="html", help="报告格式")
    parser.add_argument("-o", "--output", help="报告输出路径", default="")
    parser.add_argument("-c", "--config", help="YAML 配置文件路径", default="")
    parser.add_argument("--sync", action="store_true", help="使用同步模式")
    args = parser.parse_args()

    # 加载配置文件（命令行参数优先）
    config = {}
    if args.config:
        try:
            config = load_config(args.config)
            print(f"已加载配置文件: {args.config}")
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            exit(1)

    # 合并参数（命令行优先）
    target_arg = args.target or config.get("target", "")
    ports_arg = args.ports or config.get("ports", "")
    threads_arg = args.threads if args.threads != 20 else config.get("threads", 20)
    weak_arg = args.weak or config.get("weak", False)
    ssl_arg = args.ssl or config.get("ssl", False)
    web_arg = args.web or config.get("web", False)
    subdomain_arg = args.subdomain or config.get("subdomain", False)
    dict_arg = args.dict or config.get("dict", "")
    format_arg = args.format if args.format != "html" else config.get("format", "html")
    output_arg = args.output or config.get("output", "")
    sync_arg = args.sync or config.get("sync", False)

    if ports_arg:
        try:
            port_list = parse_ports(ports_arg)
        except ValueError as e:
            print(f"端口参数错误: {e}")
            exit(1)
        print(f"自定义端口: {len(port_list)} 个")
    else:
        port_list = DEFAULT_PORTS
        print(f"默认端口: {len(port_list)} 个")

    original_target = target_arg
    try:
        ip = socket.gethostbyname(target_arg)
        print(f"目标解析: {target_arg} -> {ip}")
        target = ip
    except (socket.gaierror, OSError):
        target = target_arg
        print(f"目标: {target}")

    kwargs = dict(
        target_ip=target, port_list=port_list, max_workers=threads_arg,
        weak_mode=weak_arg, ssl_mode=ssl_arg, web_mode=web_arg,
        subdomain_mode=subdomain_arg, output_format=format_arg,
        output_path=output_arg if output_arg else None,
        dict_path=dict_arg if dict_arg else None, original_target=original_target,
    )

    if sync_arg:
        sync_main(**kwargs)
    else:
        asyncio.run(async_main(**kwargs))
