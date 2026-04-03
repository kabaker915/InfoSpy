import socket
import time
import argparse
import ftplib
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ========== 1. 配置区域 ==========
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 11211, 9200, 27018]

# 探测命令映射（用于 banner 识别）
PROBE_COMMANDS = {
    25: b"EHLO test\r\n",
    110: b"CAPA\r\n",
    143: b"A1 CAPABILITY\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
}

# 弱口令字典（用户名, 密码）—— 用于 FTP、SSH、MySQL 等
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

# ========== 2. 端口扫描核心函数 ==========
def scan_port(ip, port, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_banner(ip, port, timeout=4.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        sock.close()
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
    finally:
        if sock:
            sock.close()

def scan_and_identify(ip, port):
    if scan_port(ip, port):
        banner = get_banner(ip, port)
        return (port, banner)
    return None

# ========== 3. 弱口令检测函数 ==========
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

def check_ssh(ip, port, user, password, timeout=3):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=user, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except Exception:
        return False

# 弱口令检测器配置：端口 -> (检测函数, 服务类型标识)
WEAK_CHECKERS = {
    21: (check_ftp, 'ftp'),
    22: (check_ssh, 'ssh'),
    6379: (check_redis, 'redis'),
    # 可继续添加 3306: (check_mysql, 'mysql') 等
}

def test_weak_credentials(ip, port, service_type):
    """对指定端口尝试弱口令，返回 (成功凭据列表)"""
    success = []
    if service_type == 'ftp':
        for user, pwd in WEAK_CREDENTIALS:
            if check_ftp(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'ssh':
        for user, pwd in WEAK_CREDENTIALS:
            if check_ssh(ip, port, user, pwd):
                success.append((user, pwd))
    elif service_type == 'redis':
        # Redis 通常无用户名，只测试密码
        for _, pwd in WEAK_CREDENTIALS:
            if check_redis(ip, port, pwd):
                success.append(("default", pwd))
        if check_redis(ip, port, ""):
            success.append(("default", ""))
    return success

# ========== 4. 生成 HTML 报告 ==========
def generate_html_report(target_ip, open_ports_info, weak_results, scan_time):
    rows = ""
    for port, banner in open_ports_info:
        rows += f"<tr><td>{port}</td><td>{banner}</td></tr>\n"
    
    weak_rows = ""
    for port, creds in weak_results.items():
        creds_str = ", ".join([f"{u}:{p}" for u, p in creds]) if creds else "无"
        weak_rows += f"<tr><td>{port}</td><td>{creds_str}</td></tr>\n"
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>InfoSpy 报告 - {target_ip}</title>
    <style>
        body {{ font-family: Arial; margin: 40px; background: #f0f2f5; }}
        .container {{ max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #2c3e50; border-left: 5px solid #3498db; padding-left: 15px; }}
        .info {{ background: #eef; padding: 10px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #3498db; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .footer {{ margin-top: 20px; font-size: 12px; color: #777; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 InfoSpy 扫描报告</h1>
    <div class="info">
        <strong>目标：</strong> {target_ip}<br>
        <strong>扫描时间：</strong> {scan_time}<br>
        <strong>开放端口数：</strong> {len(open_ports_info)}
    </div>
    <h2>端口与服务识别</h2>
    <table>
        <tr><th>端口</th><th>服务信息</th></tr>
        {rows}
    </table>
    <h2>弱口令检测结果</h2>
    <table>
        <tr><th>端口</th><th>成功凭据 (用户名:密码)</th></tr>
        {weak_rows}
    </table>
    <div class="footer">本报告由 InfoSpy 生成 | 仅用于授权测试</div>
</div>
</body>
</html>"""
    filename = f"report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n📄 报告已保存: {filename}")

# ========== 5. 主扫描逻辑 ==========
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

# ========== 6. 命令行入口 ==========
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoSpy - 端口扫描与服务识别，支持弱口令检测")
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