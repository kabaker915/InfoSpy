import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

# 常见端口列表
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 11211, 9200, 27018]

# 服务探测的字典：端口 -> (发送的探测字符串, 预期编码)
PROBE_MAP = {
    22: (b"", "utf-8"),           # SSH 直接读 banner
    25: (b"EHLO test\r\n", "ascii"),
    80: (b"HEAD / HTTP/1.0\r\n\r\n", "utf-8"),
    110: (b"CAPA\r\n", "ascii"),
    143: (b"A1 CAPABILITY\r\n", "ascii"),
    443: (b"", "utf-8"),           # SSL 握手复杂，暂不处理
}

def scan_port(ip, port, timeout=2.0):
    """检测端口是否开放"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_banner(ip, port, timeout=3.0):
    """尝试获取端口 banner 或服务响应"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # 如果该端口有预定义的探测数据，则发送
        if port in PROBE_MAP:
            probe_data, encoding = PROBE_MAP[port]
            if probe_data:
                sock.send(probe_data)
        
        # 接收 banner（最多 1024 字节）
        banner = sock.recv(1024).decode(encoding, errors='ignore').strip()
        sock.close()
        
        # 清理换行和多余空格
        banner = banner.replace('\r', ' ').replace('\n', ' ').strip()
        return banner if banner else "[No banner]"
    except Exception:
        return "[Banner read failed]"

def scan_and_identify(ip, port):
    """扫描端口并在开放时识别服务"""
    if scan_port(ip, port):
        banner = get_banner(ip, port)
        return port, banner
    return None

def generate_html_report(target_ip, open_ports_with_banner):
    """生成美观的 HTML 报告"""
    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>InfoSpy 扫描报告 - {target_ip}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .target {{ background: #ecf0f1; padding: 10px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #3498db; color: white; }}
        tr:nth-child(even) {{ background: #f2f2f2; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 InfoSpy 安全扫描报告</h1>
    <div class="target">
        <strong>目标地址：</strong> {target_ip}<br>
        <strong>扫描时间：</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <strong>开放端口数：</strong> {len(open_ports_with_banner)}
    </div>
    <table>
        <tr><th>端口</th><th>服务/版本信息</th></tr>
        {''.join(f'<tr><td>{port}</td><td>{banner}</td></tr>' for port, banner in open_ports_with_banner)}
    </table>
    <div class="footer">
        本报告由 InfoSpy 自动生成 | 仅用于授权测试
    </div>
</div>
</body>
</html>
    """
    filename = f"report_{target_ip}_{time.strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_template)
    print(f"\n📄 HTML 报告已生成: {filename}")

def main(target_ip):
    print(f"正在扫描 {target_ip} 的 {len(COMMON_PORTS)} 个常见端口...\n")
    open_ports_info = []   # 存储 (port, banner)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(scan_and_identify, target_ip, port): port for port in COMMON_PORTS}
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                port, banner = result
                open_ports_info.append((port, banner))
                print(f"✅ 端口 {port:5d} 开放  |  服务识别: {banner[:60]}")
    
    print(f"\n扫描完成。共发现 {len(open_ports_info)} 个开放端口。")
    if open_ports_info:
        generate_html_report(target_ip, open_ports_info)



if __name__ == "__main__":
    target = "scanme.nmap.org"
    main(target)