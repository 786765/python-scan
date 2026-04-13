import requests
from datetime import datetime
import re
import threading
from queue import Queue
import urllib3
import socket


# 🔴 关闭SSL警告，解决verify=False的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 🔴 关键修复：强制禁用代理，解决ProxyError
requests.adapters.DEFAULT_RETRIES = 5  # 增加重试次数
session = requests.Session()
session.trust_env = False  # 不使用系统代理
proxies = {"http": None, "https": None}  # 显式禁用代理

# 配置
THREAD_NUM = 15  # 降低线程数，避免被封
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
for port in port_list:
    port = int(port.replace('\n', ''))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        s.close()
        print(f'\033[32m端口：{port} ON\033[0m')
    except:
        print(f'\033[31m端口：{port} ON\033[0m')

# 全局队列与结果
q = Queue()
alive_urls = []
vuln_results = []
lock = threading.Lock()

# ===================== 子域名收集 =====================
def get_subdomains(domain):
    subdomains = set()
    # 1. crt.sh 证书收集子域名（增加超时）
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = session.get(url, headers=headers, timeout=30, proxies=proxies, verify=False)
        res.raise_for_status()
        data = res.json()
        for item in data:
            name = item["name_value"].strip()
            if "\n" in name:
                for s in name.split("\n"):
                    s = s.strip()
                    if domain in s and not s.startswith("*"):
                        subdomains.add(s)
            else:
                if domain in name and not name.startswith("*"):
                    subdomains.add(name)
    except Exception as e:
        print(f"[crt.sh] 超时/出错: {str(e)[:100]}")  # 截断长错误

    # 2. 主页爬取子域名
    try:
        url = f"https://www.{domain}"
        res = session.get(url, headers=headers, timeout=15, proxies=proxies, verify=False)
        res.raise_for_status()
        regex = rf"[a-zA-Z0-9-]+\.{re.escape(domain)}"
        results = re.findall(regex, res.text)
        for s in results:
            subdomains.add(s)
    except Exception as e:
        print(f"[主页爬取子域名] 出错: {str(e)[:100]}")

    # 3. 补充常见子域名兜底
    common_subs = ["www", "m", "api", "admin", "test", "dev", "blog", "shop", "pay", "login", "manage"]
    for s in common_subs:
        subdomains.add(f"{s}.{domain}")

    return sorted(list(set(subdomains)))  # 去重+排序

# ===================== 子域名存活检测 =====================
def check_alive():
    while not q.empty():
        sub = q.get()
        for proto in ["https://", "http://"]:
            url = proto + sub
            try:
                r = session.get(
                    url, headers=headers, timeout=5, proxies=proxies,
                    verify=False, allow_redirects=True
                )
                if r.status_code in [200, 301, 302, 403, 404]:
                    with lock:
                        alive_urls.append(url)
                        print(f"\033[32m[存活] {url}\033[0m")
                    break
            except:
                continue
        q.task_done()

# ===================== 网站漏洞检测（核心新增） =====================
def scan_web_vuln(url):
    """
    检测常见Web漏洞：SQL注入、XSS、目录遍历
    """
    vuln_list = []
    # 1. SQL注入检测（带参数的URL）
    sql_payloads = [
        "?id=1' AND 1=1--", "?id=1' AND 1=2--",
        "?id=1' OR '1'='1", "?id=1' UNION SELECT 1,2,3--"
    ]
    for payload in sql_payloads:
        test_url = url + payload
        try:
            r = session.get(test_url, headers=headers, timeout=5, proxies=proxies, verify=False)
            # 简单判断：页面内容差异、数据库报错
            if "mysql" in r.text.lower() or "syntax" in r.text.lower() or "error" in r.text.lower():
                vuln_list.append(f"[SQL注入风险] {test_url}")
        except:
            continue

    # 2. XSS跨站脚本检测
    xss_payload = "<script>alert('xss')</script>"
    test_url = f"{url}?search={xss_payload}"
    try:
        r = session.get(test_url, headers=headers, timeout=5, proxies=proxies, verify=False)
        if xss_payload in r.text:
            vuln_list.append(f"[XSS风险] {test_url} (payload未过滤)")
    except:
        pass

    # 3. 目录遍历/敏感文件检测
    dir_payloads = [
        "/etc/passwd", "/windows/win.ini", "/.env", "/.git/config",
        "/phpinfo.php", "/admin.php", "/backup.zip"
    ]
    for payload in dir_payloads:
        test_url = url + "/" + payload
        try:
            r = session.get(test_url, headers=headers, timeout=5, proxies=proxies, verify=False)
            if r.status_code == 200 and len(r.text) > 100:
                vuln_list.append(f"[敏感文件/目录遍历风险] {test_url}")
        except:
            continue

    # 4. 弱口令入口检测（补充原代码的登录页检测）
    login_paths = ["/login", "/admin", "/manage", "/backend"]
    for path in login_paths:
        test_url = url + path
        try:
            r = session.get(test_url, headers=headers, timeout=5, proxies=proxies, verify=False)
            if r.status_code == 200 and "login" in r.text.lower():
                vuln_list.append(f"[登录入口] {test_url} (可尝试弱口令爆破)")
        except:
            continue

    # 写入全局结果
    with lock:
        vuln_results.extend(vuln_list)
        for vuln in vuln_list:
            print(f"\033[31m[漏洞] {vuln}\033[0m")

# ===================== 服务器基础漏洞检测（核心新增） =====================
def scan_server_vuln(url):
    """
    检测服务器基础漏洞/配置问题：
    1. 服务器信息泄露
    2. 不安全的HTTP方法
    3. 敏感响应头泄露
    """
    try:
        r = session.get(url, headers=headers, timeout=8, proxies=proxies, verify=False)
        server = r.headers.get("Server", "未知")
        vuln_list = []

        # 1. 服务器版本泄露（Apache/Nginx版本号）
        if server != "未知" and any(v in server for v in ["Apache/", "Nginx/", "IIS/"]):
            vuln_list.append(f"[服务器版本泄露] {url} -> Server: {server}")

        # 2. 不安全的HTTP方法检测（OPTIONS）
        try:
            opt_r = session.options(url, headers=headers, timeout=5, proxies=proxies, verify=False)
            allow_methods = opt_r.headers.get("Allow", "")
            if any(m in allow_methods for m in ["PUT", "DELETE", "TRACE"]):
                vuln_list.append(f"[不安全HTTP方法] {url} 允许: {allow_methods}")
        except:
            pass

        # 3. 敏感响应头检测
        security_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
        for h in security_headers:
            if h not in r.headers:
                vuln_list.append(f"[安全头缺失] {url} 缺少 {h}")

        # 4. 目录索引开启检测
        if "Index of /" in r.text and r.status_code == 200:
            vuln_list.append(f"[目录索引开启] {url} 可直接浏览目录")

        # 写入全局结果
        with lock:
            vuln_results.extend(vuln_list)
            for vuln in vuln_list:
                print(f"\033[31m[服务器漏洞] {vuln}\033[0m")

    except Exception as e:
        print(f"[服务器检测] {url} 出错: {str(e)[:50]}")

# ===================== 多线程漏洞扫描 =====================
def vuln_scan_worker():
    while not q.empty():
        url = q.get()
        scan_web_vuln(url)
        scan_server_vuln(url)
        q.task_done()

# ===================== 主站信息获取 =====================
def get_info(domain):
    url = f"https://www.{domain}"
    try:
        r = session.get(url, headers=headers, timeout=10, proxies=proxies, verify=False)
        r.encoding = "utf-8"
        title = re.findall(r"<title.*?>(.*?)</title>", r.text, re.I | re.S)
        title = title[0].strip() if title else "无标题"
        print("\n===== 网站基本信息 =====")
        print(f"网址: {url}")
        print(f"状态码: {r.status_code}")
        print(f"标题: {title}")
        print(f"Server: {r.headers.get('Server', '未知')}")
    except Exception as e:
        print(f"获取信息失败: {str(e)[:100]}")

# ===================== 主函数 =====================
if __name__ == "__main__":
    # 只需要输入一次
    target = input("请输入目标网站域名（如 baidu.com）：").strip()
    if not target:
        print("域名不能为空！")
        exit()

    print("\n[+] 正在收集子域名...")
    subs = get_subdomains(target)
    print(f"[+] 共收集子域名：{len(subs)} 个")

    if not subs:
        print("❌ 无子域名可扫描，退出程序")
        exit()

    # 多线程检测存活
    for s in subs:
        q.put(s)

    print("\n[+] 多线程检测存活中...")
    for _ in range(THREAD_NUM):
        t = threading.Thread(target=check_alive, daemon=True)
        t.start()
    q.join()

    print(f"\n[+] 存活站点共：{len(alive_urls)} 个")

    # 多线程漏洞扫描（Web+服务器）
    print("\n[+] 开始漏洞扫描（Web漏洞+服务器漏洞）...")
    for url in alive_urls:
        q.put(url)

    for _ in range(THREAD_NUM):
        t = threading.Thread(target=vuln_scan_worker, daemon=True)
        t.start()
    q.join()

    # 保存所有结果到文件
    result_file = "vuln_scan_result.txt"
    with open(result_file, "w", encoding="utf-8") as f:
        f.write(f"=== {target} 漏洞扫描结果 ===\n")
        from datetime import datetime
        f.write(f"扫描时间: {datetime.now()}\n\n")
        f.write("=== 存活站点 ===\n")
        for url in alive_urls:
            f.write(url + "\n")
        f.write("\n=== 发现的漏洞 ===\n")
        if vuln_results:
            for v in vuln_results:
                f.write(v + "\n")
        else:
            f.write("未发现明显漏洞\n")

    # 主站信息
    get_info(target)

    print(f"\n✅ 全部完成！所有结果已保存到 {result_file}")
    print(f"📊 共发现 {len(vuln_results)} 个潜在风险点")