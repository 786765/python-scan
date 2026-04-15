from flask import Flask, render_template_string, request, jsonify
import threading
import webview
import time
import requests
from datetime import datetime
import urllib3
import os
import logging
import re
import asyncio
from aiohttp import ClientSession, TCPConnector
from urllib.parse import urljoin
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ====================== 全局配置 ======================
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

# 全局状态（线程安全）
log_list = []
lock = threading.Lock()
is_scanning = False
THREAD_NUM = 10

# 请求配置
session = requests.Session()
session.verify = False
session.trust_env = False
proxies = {"http": None, "https": None}
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
}

# 漏洞检测规则
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL,VERSION()--",
    "' AND (SELECT COUNT(*) FROM users) > 0--"
]
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>",
    "<svg onload='alert(1)'>", "<body onload='alert(1)'>"
]
DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "../../../../windows/system32/drivers/etc/hosts",
    "../../../../boot.ini"
]
SENSITIVE_FILES = [
    ".git/config", ".env", "robots.txt", "sitemap.xml",
    "phpinfo.php", "info.php", "test.php"
]


# ====================== 日志工具 ======================
def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {msg}"
    with lock:
        log_list.append(log_msg)
    print(log_msg)


# ====================== HTML前端（中间字母已改为粉色） ======================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Eclipse Veil 安全控制台</title>
    <style>
        body {
            background-image: url('/static/8876.jpg');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            color: #0ff;
            font-family: 'Courier New', monospace;
            overflow: hidden;
            margin: 0;
            padding: 2vh;
            text-align: center;
        }
        h1 {
            font-size: 28px;
            margin-bottom: 30px;
            text-shadow: 0 0 15px #0ff;
            animation: glitch 0.2s infinite alternate, colorflash 1.5s infinite linear;
        }

        /* 中间 ASCII 字母改为紫色*/
        pre {
             font-size: 20px;
             line-height: 1.2;
             font-weight: bold;
             margin-bottom: 20px;
             color: #FF00FF;
             text-shadow: 
                 0 0 4px #FF00FF,
                 0 0 8px #FF00FF,
                 0 0 12px #FF1493,
                 0 0 16px #FF69B4;
             animation: pulse 1.5s infinite alternate;
         }
         @keyframes pulse {
             0% { opacity: 0.8; }
             100% { opacity: 1; text-shadow: 0 0 6px #FF00FF, 0 0 12px #FF00FF; }
         }

        @keyframes colorflash {
            0% { color: #0ff; text-shadow: 0 0 10px #0ff,0 0 30px #0ff; }
            20% { color: #ff0; text-shadow: 0 0 10px #ff0,0 0 30px #ff0; }
            40% { color: #0f0; text-shadow: 0 0 10px #0f0,0 0 30px #0f0; }
            60% { color: #f0f; text-shadow: 0 0 10px #f0f,0 0 30px #f0f; }
            80% { color: #f30; text-shadow: 0 0 10px #f30,0 0 30px #f30; }
            100%{ color: #0ff; text-shadow: 0 0 10px #0ff,0 0 30px #0ff; }
        }
        @keyframes glitch {
            0% { transform: translate(0); }
            50% { transform: translate(-1px,1px); }
            100% { transform: translate(1px,-1px); }
        }
        .container {
            position: relative;
            z-index: 10;
        }
        #targetInput {
            background: #111;
            border: 2px solid #0ff;
            color: #fff;
            padding: 12px 20px;
            width: 350px;
            font-size: 16px;
            margin: 10px;
            border-radius: 4px;
            outline: none;
        }
        .btn-start {
            background: #111;
            border: 2px solid #0f0;
            color: #0f0;
            padding: 12px 25px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin: 10px;
            transition: 0.3s;
            text-shadow: 0 0 10px #0f0;
            border-radius: 4px;
        }
        .btn-start:hover {
            background: #0f0;
            color: #000;
            box-shadow: 0 0 20px #0f0;
        }
        .btn-start:disabled {
            border-color: #666;
            color: #666;
            cursor: not-allowed;
            background: #111;
            box-shadow: none;
        }
        #resultArea {
            margin-top: 20px;
            border: 1px solid #333;
            background: rgba(0,0,0,0.7);
            height: 350px;
            width: 85%;
            margin-left: auto;
            margin-right: auto;
            padding: 15px;
            text-align: left;
            overflow-y: auto;
            font-size: 13px;
            color: #fff;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .scan-options {
            margin: 20px auto;
            text-align: left;
            width: 380px;
            background: rgba(0,0,0,0.7);
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #333;
        }
        .scan-options label {
            display: block;
            margin: 8px 0;
            cursor: pointer;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ECLIPSE VEIL - 安全扫描控制台</h1>
        <pre>
 ███████╗██╗     ██╗███████╗██████╗ ██╗   ██╗███████╗
 ██╔════╝██║     ██║██╔════╝██╔══██╗██║   ██║██╔════╝
 ███████╗██║     ██║█████╗  ██████╔╝██║   ██║███████╗
 ╚════██║██║     ██║██╔══╝  ██╔══██╗██║   ██║╚════██║
 ███████║███████╗██║███████╗██║  ██║╚██████╔╝███████║
 ╚══════╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
        </pre>

        <div class="scan-options">
            <label><input type="checkbox" id="opt1" checked> 🌐 子域名收集</label>
            <label><input type="checkbox" id="opt2" checked> 🔍 存活URL探测</label>
            <label><input type="checkbox" id="opt3" checked> ⚠️ 漏洞扫描（SQL/XSS）</label>
            <label><input type="checkbox" id="opt4" checked> 🔐 敏感文件扫描</label>
            <label><input type="checkbox" id="opt5" checked> 📄 生成PDF报告</label>
        </div>

        <input type="text" id="targetInput" placeholder="例如：baidu.com" value="baidu.com">
        <button class="btn-start" id="startBtn" onclick="startScan()">🖤 启动安全扫描</button>
        <div id="resultArea">等待扫描开始...</div>
    </div>

    <script>
        let isScanning = false;
        const resultArea = document.getElementById('resultArea');
        const startBtn = document.getElementById('startBtn');
        const targetInput = document.getElementById('targetInput');

        function pollLogs() {
            fetch('/api/get_logs')
            .then(res => res.json())
            .then(data => {
                if (data.logs) {
                    resultArea.textContent = data.logs.join('\\n');
                    resultArea.scrollTop = resultArea.scrollHeight;
                }
                if (isScanning) setTimeout(pollLogs, 700);
            }).catch(()=>{ if(isScanning) setTimeout(pollLogs,1000) })
        }

        function startScan() {
            const target = targetInput.value.trim();
            if (!target) { alert('请输入目标'); return; }
            if (isScanning) { alert('正在扫描中'); return; }

            isScanning = true;
            startBtn.disabled = true;
            startBtn.textContent = '🔄 扫描中...';
            resultArea.textContent = `[系统] 开始扫描：${target}\\n`;

            const options = {
                subdomain: document.getElementById('opt1').checked,
                alive: document.getElementById('opt2').checked,
                vuln: document.getElementById('opt3').checked,
                sensitive: document.getElementById('opt4').checked,
                pdf: document.getElementById('opt5').checked
            };

            fetch('/api/start_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, options })
            }).then(res=>res.json()).then(data=>{
                if (data.status === 'success') {
                    resultArea.textContent += '[系统] 任务已启动\\n';
                    pollLogs();
                } else {
                    resultArea.textContent += '[错误] 启动失败\\n';
                    resetScanState();
                }
            }).catch(()=>{ resetScanState() });
        }

        function resetScanState() {
            isScanning = false;
            startBtn.disabled = false;
            startBtn.textContent = '🖤 启动安全扫描';
        }

        const observer = new MutationObserver(()=>{
            if (resultArea.textContent.includes('扫描已完成，可重新发起扫描')) {
                resetScanState();
            }
        });
        observer.observe(resultArea, { childList:true, subtree:true });
    </script>
</body>
</html>
'''


# ====================== 子域名收集 ======================
def get_subdomains(domain):
    subdomains = set()
    log("=== 子域名收集 ===")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = session.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            for item in resp.json():
                names = item.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name.endswith(domain) and not name.startswith("*"):
                        subdomains.add(name)
    except Exception as e:
        log(f"crt.sh 失败：{e}")
    common = ["www", "m", "api", "admin", "test", "dev", "blog", "shop", "pay", "login", "mail", "ftp", "cdn", "app",
              "wap"]
    for s in common: subdomains.add(f"{s}.{domain}")
    log(f"收集完成：{len(subdomains)} 个")
    return sorted(list(subdomains))


# ====================== 存活检测 ======================
async def check_alive(session, url):
    try:
        async with session.get(url, timeout=8, ssl=False) as r:
            if r.status in [200, 301, 302, 403]:
                log(f"[存活] {url}")
                return url
    except:
        pass
    return None


async def check_alive_batch(urls):
    alive = []
    conn = TCPConnector(limit=THREAD_NUM, ssl=False)
    async with ClientSession(connector=conn) as s:
        tasks = [check_alive(s, u) for u in urls]
        res = await asyncio.gather(*tasks)
        alive = [x for x in res if x]
    return alive


def get_alive_urls(subs):
    log("=== 存活检测 ===")
    urls = [f"https://{s}" for s in subs] + [f"http://{s}" for s in subs]
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(check_alive_batch(urls))
    finally:
        loop.close()


# ====================== 漏洞扫描 ======================
async def scan_sql(session, url):
    for p in SQL_INJECTION_PAYLOADS:
        try:
            u = urljoin(url, f"?id={p}")
            async with session.get(u, timeout=6, ssl=False) as r:
                t = await r.text()
                if re.search(r"MySQL syntax|SQL syntax|ORA-", t, re.I):
                    log(f"[SQL注入] {u}", "CRITICAL")
                    return {"type": "SQL注入", "url": u, "payload": p}
        except:
            pass
    return None


async def scan_xss(session, url):
    for p in XSS_PAYLOADS:
        try:
            u = urljoin(url, f"?q={p}")
            async with session.get(u, timeout=6, ssl=False) as r:
                t = await r.text()
                if p in t:
                    log(f"[XSS] {u}", "CRITICAL")
                    return {"type": "XSS", "url": u, "payload": p}
        except:
            pass
    return None


async def vuln_scan_batch(urls):
    vuln = []
    conn = TCPConnector(limit=THREAD_NUM, ssl=False)
    async with ClientSession(connector=conn) as s:
        tasks = []
        for u in urls:
            tasks.append(scan_sql(s, u))
            tasks.append(scan_xss(s, u))
        r = await asyncio.gather(*tasks)
        vuln = [x for x in r if x]
    return vuln


def detect_vulns(urls):
    log("=== 漏洞扫描 ===")
    if not urls: return []
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(vuln_scan_batch(urls))
    finally:
        loop.close()


# ====================== 敏感文件 ======================
async def scan_sensitive(session, url):
    res = []
    for f in SENSITIVE_FILES:
        try:
            u = urljoin(url, f)
            async with session.get(u, timeout=6, ssl=False) as r:
                if r.status == 200:
                    log(f"[敏感文件] {u}", "WARN")
                    res.append({"type": "敏感文件", "url": u})
        except:
            pass
    return res


async def sensitive_batch(urls):
    out = []
    conn = TCPConnector(limit=THREAD_NUM, ssl=False)
    async with ClientSession(connector=conn) as s:
        tasks = [scan_sensitive(s, u) for u in urls]
        r = await asyncio.gather(*tasks)
        for x in r: out.extend(x)
    return out


def detect_sensitive(urls):
    log("=== 敏感文件扫描 ===")
    if not urls: return []
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(sensitive_batch(urls))
    finally:
        loop.close()


# ====================== PDF报告 ======================
def gen_pdf(results, target):
    log("=== 生成PDF报告 ===")
    try:
        fn = f"EclipseVeil_{target}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        doc = SimpleDocTemplate(fn, pagesize=letter)
        styles = getSampleStyleSheet()
        ele = []
        ele.append(Paragraph("Eclipse Veil 扫描报告", styles["Title"]))
        ele.append(Paragraph(f"目标：{target}", styles["Heading2"]))
        ele.append(Paragraph(f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyText"]))
        ele.append(Paragraph("=" * 50, styles["BodyText"]))

        if results.get("subs"):
            ele.append(Paragraph(f"子域名：{len(results['subs'])} 个", styles["Heading2"]))
            data = [["序号", "子域名"]]
            for i, x in enumerate(results["subs"], 1): data.append([str(i), x])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black)
            ]))
            ele.append(t)

        if results.get("alive"):
            ele.append(Paragraph(f"存活URL：{len(results['alive'])} 个", styles["Heading2"]))
            data = [["序号", "URL"]]
            for i, x in enumerate(results["alive"], 1): data.append([str(i), x])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black)
            ]))
            ele.append(t)

        if results.get("vulns"):
            ele.append(Paragraph(f"漏洞：{len(results['vulns'])} 个", styles["Heading2"]))
            data = [["序号", "类型", "URL", "Payload"]]
            for i, x in enumerate(results["vulns"], 1):
                data.append([str(i), x.get("type"), x.get("url"), x.get("payload", "-")])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black)
            ]))
            ele.append(t)

        if results.get("sensitive"):
            ele.append(Paragraph(f"敏感文件：{len(results['sensitive'])} 个", styles["Heading2"]))
            data = [["序号", "类型", "URL"]]
            for i, x in enumerate(results["sensitive"], 1): data.append([str(i), x["type"], x["url"]])
            t = Table(data)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black)
            ]))
            ele.append(t)

        doc.build(ele)
        log(f"报告已保存：{fn}")
        return fn
    except Exception as e:
        log(f"PDF生成失败：{e}")
        return None


# ====================== 主扫描逻辑 ======================
def scan_task(target, opts):
    global is_scanning
    is_scanning = True
    res = {}
    try:
        log(f"开始扫描：{target}")
        if opts.get("subdomain"):
            subs = get_subdomains(target)
        else:
            subs = [target]
        res["subs"] = subs

        alive = []
        if opts.get("alive"):
            alive = get_alive_urls(subs)
        res["alive"] = alive

        res["vulns"] = detect_vulns(alive) if opts.get("vuln") else []
        res["sensitive"] = detect_sensitive(alive) if opts.get("sensitive") else []

        if opts.get("pdf"):
            gen_pdf(res, target)

        log("[系统] 扫描已完成，可重新发起扫描", "SUCCESS")
    except Exception as e:
        log(f"异常：{e}")
    finally:
        is_scanning = False


# ====================== Flask ======================
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/get_logs")
def get_logs():
    with lock:
        return jsonify({"logs": log_list.copy()})


@app.route("/api/start_scan", methods=["POST"])
def start_scan():
    global is_scanning, log_list
    if is_scanning:
        return jsonify({"status": "error", "message": "正在扫描"})
    data = request.get_json()
    target = data.get("target", "").strip()
    opts = data.get("options", {})
    if not target:
        return jsonify({"status": "error", "message": "请输入目标"})
    with lock:
        log_list.clear()
    threading.Thread(target=scan_task, args=(target, opts), daemon=True).start()
    return jsonify({"status": "success", "message": "已启动"})


@app.route("/static/<path:fn>")
def static_serve(fn):
    if not os.path.exists("static"): os.makedirs("static")
    return app.send_static_file(fn)


# ====================== 启动 ======================
def run_flask():
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    if not os.path.exists("static"): os.makedirs("static")
    threading.Thread(target=run_flask, daemon=True).start()
    time.sleep(1.5)
    webview.create_window("Eclipse Veil 安全扫描工具", "http://127.0.0.1:5000", width=1100, height=780)
    webview.start()
