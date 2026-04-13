from flask import Flask, render_template_string, request, jsonify
import threading
import webview
import time
import requests
from datetime import datetime
from queue import Queue
import urllib3
import os

# ================== 全局配置（修复：关闭警告、统一会话） ==================
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

# 全局状态（线程安全）
log_list = []
lock = threading.Lock()
is_scanning = False
THREAD_NUM = 10  # 线程数，根据电脑性能调整（5-15最佳）

# 统一请求会话
session = requests.Session()
session.verify = False
session.trust_env = False
proxies = {"http": None, "https": None}
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
}


# ================== 【修复】日志工具（线程安全，前端可实时拉取） ==================
def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {msg}"
    with lock:
        log_list.append(log_msg)
    print(log_msg)  # 后端终端同步打印


# ================== 【修复】完整HTML前端（解决日志不更新问题） ==================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Eclipse Veil 安全控制台</title>
<style>
body {
background-color: #0a0a1a;
font-family: 'Courier New', monospace;
overflow: hidden;
margin: 0;
padding: 2vh;
text-align: center;
color: #0ff;
}

h1 {
font-size: 28px;
margin-bottom: 30px;
text-shadow: 0 0 15px #0ff;
}

pre {
font-size: 20px;
line-height: 1.2;
font-weight: bold;
animation: glitch 0.2s infinite alternate, colorflash 1.5s infinite linear;
margin-bottom: 20px;
}

/* 彩色渐变闪烁 */
@keyframes colorflash {
0%  { color: #0ff; text-shadow: 0 0 10px #0ff,0 0 30px #0ff; }
20% { color: #ff0; text-shadow: 0 0 10px #ff0,0 0 30px #ff0; }
40% { color: #0f0; text-shadow: 0 0 10px #0f0,0 0 30px #0f0; }
60% { color: #f0f; text-shadow: 0 0 10px #f0f,0 0 30px #f0f; }
80% { color: #f30; text-shadow: 0 0 10px #f30,0 0 30px #f30; }
100%{ color: #0ff; text-shadow: 0 0 10px #0ff,0 0 30px #0ff; }
}

/* 故障抖动 */
@keyframes glitch {
0% { transform: translate(0); }
50% { transform: translate(-1px,1px); }
100% { transform: translate(1px,-1px); }
}

/* 扫描线 */
body::after {
content: "";
position: fixed; top:0; left:0; width:100%; height:100%;
background: repeating-linear-gradient(
0deg, rgba(0,255,255,0.05) 0px, rgba(0,255,255,0.05) 1px, transparent 1px, transparent 2px
);
pointer-events: none;
}

/* 自定义UI样式 */
.container {
position: relative;
z-index: 10;
}

/* 输入框样式 */
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
</style>
</head>
<body>

<div class="container">
    <h1>ECLIPSE VEIL - 安全扫描控制台</h1>

    <pre>
__/\\\\\\\\\\\\\\\_        _______________        _______        __/\\\\\\____        _______________        ______________        ________________         ___________         __/\\\________/\\\_        ________________        _______        __/\\\\\\____        __/\\\\\\____
 _\/\\\///////////__        _______________        _______        _\////\\\____        _______________        ______________        ________________         ___________         _\/\\\_______\/\\\_        ________________        _______        _\////\\\____        _\////\\\____
  _\/\\\_____________        _______________        __/\\\_        ____\/\\\____        ___/\\\\\\\\\__        ______________        ________________         ___________         _\//\\\______/\\\__        ________________        __/\\\_        ____\/\\\____        ____\/\\\____
   _\/\\\\\\\\\\\_____        _____/\\\\\\\\_        _\///__        ____\/\\\____        __/\\\/////\\\_        __/\\\\\\\\\\_        _____/\\\\\\\\__         ___________         __\//\\\____/\\\___        _____/\\\\\\\\__        _\///__        ____\/\\\____        ____\/\\\____
    _\/\\\///////______        ___/\\\//////__        __/\\\_        ____\/\\\____        _\/\\\\\\\\\\__        _\/\\\//////__        ___/\\\/////\\\_         ___________         ___\//\\\__/\\\____        ___/\\\/////\\\_        __/\\\_        ____\/\\\____        ____\/\\\____
     _\/\\\_____________        __/\\\_________        _\/\\\_        ____\/\\\____        _\/\\\//////___        _\/\\\\\\\\\\_        __/\\\\\\\\\\\__         ___________         ____\//\\\/\\\_____        __/\\\\\\\\\\\__        _\/\\\_        ____\/\\\____        ____\/\\\____
      _\/\\\_____________        _\//\\\________        _\/\\\_        ____\/\\\____        _\/\\\_________        _\////////\\\_        _\//\\///////___         ___________         _____\//\\\\\______        _\//\\///////___        _\/\\\_        ____\/\\\____        ____\/\\\____
       _\/\\\\\\\\\\\\\\\_        __\///\\\\\\\\_        _\/\\\_        __/\\\\\\\\\_        _\/\\\_________        __/\\\\\\\\\\_        __\//\\\\\\\\\\_         ___________         ______\//\\\_______        __\//\\\\\\\\\\_        _\/\\\_        __/\\\\\\\\\_        __/\\\\\\\\\_
        _\///////////////__        ____\////////__        _\///__        _\/////////__        _\///__________        _\//////////__        ___\//////////__         ___________         _______\///________        ___\//////////__        _\///__        _\/////////__        _\/////////__
    </pre>

    <!-- 输入框 + 交互按钮 -->
    <input type="text" id="targetInput" placeholder="请输入目标域名（如 baidu.com）" value="baidu.com">
    <button class="btn-start" id="startBtn" onclick="startScan()">🚀 启动安全扫描</button>

    <div id="resultArea">等待扫描开始...</div>
</div>

<script>
// -------------------
// 【修复】前端逻辑：解决日志不更新、按钮重复点击问题
// -------------------
let isScanning = false;
const resultArea = document.getElementById('resultArea');
const startBtn = document.getElementById('startBtn');
const targetInput = document.getElementById('targetInput');

// 轮询日志（核心修复：解决前端不显示日志）
function pollLogs() {
    fetch('/api/get_logs')
    .then(res => res.json())
    .then(data => {
        if (data.logs && data.logs.length > 0) {
            resultArea.textContent = data.logs.join('\\n');
            resultArea.scrollTop = resultArea.scrollHeight; // 自动滚动到底部
        }
        // 扫描中则继续轮询
        if (isScanning) {
            setTimeout(pollLogs, 800);
        }
    })
    .catch(err => {
        resultArea.textContent += `\\n[错误] 日志拉取失败: ${err}`;
        if (isScanning) setTimeout(pollLogs, 1000);
    });
}

// 启动扫描
function startScan() {
    const target = targetInput.value.trim();
    if (!target) {
        alert('❌ 请输入有效的目标域名！');
        return;
    }
    if (isScanning) {
        alert('⚠️ 扫描正在进行中，请等待完成！');
        return;
    }

    // 重置状态
    isScanning = true;
    startBtn.disabled = true;
    startBtn.textContent = '🔄 扫描中...';
    resultArea.textContent = `[系统] 开始扫描目标: ${target}\\n`;

    // 发送请求给Flask后端
    fetch('/api/start_scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            resultArea.textContent += '[系统] 扫描任务已启动，后台运行中...\\n';
            pollLogs(); // 启动日志轮询
        } else {
            resultArea.textContent += `[错误] 启动失败: ${data.message}\\n`;
            resetScanState();
        }
    })
    .catch(err => {
        resultArea.textContent += `[错误] 连接后端失败: ${err}\\n`;
        resetScanState();
    });
}

// 重置扫描状态
function resetScanState() {
    isScanning = false;
    startBtn.disabled = false;
    startBtn.textContent = '🚀 启动安全扫描';
}
</script>

</body>
</html>
'''


# ================== 【修复】子域名收集（加备用源，解决crt.sh 502） ==================
def get_subdomains(domain):
    subdomains = set()
    log("=== 步骤1：子域名收集 ===")

    # 源1：crt.sh（主源，加超时+异常处理）
    try:
        log("正在从 crt.sh 收集子域名...")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = session.get(url, headers=headers, timeout=15, proxies=proxies)
        if resp.status_code == 200:
            for item in resp.json():
                names = item.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name.endswith(domain) and not name.startswith("*"):
                        subdomains.add(name)
        else:
            log(f"crt.sh 响应异常: {resp.status_code}", "WARN")
    except Exception as e:
        log(f"crt.sh 请求失败: {str(e)}", "ERROR")

    # 源2：常用子域名爆破（备用，保证即使crt.sh挂了也有结果）
    common_subs = ["www", "m", "api", "admin", "test", "dev", "blog", "shop", "pay", "login", "mail", "ftp", "cdn",
                   "app", "wap"]
    for sub in common_subs:
        subdomains.add(f"{sub}.{domain}")

    log(f"子域名收集完成，共 {len(subdomains)} 个", "SUCCESS")
    return sorted(list(subdomains))


# ================== 【修复】存活检测（多线程，稳定不崩） ==================
def check_alive_worker(q, alive_list):
    while not q.empty():
        sub = q.get()
        for protocol in ["https://", "http://"]:
            url = f"{protocol}{sub}"
            try:
                resp = session.get(url, headers=headers, timeout=5, proxies=proxies, allow_redirects=True)
                if 200 <= resp.status_code < 500:
                    with lock:
                        alive_list.append(url)
                    log(f"[存活] {url}", "SUCCESS")
                    break
            except:
                continue
        q.task_done()


# ================== 【修复】漏洞扫描（稳定版，线程安全） ==================
def vuln_scan_worker(q, vuln_list):
    while not q.empty():
        url = q.get()
        # SQL注入检测
        sql_payloads = ["?id=1' AND 1=1--", "?id=1' OR '1'='1"]
        for payload in sql_payloads:
            try:
                test_url = url + payload
                resp = session.get(test_url, headers=headers, timeout=3, proxies=proxies)
                if "mysql" in resp.text.lower() or "error" in resp.text.lower() or "syntax" in resp.text.lower():
                    vuln = f"[SQL注入] {test_url}"
                    with lock:
                        vuln_list.append(vuln)
                    log(vuln, "WARN")
            except:
                continue
        # 服务器版本泄露检测
        try:
            resp = session.get(url, headers=headers, timeout=4, proxies=proxies)
            server = resp.headers.get("Server", "")
            if server:
                vuln = f"[版本泄露] {url} | Server: {server}"
                with lock:
                    vuln_list.append(vuln)
                log(vuln, "INFO")
        except:
            continue
        q.task_done()


# ================== 【修复】完整扫描流程（解决队列复用问题） ==================
def run_full_scan(target):
    global is_scanning
    try:
        # 重置状态
        with lock:
            log_list.clear()
            is_scanning = True

        # 1. 子域名收集
        subs = get_subdomains(target)
        if not subs:
            log("❌ 未收集到任何子域名，扫描终止", "ERROR")
            return

        # 2. 多线程存活检测
        log("=== 步骤2：多线程存活检测 ===")
        q_alive = Queue()
        for sub in subs:
            q_alive.put(sub)
        alive_list = []
        # 启动10个线程
        for _ in range(THREAD_NUM):
            t = threading.Thread(target=check_alive_worker, args=(q_alive, alive_list), daemon=True)
            t.start()
        q_alive.join()  # 等待所有存活检测完成
        log(f"存活检测完成，共 {len(alive_list)} 个存活站点", "SUCCESS")

        # 3. 多线程漏洞扫描
        log("=== 步骤3：漏洞扫描 ===")
        q_vuln = Queue()
        for url in alive_list:
            q_vuln.put(url)
        vuln_list = []
        for _ in range(THREAD_NUM):
            t = threading.Thread(target=vuln_scan_worker, args=(q_vuln, vuln_list), daemon=True)
            t.start()
        q_vuln.join()
        log(f"漏洞扫描完成，共发现 {len(vuln_list)} 个风险项", "SUCCESS")

        # 4. 保存结果到文件
        log("=== 步骤4：结果保存 ===")
        save_path = os.path.join(os.getcwd(), f"Eclipse_Veil_Scan_Result_{target.replace('.', '_')}.txt")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(f"=== Eclipse Veil 扫描报告 ===\\n")
            f.write(f"目标域名: {target}\\n")
            f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n\\n")
            f.write(f"=== 存活站点 ({len(alive_list)} 个) ===\\n")
            f.write("\\n".join(alive_list) + "\\n\\n")
            f.write(f"=== 风险项 ({len(vuln_list)} 个) ===\\n")
            f.write("\\n".join(vuln_list) + "\\n")
        log(f"✅ 扫描结果已保存到: {save_path}", "SUCCESS")
        log("=== 扫描全部完成 ===", "SUCCESS")

    except Exception as e:
        log(f"❌ 扫描过程发生异常: {str(e)}", "ERROR")
    finally:
        is_scanning = False
        # 前端自动重置按钮状态
        with lock:
            log_list.append("[系统] 扫描已完成，可重新发起扫描")


# ================== 【修复】Flask后端接口（解决前后端通信问题） ==================
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/get_logs')
def get_logs():
    with lock:
        return {"logs": log_list[-150:]}  # 返回最近150条日志，避免卡顿


@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    global is_scanning
    if is_scanning:
        return {"status": "error", "message": "扫描正在进行中，请等待完成"}

    try:
        data = request.get_json()
        target = data.get("target", "").strip()
        if not target:
            return {"status": "error", "message": "目标域名不能为空"}

        # 启动扫描线程（后台运行，不阻塞前端）
        threading.Thread(target=run_full_scan, args=(target,), daemon=True).start()
        return {"status": "success", "message": "扫描任务已启动"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ================== 【修复】Flask + WebView 启动逻辑（解决404/启动顺序问题） ==================
def run_flask_server():
    # 关闭Flask默认日志，避免干扰
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=8999, debug=False, use_reloader=False)


def main():
    # 1. 启动Flask后端（后台线程）
    flask_thread = threading.Thread(target=run_flask_server, daemon=True)
    flask_thread.start()
    log("Flask后端服务启动中...")

    # 2. 等待Flask完全启动（避免webview先打开导致404）
    time.sleep(2)

    # 3. 启动webview桌面窗口
    log("启动WebView桌面窗口...")
    window = webview.create_window(
        title="Eclipse Veil 安全扫描工具",
        url="http://127.0.0.1:8999",
        width=1000,
        height=700,
        resizable=True,
        min_size=(800, 600)
    )
    webview.start()


if __name__ == "__main__":
    # 解决Windows路径问题
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()

