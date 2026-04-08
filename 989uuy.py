import requests
import re

target = "jd.com"
headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
}
def get_subdomains(domain):
    subdomains = set()
    try:
        url = f"https://www.jd.com/:{domain}"
        res = requests.get(url, headers=headers, timeout=2)
        regex = r"[a-zA-Z0-9]+\." + domain.replace(".", r"\.")
        results = re.findall(regex, res.text)
        for s in results:
            subdomains.add(s)
    except:
        pass
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, headers=headers, timeout=10)
        data = res.json()
        for item in data:
            name = item["name_value"].strip()
            if "\n" in name:
                subs = name.split("\n")
                for s in subs:
                    if domain in s:
                        subdomains.add(s)
            else:
                if domain in name:
                    subdomains.add(name)
    except:
        pass

    return sorted(list(subdomains))

if __name__ == "__main__":
    print(f"[+] 正在收集 {target} 子域名...\n")
    subs = get_subdomains(target)
    for i, sub in enumerate(subs, 1):
        print(f"{i}. {sub}")
    print(f"\n[+] 共收集到 {len(subs)} 个子域名")
subs = get_subdomains(target) or []
subs +=["test.com/list","test.com/login","test.com?id=1"]
for user in subs:
    if '/list' in user:
        print(f'{user}->可能是敏感信息')
        with open(f'D:\\cd.txt', 'a', encoding='utf-8') as f:
            f.write(f'{user}->可能是敏感信息')
    if '/login' in user or '/register' in user:
        print(f'{user}->可能是注册点和登录')
        with open(f'D:\\cd.txt', 'a', encoding='utf-8') as f:
            f.write(f'{user}->可能是注册点和登录')
    if '?id=1' in user or '/index.php?id=1' in user:
        print(f'{user}->可能是SQL')
        with open(f'D:\\cd.txt', 'a', encoding='utf-8') as f:
            f.write(f'{user}->可能是SQL')
response = None
content_text = ""

try:
    response = requests.get('https://www.jd.com/', headers=headers, timeout=2)
    response.encoding = 'utf-8'
    content_text = response.text
    print(response.text[:300])
    print(f"状态码: {response.status_code}")
    title_list = re.findall(r'<title>(.*?)</title>', content_text)
    if title_list:
        title = title_list[0]
    else:
        title = "未获取到标题"
    print(f"网站标题: {title}")

    print(f"页面长度: {len(content_text)}")
    print(f"服务器信息: {response.headers.get('Server', '未找到Server头')}")
    print(f"响应头: {response.headers}")

except Exception as e:
    print(f"请求主站出错: {e}")

