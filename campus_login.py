#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTBU 校园网自动登录  ——  重庆工商大学 CTBU-Student
=================================================

设计目标
--------
* 零第三方依赖：只用 Python 标准库（不装 requests / PIL / ddddocr / 浏览器自动化）
* 低内存：单进程、跑完即退，峰值内存约 15~25 MB
* 跨平台：macOS 与 Windows 同一份代码
* 安全：只在校园网内动作；密码错误不重试，避免账号被锁

工作流程
--------
1. 判断"我现在是不是在校园网"（门户可达 / 本机网段 / SSID 关键字）——不是就直接退出，不发任何请求
2. 判断"是不是已经登录了"（captive 探测 + 门户 getOnlineUserInfo）——已登录就直接退出
3. 未登录 → 从 AC 的 302 跳转里抓出 queryString（含 wlanuserip / wlanacname / nasip / ssid / mac）
4. 拉验证码图片 → 本地字形模板识别（逐像素确定性匹配，非 OCR 猜测）
5. POST /eportal/InterFace.do?method=login
6. 按服务器返回分类处理：验证码错 → 换一张重试；密码错 → 立即停止；成功 → 二次验证联网状态

验证码识别说明
--------------
CTBU 门户（锐捷 ePortal）的验证码是 4 位数字，**纯 2 色、无抗锯齿、逐像素确定性**：
同一个数字在任何一张验证码里渲染出的位图完全一致。因此这里不用 OCR 猜，而是用
内置字形模板做精确匹配 —— 准确率 100%，且完全离线、零依赖、低内存。

内置模板覆盖 1 2 3 4 6 7 8 9。首次遇到 0 或 5 时，程序会把这几个字形画在终端里
让你确认一次（约 2 秒），确认后永久记住，之后就是全自动。

用法
----
    python3 campus_login.py              # 正常登录（双击启动器等价）
    python3 campus_login.py --check      # 只看状态，不做任何登录动作
    python3 campus_login.py --train      # 校园网内补齐缺失字形（只需跑一次）
    python3 campus_login.py --probe      # 校园网内抓诊断报告（出问题时发给我）
    python3 campus_login.py --self-test  # 离线自检：不联网，验证识别引擎

退出码
------
    0  已登录 / 登录成功
    1  运行出错
    2  当前不在校园网（未做任何动作）
    3  配置缺失（账号或密码没填）
    4  账号或密码被服务器拒绝（已停止，避免锁号）
    5  验证码连续识别失败
    6  找不到可用的门户地址
"""

import argparse
import base64
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

# ---------------------------------------------------------------------------
# 基本常量
# ---------------------------------------------------------------------------

VERSION = "1.0"
IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
LEARNED_PATH = os.path.join(HERE, "learned_templates.json")
LOG_PATH = os.path.join(HERE, "login.log")
REPORT_PATH = os.path.join(HERE, "diagnostic-report.txt")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

#: 内置字形模板：数字 -> (位图宽度, 20 行、每行按 4bit 对齐的十六进制)
#: 由真实门户验证码逐像素提取，跨样本一致性已校验
BUILTIN_TEMPLATES = {
    '1': (9, '0c07c0fc01c01c01c01c01c01c01c01c01c01c01c01c01c01c01c01c0ff8'),
    '2': (13, '1f803fc061e080f08070007000700060006000c000c001800300020004000800180830187ff0fff0'),
    '3': (12, '1f83fc41e80e00e00e00c0180781fc03e00f00f007007007006c0cf187e0'),
    '4': (13, '00c001c003c003c005c005c009c011c011c021c021c041c0c1c0fff8fff801c001c001c001c001c0'),
    '6': (13, '007801c007000e001c0038003000700067c0f8e0e070e078e038e038e03860387030307018e00f80'),
    '7': (13, '3ff87ff87ff0403080600060006000c000c000c00180018001800300030003000600060006000c00'),
    '8': (11, '1f071c60ee0ee0ee0ef1c7983e01e01f037863ce1ee0ee0ee0e60c71c1f0'),
    '9': (13, '0f8038c070606070e030e038e038e038f038703838781fb00070006000e001c0038007001c00f000'),
    # 0 和 5 由真机验证码 (2059) 补齐；同批次样本里已知数字与上述模板逐像素一致，
    # 证明渲染是确定性的、跨会话稳定（详见 README「验证状态」）。
    '0': (13, '078018c03060307070306030e038e038e038e038e038e038e038e038603070707070306018c00f00'),
    '5': (11, '0fe1fc1fc2002007807e0ff80fc03c01e00e00600600600400c418ff07c0'),
}

#: 离线自检样本：(正确答案, 验证码 PNG 的 base64)
SELFTEST_SAMPLES = [
    ('7911', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAAtklEQVR42u3YSw6AIAwEUK7mQT2dB9G9hrZTwDAwxJVC6ENSPuXerBSBBRZ4F/B1HvbjNon3AoU0BOxqXx1/X9rBQUOTGMf+YFtrmyOTJVe5CRyfVy7MxUD/oD84oa014QBDaSMCzn0V+HewkZl2BCfyFiXYDoUYnMi37uJJDK7tEIiXpURnNBuPLlpoUqwAhvbJ9GD0GDQXeJB2EfA4w3TgREAzgqHlt/12obGyLvEEFlhg8vIAQleM60ls1fAAAAAASUVORK5CYII='),
    ('4134', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAAzUlEQVR42u3Y0Q2AIAwEUFZzUKdzEDXhx4jKQY9a4xH+BOxDA5S0/qwkgQUW+L/gZZ72SmmW2xwrPQwruBoZDii1uKF1gpJRe/cmPPryEW7u+CNGgcEvUJ2vEOA8OgVs6dUUhsCNWh8wMYxO8HHccWBc+3kwvo15gE+DcsH4PtwXRjgwflxxAj8cD4au0iXP46R1OaI/2BJGD7haieDLjpYwBB6QLdHBb2ZLbuAo6SEL/LD3xMqHuWBkNY4OxhcVy+WOK1i3lgILLPALZQObuman2D2CkAAAAABJRU5ErkJggg=='),
    ('4821', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAA6ElEQVR42u3YQQ6EIAwFUK82B/V0HmTGxIQN0H5+i5axhpVg4KG04PZ92bUlOMEJfi/42D9nURuUgreUG+MD8ATLI6trhfa1VpYQU2MFq/01q5qP9O7gs/M8uFfVfO3chKqfmCf46mMqGPEsCaZjxH3g0gG4zOjxhQDjgNo8Ojg8k4UAG5NHCHAveViyl2VHER3s+z1PBxMht9RO2jBOBBM5pheiwffmEsatYLUgW0hkFXjlrYfB4CrwOr3celriwFwkXxVMTEQgsBznRrUrgYcWNv0bIAQY3HgMxUL1kfyJl+AEJ/jvrh/TmlBv+5785AAAAABJRU5ErkJggg=='),
    ('7648', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAA6ElEQVR42u2YQRaAIAhEuVoH7XQdpHYtKmlmFPMlvXYU8oNG0PbJLkvgBE7gWYC3dfFvygPyJB5Me+BXWjA+ai3QSjm36PSySXj1+WjCVyGAhfITSs4HLpkaA/ek9V/sBCyoi0D7B2CBFgQOF63o9OIAd2ZqLYtOLy7m+PeSN+EQ4FI0fqGyBfIBsFDPjuTUAId0Wm2BL5lnJeC0CszWWbEQvaE6LZbZ2tJqwHjf+uicYv4DcI/GA/zHtC16uE6rPmJ5PBwUuHKIk8fDKNGizjeEJAxxAKBNBVp7MGjjkaeWCZzACfzBdQChkT3r1bfJSgAAAABJRU5ErkJggg=='),
    # 真实门户抓到的样本（含 0 和 5），用来证明 10 个数字字形全覆盖
    ('2059', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAA/ElEQVR42u2YSxKEMAhEudocdE7nQZztlJqku9NoWSHlKl8eGALEvliLAi7gAl4IePt+Dh+1RNi/tYoVQwG+lKZz2GF0KBm4+XmIYg6KFjfdZT+ioD5wv98GjPxXOHBLQZrehzs7gVsnsZYHgZFbne6lO8C4WKD7Ad3Y3cCCWKxnfh54RqyW86dcwJuAcVOzz5UfOMkOmpFfDCww41FXeGldwKAx/+fkPkvZvpSNn8yBx3wocg9wVnoI3sBJyfDJlBLDTjsM8SlgL62YDw+FswBTzjwxH6bCDzlzSKKl82E8DMQLAGxdQUbl0kMBWEiD8ApBFfEKuIALeI32AzeIR8uuxWf/AAAAAElFTkSuQmCC'),
    ('4669', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAA8klEQVR42u2Y0Q2AIAxEu5qDOp2DqIk/RlTuylU0lvDHCbxaaIvNP2uWwAmcwP8FnsZh7awe/OpevB+l9mCNtOBiQnE5SjFbI211Ja1drgT4ErHAci+oengI8Dav+2800t67ejfgiBMuWdF8tCp7U+IOwOXd2HiiKPHbgcGAiYvByCwDPsyFbKtqIEoscatAYDxnoACqhtMA42BgPugQX/nFPmpowhIFRl0tqtgmTjxKi5727sCy1PLlwFQUDKmWVLWOPF2PBQZt4TOcjzawHnbcc6pSsdsDAB5yfWIW9YkXD+ohBkxC3aj5iJfACZzAH2wL1xg1R8gAUoIAAAAASUVORK5CYII='),
    ('9169', 'iVBORw0KGgoAAAANSUhEUgAAAFAAAAAeCAIAAAA0IQ7mAAAA7klEQVR42u2YXQ6DIBCEuVoP2tP1IPa1iYLzt43RNb4pMJ/AzuDYHnaNBm7gBn4W8Of9+r3xJs5AERk08L739WCypnUTVoYIPBMBzgC1FpCPKC8iDjgoUXtTlsEBI2vMBMZpNRl5YO1p8KOAnVwIuFTGhYBTm7wEWCgYIDDiZI6MmC2l5v/QWhfM5cCzHk+dVn5KMeOGz0XLwzjhbFEwPPoyYocHsyZF6lA+eDiO8k/g8uNhKh6ZwFRcH6W0rC3VpTQXOLi7TutWkFYEzp74ZmDBiBawpaKVHy9mJdESdGx8xgRn7p94DdzADXzT6wuElU8zKI1+zwAAAABJRU5ErkJggg=='),
]

DEFAULT_CONFIG = {
    "username": "",
    "password": "",
    "portal_candidates": [
        "http://211.83.192.55",
        "http://211.83.192.55:8080",
        "http://1.1.1.1",
    ],
    "ssid_keywords": ["CTBU"],
    "detect_ssid": True,
    "campus_subnets": ["10.203.0.0/17"],
    "captcha_length": 4,
    "max_captcha_attempts": 6,
    "max_password_attempts": 2,
    "password_encrypt": False,
    "password_transform": "plain",
    "double_encode": True,
    "service": "auto",
    "service_keyword": "移动",
    "http_timeout": 6,
    "captive_probe_urls": [
        "http://captive.apple.com/hotspot-detect.html",
        "http://connect.rom.miui.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt",
    ],
    "verify_url": "http://captive.apple.com/hotspot-detect.html",
}


# ---------------------------------------------------------------------------
# 输出与日志
# ---------------------------------------------------------------------------

class Log(object):
    """同时输出到控制台和日志文件。"""

    def __init__(self, path=None, verbose=True):
        self.verbose = verbose
        self.fh = None
        if path:
            try:
                self.fh = open(path, "a", encoding="utf-8")
                self.fh.write("\n" + "=" * 68 + "\n")
                # 注意：不要把带 %Y%m%d 的格式串和 % 格式化写在同一行 ——
                # % 的优先级高于函数调用，会把整个字符串当成格式串而抛 ValueError。
                stamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
                self.fh.write(stamp + " 启动 campus_login " + VERSION + "\n")
                self.fh.flush()
            except Exception as e:
                self.fh = None
                if self.verbose:
                    print("(警告：日志文件不可写，改为只输出到屏幕：%s)" % e)

    def __call__(self, msg="", level="INFO"):
        line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
        if level == "ERR":
            line = "%s [错误] %s" % (time.strftime("%H:%M:%S"), msg)
        elif level == "WARN":
            line = "%s [注意] %s" % (time.strftime("%H:%M:%S"), msg)
        elif level == "OK":
            line = "%s [成功] %s" % (time.strftime("%H:%M:%S"), msg)
        if self.verbose:
            try:
                print(line)
            except Exception:
                print(line.encode("utf-8", "replace").decode("utf-8", "replace"))
        if self.fh:
            try:
                self.fh.write(line + "\n")
                self.fh.flush()
            except Exception:
                pass

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except Exception:
                pass
            self.fh = None


def setup_console_encoding():
    """Windows 控制台默认不是 UTF-8，中文会乱码/报错。"""
    for stream in ("stdout", "stderr"):
        s = getattr(sys, stream, None)
        if s is None:
            continue
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

def load_config(log, path=None):
    path = path or CONFIG_PATH
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
        log("已生成配置文件：%s" % path)
        log("请用记事本/文本编辑器填好 username(学号) 和 password(统一身份认证密码) 后再运行。", "WARN")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        cfg = json.loads(raw)
    except Exception as e:
        log("配置文件读取失败：%s" % e, "ERR")
        return None

    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg or {})
    return merged


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 网络环境探测（尽量少用子进程，拿到就拿、拿不到不阻塞）
# ---------------------------------------------------------------------------

def run_cmd(args, timeout=6):
    """执行命令并返回 (是否成功, 输出文本)。任何异常都返回失败，绝不抛出。"""
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        out = p.stdout.decode("utf-8", "replace")
        if not out.strip():
            out = p.stdout.decode("gbk", "replace")
        return p.returncode == 0, out
    except Exception:
        return False, ""


def local_ip_towards(host):
    """取本机用来访问 host 的那块网卡的 IPv4 —— 这正是门户需要的 wlanuserip。

    用 UDP connect，不发包，纯本地路由查询。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def tcp_reachable(host, port=80, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def default_gateway():
    """取默认网关。macOS 用 route，Windows 用 ipconfig。"""
    if IS_WINDOWS:
        ok, out = run_cmd(["ipconfig"])
        if ok:
            # 中文/英文 Windows 都是 "Default Gateway . . . : 10.203.255.254"
            for line in out.splitlines():
                if ":" in line and ("Gateway" in line or "网关" in line):
                    val = line.split(":", 1)[1].strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
                        return val
        return None

    ok, out = run_cmd(["route", "-n", "get", "default"])
    if ok:
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return None


def detect_ssid():
    """尽力识别当前 WiFi 名称。拿不到就返回 None（新版 macOS 会脱敏）。

    返回: (ssid 或 None, 说明文字)
    """
    if IS_WINDOWS:
        ok, out = run_cmd(["netsh", "wlan", "show", "interfaces"])
        if ok:
            for line in out.splitlines():
                # 只匹配 SSID，不匹配 BSSID
                m = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line, re.IGNORECASE)
                if m:
                    return m.group(1), "netsh wlan show interfaces"
        return None, "netsh 未取到（无线网卡未连接或服务未启动）"

    if IS_MACOS:
        # 1) networksetup：先找 Wi-Fi 设备名
        ok, out = run_cmd(["networksetup", "-listallhardwareports"])
        dev = None
        if ok:
            blocks = out.split("Hardware Port:")
            for b in blocks:
                if "Wi-Fi" in b or "AirPort" in b:
                    m = re.search(r"Device:\s*(\S+)", b)
                    if m:
                        dev = m.group(1)
                        break
        if dev:
            ok2, out2 = run_cmd(["networksetup", "-getairportnetwork", dev])
            if ok2:
                m = re.search(r"Current Wi-Fi Network:\s*(.+)", out2)
                if not m:
                    m = re.search(r"你当前的无线网络是\s*(.+)", out2)
                if m:
                    return m.group(1).strip(), "networksetup(%s)" % dev
        # 2) system_profiler：新版 macOS 常把 SSID 脱敏成 <redacted>
        ok3, out3 = run_cmd(["system_profiler", "SPAirPortDataType"], timeout=20)
        if ok3:
            m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n", out3)
            if m:
                name = m.group(1).strip()
                if name and name.lower() not in ("<redacted>", "none"):
                    return name, "system_profiler"
                if name.lower() == "<redacted>":
                    return None, "system_profiler 返回 <redacted>（系统隐私限制）"
        # 3) sudo -n wdutil：只在配置了免密 sudo 时有效，不会弹密码
        ok4, out4 = run_cmd(["sudo", "-n", "wdutil", "info"], timeout=8)
        if ok4:
            m = re.search(r"SSID\s*:\s*(.+)", out4)
            if m:
                return m.group(1).strip(), "wdutil"
        return None, "macOS 未能取到 SSID（属于正常现象，不影响登录）"

    return None, "不支持的平台"


def ip_in_cidr(ip, cidr):
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
        ip_i = struct.unpack(">I", socket.inet_aton(ip))[0]
        net_i = struct.unpack(">I", socket.inet_aton(net))[0]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
        return (ip_i & mask) == (net_i & mask)
    except Exception:
        return False


def http_get(url, timeout=6, cookie_jar=None, allow_redirect=True, headers=None):
    """返回 (状态码, 响应头, 正文bytes, 最终URL)。不抛异常，失败返回 (None,...)。"""
    handlers = [urllib.request.ProxyHandler({})]  # 关键：忽略系统代理，否则门户探测会被代理污染
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    if not allow_redirect:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read(), resp.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body, url
    except Exception:
        return None, {}, b"", url


def http_post(url, data, timeout=6, cookie_jar=None, headers=None):
    handlers = [urllib.request.ProxyHandler({})]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    opener = urllib.request.build_opener(*handlers)

    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    if headers:
        hdrs.update(headers)
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception:
        return None, b""


def smart_decode(raw):
    """门户的 JSON 是 UTF-8，HTML 页面是 GBK，逐个试。"""
    if not raw:
        return ""
    for enc in ("utf-8", "gbk", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def js_encode(s):
    """近似 JavaScript 的 encodeURIComponent。

    前端把 userId / password / service / validcode 都做了
    encodeURIComponent(encodeURIComponent(x)) 双重编码，服务端会解码两层。
    对纯数字学号来说是恒等变换，但密码里含 ! * ' ( ) 等字符时就有区别了。
    """
    return urllib.parse.quote(s if s is not None else "", safe="!~*'()")


# ---------------------------------------------------------------------------
# PNG 解码 + 字形识别
# ---------------------------------------------------------------------------

def decode_png(data):
    """极简 PNG 解码器：支持 8bit 灰度/RGB/RGBA 非隔行。返回 (w, h, channels, pixels)。"""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("不是 PNG 数据")
    pos = 8
    idat = b""
    w = h = bitdepth = colortype = None
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if ctype == b"IHDR":
            w, h, bitdepth, colortype, comp, filt, interlace = struct.unpack(">IIBBBBB", chunk)
            if interlace != 0:
                raise ValueError("不支持隔行 PNG")
        elif ctype == b"IDAT":
            idat += chunk
        elif ctype == b"IEND":
            break
        pos += 12 + length

    if bitdepth != 8:
        raise ValueError("只支持 8bit PNG，当前 %s" % bitdepth)

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colortype)
    if channels is None:
        raise ValueError("不支持的 PNG 颜色类型 %s" % colortype)
    if colortype == 3:
        raise ValueError("不支持调色板 PNG")

    raw = zlib.decompress(idat)
    stride = w * channels
    out = bytearray()
    prev = bytearray(stride)
    i = 0
    for _ in range(h):
        f = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        if f == 1:
            for x in range(channels, stride):
                line[x] = (line[x] + line[x - channels]) & 0xFF
        elif f == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif f == 3:
            for x in range(stride):
                a = line[x - channels] if x >= channels else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif f == 4:
            for x in range(stride):
                a = line[x - channels] if x >= channels else 0
                b = prev[x]
                c = prev[x - channels] if x >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        out += line
        prev = line
    return w, h, channels, bytes(out)


def encode_template(width, rows):
    """把 glyph 行（每行一个 int）编码成 (宽度, 十六进制字符串)。"""
    nib = (width + 3) // 4
    shift = nib * 4 - width
    return width, "".join("%0*x" % (nib, (r << shift) & ((1 << (nib * 4)) - 1)) for r in rows)


def parse_template(width, bits):
    """把存储格式（每行左移到 4bit 对齐）还原成自然位（第 width-1 位是最左像素）。"""
    nib = (width + 3) // 4
    if nib == 0 or len(bits) % nib != 0:
        return width, []
    shift = nib * 4 - width
    return width, [(int(bits[i:i + nib], 16) >> shift) for i in range(0, len(bits), nib)]


def load_templates(log=None):
    tpl = {}
    for k, (w, bits) in BUILTIN_TEMPLATES.items():
        tpl[k] = parse_template(w, bits)
    if os.path.exists(LEARNED_PATH):
        try:
            with open(LEARNED_PATH, "r", encoding="utf-8") as f:
                learned = json.load(f)
            n = 0
            for k, v in learned.items():
                tpl[k] = parse_template(int(v["w"]), v["bits"])
                n += 1
            if log and n:
                log("已载入 %d 个自学字形：%s" % (n, "".join(sorted(learned))))
        except Exception as e:
            if log:
                log("自学字形载入失败（忽略）：%s" % e, "WARN")
    return tpl


def save_learned(tpl):
    """只把内置模板之外的（自学到的）字形写盘。"""
    builtin_keys = set(BUILTIN_TEMPLATES.keys())
    out = {}
    for k, (w, rows) in tpl.items():
        if k in builtin_keys:
            continue
        out[k] = {"w": w, "bits": encode_template(w, rows)[1]}
    with open(LEARNED_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)


def image_to_glyphs(png_bytes):
    """验证码图片 -> 字形位图列表。返回 (glyphs, 诊断信息)。"""
    w, h, ch, px = decode_png(png_bytes)

    # 出现最多的颜色视为背景
    counts = {}
    for y in range(h):
        for x in range(w):
            o = (y * w + x) * ch
            c = (px[o], px[o + 1], px[o + 2])
            counts[c] = counts.get(c, 0) + 1
    bg = max(counts, key=counts.get)

    def is_ink(x, y):
        o = (y * w + x) * ch
        return max(abs(px[o] - bg[0]), abs(px[o + 1] - bg[1]), abs(px[o + 2] - bg[2])) > 60

    grid = [[1 if is_ink(x, y) else 0 for x in range(w)] for y in range(h)]

    cols = [any(grid[y][x] for y in range(h)) for x in range(w)]
    segs = []
    start = None
    for x, c in enumerate(cols):
        if c and start is None:
            start = x
        elif not c and start is not None:
            segs.append((start, x))
            start = None
    if start is not None:
        segs.append((start, w))

    # 去掉噪点（过窄的段）
    segs = [(a, b) for a, b in segs if b - a >= 3]

    glyphs = []
    for x0, x1 in segs:
        ys = [y for y in range(h) if any(grid[y][x] for x in range(x0, x1))]
        if not ys:
            continue
        sub = [row[x0:x1] for row in grid[min(ys):max(ys) + 1]]
        width = x1 - x0
        rows = []
        for row in sub:
            v = 0
            for i, bit in enumerate(row):
                if bit:
                    v |= (1 << (width - 1 - i))
            rows.append(v)
        glyphs.append((width, rows))

    info = "图像 %dx%d，背景 %s，切出 %d 个字形" % (w, h, "#%02X%02X%02X" % bg, len(glyphs))
    return glyphs, info


def match_glyph(width, rows, templates):
    """精确匹配优先，其次最邻近（返回 (数字, 距离, 是否精确)）。"""
    # 精确匹配
    for digit, (tw, trows) in templates.items():
        if tw == width and len(trows) == len(rows) and trows == rows:
            return digit, 0, True

    # 最邻近：按行做位差
    best = None
    for digit, (tw, trows) in templates.items():
        if len(trows) != len(rows):
            continue
        dist = 0
        for a, b in zip(rows, trows):
            dist += bin(a ^ b).count("1")
        if best is None or dist < best[1]:
            best = (digit, dist)
    if best is None:
        return None, None, False
    return best[0], best[1], False


def glyph_ascii(width, rows, indent="      "):
    lines = []
    for r in rows:
        lines.append(indent + "".join("#" if (r >> (width - 1 - i)) & 1 else "." for i in range(width)))
    return "\n".join(lines)


def recognize(png_bytes, templates, expected_len=4, interactive=False, log=None,
              unknown_sink=None):
    """识别验证码。

    返回 (code 或 None, 说明)。遇到未知字形时，如果允许交互就问用户一次并永久记住。
    """
    try:
        glyphs, info = image_to_glyphs(png_bytes)
    except Exception as e:
        return None, "验证码解码失败：%s" % e

    if len(glyphs) != expected_len:
        return None, "%s，但期望 %d 位，本张作废" % (info, expected_len)

    out = []
    for width, rows in glyphs:
        digit, dist, exact = match_glyph(width, rows, templates)
        if exact:
            out.append(digit)
            continue

        # 未知字形
        if log:
            log("遇到未知字形（最接近 '%s'，差异 %s 个像素，宽度 %d）" % (digit, dist, width))
        if unknown_sink is not None:
            unknown_sink.append((width, rows))

        if interactive:
            print()
            print("  ┌─ 需要你认一次这个字形（只此一次，之后永久记住）")
            print(glyph_ascii(width, rows))
            print("  └─ 上面这个字形是哪个数字？输入 0-9，直接回车=跳过本张验证码")
            try:
                ans = input("     请输入：").strip()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if len(ans) == 1 and ans.isdigit():
                templates[ans] = (width, rows)
                try:
                    save_learned(templates)
                    if log:
                        log("已记住字形 '%s'，下次不会再问。" % ans, "OK")
                except Exception as e:
                    if log:
                        log("字形保存失败：%s" % e, "WARN")
                out.append(ans)
                continue
        return None, "出现未知字形，且未提供答案，本张作废"

    return "".join(out), info


# ---------------------------------------------------------------------------
# 门户客户端
# ---------------------------------------------------------------------------

class Portal(object):
    def __init__(self, base, cfg, log, cookie_jar=None):
        self.base = base.rstrip("/")
        self.cfg = cfg
        self.log = log
        self.timeout = cfg.get("http_timeout", 6)
        if cookie_jar is not None:
            self.jar = cookie_jar
        else:
            import http.cookiejar
            self.jar = http.cookiejar.CookieJar()

    # ---- 基础 ----
    @property
    def login_url(self):
        return self.base + "/eportal/InterFace.do?method=login"

    def api(self, method, **params):
        q = {"method": method}
        q.update(params)
        url = self.base + "/eportal/InterFace.do?" + urllib.parse.urlencode(q)
        code, headers, body, final = http_get(url, timeout=self.timeout, cookie_jar=self.jar)
        return code, body

    def api_json(self, method, **params):
        code, body = self.api(method, **params)
        text = smart_decode(body)
        try:
            return json.loads(text), code, text
        except Exception:
            return None, code, text

    # ---- 状态 ----
    def online_info(self):
        """返回 (是否在线, 账号或None, 原始文本)。"""
        data, code, text = self.api_json("getOnlineUserInfo")
        if isinstance(data, dict):
            if data.get("result") == "success" and data.get("userIndex"):
                idx = data["userIndex"] or ""
                acct = None
                try:
                    decoded = bytes.fromhex(idx).decode("ascii", "replace")
                    acct = decoded.split("_")[-1] or None
                except Exception:
                    pass
                return True, acct, text
            return False, None, text
        return False, None, text or "(无响应)"

    def capture_querystring(self):
        """抓 AC 跳转里的 queryString —— 登录必需。

        未认证时，AC 会把任意 http 请求 302 到门户登录页，Location 里带着
        wlanuserip / wlanacname / nasip / ssid / mac / t / url，这一串就是 queryString。
        """
        tries = list(self.cfg.get("captive_probe_urls", []))
        tries += ["http://www.baidu.com/", "http://" + urllib.parse.urlsplit(self.base).netloc + "/"]

        KEYS = ("wlanuserip", "wlanacname", "nasip")

        def pick(q):
            return q if q and any(k in q for k in KEYS) else None

        for url in tries:
            # 1) 关键：不跟随跳转，才能读到 302 的 Location —— queryString 就在这里
            code, headers, body, final = http_get(
                url, timeout=self.timeout, cookie_jar=self.jar, allow_redirect=False)
            loc = headers.get("Location") or headers.get("location") or ""
            q = pick(urllib.parse.urlsplit(loc).query)
            if q:
                self.log("已从跳转 Location 抓到 queryString（来自 %s）" % url)
                return q

            # 2) 跟随跳转，看最终落地 URL 的 query
            code2, headers2, body2, final2 = http_get(
                url, timeout=self.timeout, cookie_jar=self.jar, allow_redirect=True)
            q2 = pick(urllib.parse.urlsplit(final2).query)
            if q2:
                self.log("已从最终地址抓到 queryString（来自 %s）" % url)
                return q2

            # 3) 有的设备直接把门户内容/脚本塞在 200 正文里
            text = smart_decode(body2 or body)
            m = re.search(r"(wlanuserip=[^\"'\s<>&]+(?:&[^\"'\s<>&]+)*)", text)
            if m:
                self.log("已从页面正文抓到 queryString（来自 %s）" % url)
                return m.group(1)

        # 4) 再试 pageInfo
        code, body = self.api("pageInfo")
        text = smart_decode(body)
        m = re.search(r"queryString\s*[:=]\s*[\"']([^\"']+)[\"']", text)
        if m:
            self.log("已从 pageInfo 抓到 queryString")
            return m.group(1)

        return None

    def fetch_captcha(self):
        url = self.base + "/eportal/validcode?r=%d" % random.randint(100000, 9999999)
        code, headers, body, final = http_get(
            url, timeout=self.timeout, cookie_jar=self.jar,
            headers={"Referer": self.base + "/eportal/index.jsp", "Accept": "image/*"})
        if code == 200 and body and body[:8] == b"\x89PNG\r\n\x1a\n":
            return body
        return None

    def login(self, username, password, query_string, validcode, password_encrypt):
        """提交登录。

        字段编码严格照抄前端 login_bch.js：
            userId   = encodeURIComponent(encodeURIComponent(username))
            password = encodeURIComponent(encodeURIComponent(password))
            service / validcode / passwordEncrypt 同理，都是双重编码
            queryString 例外 —— 前端直接把 location.search 去掉 '?' 后原样传，不再编码
        表单序列化本身还会再编码一层，等价于 jQuery 的 $.post。
        """
        double = self.cfg.get("double_encode", True)

        def enc(v):
            v = "" if v is None else str(v)
            return js_encode(js_encode(v)) if double else v

        data = {
            "userId": enc(username),
            "password": enc(password),
            "service": enc(self.cfg.get("service", "")),
            "queryString": query_string or "",
            "operatorPwd": enc(""),
            "operatorUserId": enc(""),
            "validcode": enc(validcode or ""),
            "passwordEncrypt": enc("true" if password_encrypt else "false"),
        }
        referer = self.base + "/eportal/index.jsp"
        if query_string:
            referer += "?" + query_string
        code, body = http_post(self.login_url, data, timeout=self.timeout,
                               cookie_jar=self.jar, headers={"Referer": referer})
        text = smart_decode(body)
        try:
            return json.loads(text), code, text
        except Exception:
            return None, code, text


def classify_failure(message):
    """把服务器返回的失败信息归类，决定要不要继续重试。"""
    m = message or ""
    if any(k in m for k in ("验证码", "校验码", "validcode")):
        return "captcha"
    if any(k in m for k in ("密码", "password")):
        return "password"
    if any(k in m for k in ("用户名", "用户不存在", "账号", "userId")):
        return "username"
    if any(k in m for k in ("已在线", "已经在线", "重复登录", "已登录")):
        return "already"
    # 顺序很重要：必须排在"密码/用户名"之后，否则会把账号密码错误误判成出口问题
    if any(k in m for k in ("出口", "服务", "service", "运营商", "接入方式")):
        return "service"
    return "other"


# ---------------------------------------------------------------------------
# 服务出口（service）自动发现
#
# CTBU 门户首页是「统一身份用户 / 其他用户」两个标签页 + 一排出口按钮：
#   教职员工专用 / 学生移动出口 / 学生联通出口 / 学生电信出口 ...
# 登录表单必须带上被选中出口对应的 service 值，否则认证不通过。
# 这些出口名和值都写在前端 JS 里，所以运行时现场抓下来解析，不写死。
# ---------------------------------------------------------------------------

JS_REF_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""")
SERVICE_KV_RE = re.compile(r"""service\w*\s*[=:]\s*['"]([^'"]{1,80})['"]""", re.I)
SERVICE_CALL_RE = re.compile(
    r"""\w*[Ss]ervice\w*\s*\(\s*['"]([^'"]{1,80})['"]\s*,\s*['"]([^'"]{1,80})['"]""")
CN_EXIT_RE = re.compile(r"""['"]([\u4e00-\u9fa5A-Za-z0-9]{2,16}出口)['"]""")


def fetch_login_assets(portal, query_string):
    """抓登录页和它引用的 JS。返回 (页面文本, {地址: 内容}, 登录页地址)。"""
    page_url = portal.base + "/eportal/index.jsp"
    if query_string:
        page_url += "?" + query_string
    code, headers, body, final = http_get(page_url, timeout=portal.timeout,
                                          cookie_jar=portal.jar)
    text = smart_decode(body)
    assets = {}
    for ref in JS_REF_RE.findall(text)[:8]:
        if ref.startswith("http://") or ref.startswith("https://"):
            url = ref
        elif ref.startswith("/"):
            url = portal.base + ref
        else:
            url = portal.base + "/eportal/" + ref
        c, h, b, f = http_get(url, timeout=portal.timeout, cookie_jar=portal.jar)
        if c == 200 and b:
            assets[url] = smart_decode(b)
    return text, assets, page_url


NAME_KV_RE = re.compile(
    r"""(?:name|title|label|text|serviceName|showName)\s*[:=]\s*['"]([^'"]{1,40})['"]""", re.I)


def _label_near(blob, m):
    """给一个 service 匹配找它对应的标签。

    要点：取**紧邻 service 之前的最后一个 name**。
    如果用一个宽对称窗口取第一个 name，会把上一条记录的 name 配到这一条上
    （{name:'教职员工专用',service:'staff'}, {name:'学生移动出口',service:'mobile'}
     里 mobile 会被错配成"教职员工专用"），关键字就会选错出口。
    """
    pre = blob[max(0, m.start() - 160): m.start()]
    names = NAME_KV_RE.findall(pre)
    if names:
        return names[-1]
    post = blob[m.end(): m.end() + 160]
    nm = NAME_KV_RE.search(post)
    if nm:
        return nm.group(1)
    # 退一步：找中文出口名，先看 service 之后（同一条记录内），再看之前（取最近的）
    names = CN_EXIT_RE.findall(post)
    if names:
        return names[0]
    names = CN_EXIT_RE.findall(pre)
    if names:
        return names[-1]
    return ""


def discover_services(page_text, assets):
    """从页面和 JS 里挖出 (标签, service 值) 候选。

    真实门户的出口列表长这样（对象数组）：
        {name:'学生移动出口', service:'student_mobile'}
    所以关键是**把 service 值和它附近的标签配起来**，而不是把中文名本身当成值 ——
    否则「移动」关键字会先命中中文标签，选出一个根本不存在的 service。
    """
    kv_pairs = []      # (标签, 值) —— 有明确 service 值的
    bare_names = []    # 只有中文出口名、没有配到值的兜底候选

    for blob in [page_text] + list(assets.values()):
        for m in SERVICE_KV_RE.finditer(blob):
            kv_pairs.append((_label_near(blob, m), m.group(1)))

        # 交互函数写法：selectService('student_mobile', '学生移动出口')
        for m in SERVICE_CALL_RE.finditer(blob):
            a, b = m.group(1), m.group(2)
            if "出口" in a or CN_EXIT_RE.fullmatch("'" + a + "'"):
                kv_pairs.append((a, b))
            else:
                kv_pairs.append((b, a))

        for m in CN_EXIT_RE.finditer(blob):
            bare_names.append((m.group(1), m.group(1)))

    def dedup(seq):
        seen, out = set(), []
        for label, val in seq:
            label, val = (label or "").strip(), (val or "").strip()
            if not val or len(val) > 80:
                continue
            key = (label, val)
            if key in seen:
                continue
            seen.add(key)
            out.append((label, val))
        return out

    kv_pairs = dedup(kv_pairs)
    bare_names = [p for p in dedup(bare_names) if p not in kv_pairs]
    return kv_pairs, bare_names


def resolve_service(portal, query_string, cfg, log):
    """决定登录时要带的 service 值。

    config 里 service 明确写了就用它；写 "auto" 或留空则现场发现。
    返回 (首选值或 None, 说明, 按优先级排序的全部候选)。
    候选列表要带出来，因为万一首选不对还能逐个重试。
    """
    want = cfg.get("service", "")
    if want and str(want).lower() != "auto":
        return want, "来自 config.json", [(want, want)]

    try:
        page_text, assets, _ = fetch_login_assets(portal, query_string)
        kv_pairs, bare_names = discover_services(page_text, assets)
    except Exception as e:
        return None, "出口发现失败：%s" % e, []

    keywords = [k for k in [cfg.get("service_keyword") or "移动", "移动", "学生移动", "学生"] if k]

    scored = []
    for tier, group in ((0, kv_pairs), (1, bare_names)):
        for label, val in group:
            rank = len(keywords) + 1
            for i, kw in enumerate(keywords):
                if kw in (label or "") or kw in (val or ""):
                    rank = i
                    break
            scored.append((rank, tier, label, val))
    scored.sort(key=lambda x: (x[0], x[1]))

    cands = [(label, val) for _, _, label, val in scored]
    if not cands:
        return None, "页面和 JS 里没找到任何出口候选", []

    if log:
        log("发现 %d 个出口候选（按关键字优先级排序）：" % len(cands))
        for label, val in cands[:25]:
            log("    %-22s -> %s" % (label or "(无标签)", val))

    rank, tier, label, val = scored[0]
    if rank > len(keywords):
        if len(cands) == 1:
            return val, "唯一候选「%s」" % (label or val), cands
        return None, ("有 %d 个候选但没一个命中关键字，"
                      "请在 config.json 里把 service 写死" % len(cands)), cands
    return val, "关键字命中「%s」" % (label or val), cands


# ---------------------------------------------------------------------------
# 联网验证
# ---------------------------------------------------------------------------

def check_internet(cfg, log=None):
    url = cfg.get("verify_url") or "http://captive.apple.com/hotspot-detect.html"
    code, headers, body, final = http_get(url, timeout=cfg.get("http_timeout", 6), allow_redirect=True)
    text = smart_decode(body)
    if code == 200 and "Success" in text and len(text) < 2000:
        return True, "captive 探测通过"
    if code == 204:
        return True, "204 探测通过"
    if code is None:
        return False, "探测请求失败（连不上）"
    return False, "探测未通过（code=%s，可能被重定向到门户）" % code


# ---------------------------------------------------------------------------
# 校园网判定
# ---------------------------------------------------------------------------

def campus_status(cfg, log):
    """返回 (是否在校园网, 说明字典)。"""
    info = {}
    parts = urllib.parse.urlsplit(cfg["portal_candidates"][0])
    portal_host = parts.hostname or "211.83.192.55"
    portal_port = parts.port or 80
    info["portal_host"] = portal_host
    info["portal_port"] = portal_port

    info["local_ip"] = local_ip_towards(portal_host)
    info["gateway"] = default_gateway()
    if cfg.get("detect_ssid", True):
        info["ssid"], info["ssid_source"] = detect_ssid()
    else:
        info["ssid"], info["ssid_source"] = None, "已按配置关闭"
    info["portal_tcp"] = tcp_reachable(portal_host, portal_port, timeout=4)
    info["in_subnet"] = bool(info["local_ip"]) and any(
        ip_in_cidr(info["local_ip"], c) for c in cfg.get("campus_subnets", []))

    ssid_ok = None
    if info["ssid"]:
        kws = [k.lower() for k in cfg.get("ssid_keywords", [])]
        ssid_ok = any(k in info["ssid"].lower() for k in kws) if kws else True
    info["ssid_match"] = ssid_ok

    log("本机 IP：%s     默认网关：%s" % (info["local_ip"] or "未知", info["gateway"] or "未知"))
    if info["ssid"]:
        log("当前 WiFi：%s（来源：%s）" % (info["ssid"], info["ssid_source"]))
    else:
        log("当前 WiFi：识别不到（%s）" % info["ssid_source"], "WARN")
    log("校园门户 %s:%d 可达：%s" % (portal_host, portal_port, "是" if info["portal_tcp"] else "否"))
    log("本机网段命中校园网段 %s：%s" % (cfg.get("campus_subnets"), "是" if info["in_subnet"] else "否"))

    # 铁证优先：门户可达 = 一定在校园网
    if info["portal_tcp"]:
        if ssid_ok is False:
            log("WiFi 名称 '%s' 不含关键字 %s，但你确实能连到校园门户，按校园网处理。"
                % (info["ssid"], cfg.get("ssid_keywords")), "WARN")
        return True, info

    if info["in_subnet"]:
        log("在校园网段内但门户暂时不可达，仍按校园网处理（登录可能会失败）。", "WARN")
        return True, info

    if ssid_ok:
        log("WiFi 名称匹配校园网关键字，但门户不可达。", "WARN")
        return True, info

    return False, info


# ---------------------------------------------------------------------------
# 门户发现
# ---------------------------------------------------------------------------

def discover_portal(cfg, log):
    """在候选地址里找出真正能用的 ePortal。"""
    for base in cfg.get("portal_candidates", []):
        host = urllib.parse.urlsplit(base).hostname
        if not host:
            continue
        if not tcp_reachable(host, urllib.parse.urlsplit(base).port or 80, timeout=3):
            log("候选门户 %s 不可达，跳过" % base)
            continue
        code, headers, body, final = http_get(base + "/eportal/InterFace.do?method=getOnlineUserInfo",
                                              timeout=cfg.get("http_timeout", 6))
        text = smart_decode(body)
        if code == 200 and ("userIndex" in text or "result" in text):
            log("选定门户：%s" % base, "OK")
            return base
        # 只要求能通、像个门户
        if code in (200, 302) and ("eportal" in final.lower() or "eportal" in text.lower()
                                   or code == 200):
            log("选定门户：%s（弱匹配）" % base)
            return base
        log("候选门户 %s 响应异常（code=%s），跳过" % (base, code))
    return None


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def do_login(cfg, log, check_only=False, train_mode=False):
    on_campus, info = campus_status(cfg, log)
    if not on_campus:
        log("当前不在校园网（连不到校园门户，网段也不匹配），不执行任何登录动作。", "WARN")
        log("如果你确实连着 CTBU-Student，请把 portal_candidates 里的地址换成浏览器跳转时显示的地址。")
        return 2

    base = discover_portal(cfg, log)
    if not base:
        log("找不到可用的门户地址。请检查 portal_candidates 配置。", "ERR")
        return 6

    portal = Portal(base, cfg, log)

    # --- 是否已经登录 ---
    online, acct, raw = portal.online_info()
    if online:
        log("门户显示已在线，账号：%s" % (acct or "未知"), "OK")
        ok, why = check_internet(cfg, log)
        log("联网状态：%s" % why, "OK" if ok else "WARN")
        return 0

    ok, why = check_internet(cfg, log)
    if ok:
        log("虽然门户没说在线，但外网已经通了（%s），无需登录。" % why, "OK")
        return 0

    log("未登录，开始自动认证流程。")

    if check_only:
        log("--check 模式：只报告状态，不提交登录。")
        return 0

    # --- 抓 queryString ---
    query_string = portal.capture_querystring()
    if not query_string:
        log("没能抓到 queryString。", "WARN")
        log("提示：未认证时 AC 会把 http 请求 302 到门户，正常情况下一定能抓到。", "WARN")
        log("如果持续抓不到，请运行 --probe 生成诊断报告。", "WARN")
    else:
        log("queryString = %s" % query_string)

    # --- 决定服务出口（service）---
    # CTBU 门户要先选「学生移动出口」才能登录，这一步以前要手点，现在自动发现。
    service_value, service_why, service_cands = resolve_service(portal, query_string, cfg, log)
    if service_value:
        cfg["service"] = service_value
        log("使用出口 service = %s（%s）" % (service_value, service_why), "OK")
    else:
        # 关键：失败时必须清空，否则会把字面量 "auto" 当成 service 发出去
        cfg["service"] = ""
        log("没能确定出口 service：%s" % service_why, "WARN")
        log("将先按空 service 尝试；若失败，请在 config.json 里把 service 写死。", "WARN")
    svc_idx = 0

    templates = load_templates(log)
    missing = [d for d in "0123456789" if d not in templates]
    if missing:
        log("字形库缺少数字 %s，遇到时会问你一次（之后永久记住）。" % "".join(missing), "WARN")

    user = (cfg.get("username") or "").strip()
    pwd = cfg.get("password") or ""
    if not user or not pwd:
        log("config.json 里还没填 username / password。", "ERR")
        return 3

    # 密码变换策略
    base_transform = cfg.get("password_transform", "plain")
    enc_flag = bool(cfg.get("password_encrypt", False))
    strategies = [(base_transform, enc_flag)]
    if cfg.get("password_encrypt") == "auto" or str(cfg.get("password_encrypt")).lower() == "auto":
        strategies = [("plain", False), ("base64", False), ("plain", True)]

    max_captcha = int(cfg.get("max_captcha_attempts", 6))
    max_pwd = int(cfg.get("max_password_attempts", 2))

    pwd_tries = 0
    unknown_this_run = []

    for attempt in range(1, max_captcha + 1):
        log("—— 第 %d/%d 次尝试 ——" % (attempt, max_captcha))

        png = portal.fetch_captcha()
        if not png:
            log("验证码下载失败，稍后重试。", "WARN")
            time.sleep(1.0)
            continue

        transform, enc = strategies[min(pwd_tries, len(strategies) - 1)]
        sent_pwd = pwd
        if transform == "base64":
            sent_pwd = base64.b64encode(pwd.encode("utf-8")).decode("ascii")

        code, why = recognize(png, templates, expected_len=int(cfg.get("captcha_length", 4)),
                              interactive=True, log=log, unknown_sink=unknown_this_run)
        if not code:
            log("识别失败（%s），换一张。" % why)
            continue
        log("验证码识别为：%s" % code)

        result, http_code, raw = portal.login(user, sent_pwd, query_string, code, enc)
        log("服务器返回：%s" % (raw.strip()[:300] or "(空)"))

        if result is None:
            log("返回不是 JSON（code=%s），换一张重试。" % http_code, "WARN")
            continue

        if result.get("result") == "success":
            ok2, why2 = check_internet(cfg, log)
            if ok2:
                log("登录成功，外网已通（%s）。" % why2, "OK")
                return 0
            log("门户说成功，但外网探测未通过（%s），再试一次。" % why2, "WARN")
            time.sleep(1.0)
            continue

        msg = result.get("message") or ""
        kind = classify_failure(msg)

        if kind == "captcha":
            log("验证码不对，换一张重试。")
            continue
        if kind == "already":
            log("服务器提示已在线，视为成功。", "OK")
            return 0
        if kind == "service":
            # 出口没选对：换下一个候选，不消耗验证码次数
            svc_idx += 1
            if svc_idx < len(service_cands):
                label, val = service_cands[svc_idx]
                cfg["service"] = val
                log("服务器说出口不对（%s），换成候选 #%d：%s -> %s"
                    % (msg, svc_idx + 1, label or "(无标签)", val), "WARN")
                continue
            log("服务器拒绝：%s" % msg, "ERR")
            log("已把 %d 个出口候选都试过。请在校园网里跑一次 --probe，"
                "把报告里的「出口自动解析结果」发我。" % max(len(service_cands), 1), "ERR")
            return 4
        if kind in ("password", "username"):
            pwd_tries += 1
            if pwd_tries < max_pwd and pwd_tries < len(strategies):
                log("服务器拒绝：%s —— 换密码编码方式再试一次。" % msg, "WARN")
                continue
            log("服务器拒绝：%s" % msg, "ERR")
            log("已停止重试，避免账号被锁定。请核对 config.json 里的学号与统一身份认证密码。", "ERR")
            return 4

        log("登录未成功（%s），重试。" % (msg or "无信息"), "WARN")
        time.sleep(0.8)

    # 收尾
    if "0" in unknown_this_run or "5" in unknown_this_run:
        pass
    log("验证码尝试次数用尽，仍未登录成功。", "ERR")
    log("建议：连上校园网后运行  python3 campus_login.py --train   把缺的字形补齐。", "WARN")
    return 5


# ---------------------------------------------------------------------------
# 训练模式
# ---------------------------------------------------------------------------

def do_train(cfg, log):
    on_campus, info = campus_status(cfg, log)
    if not on_campus:
        log("训练需要连着校园网（要能拉到门户验证码），当前不在。", "ERR")
        return 2
    base = discover_portal(cfg, log)
    if not base:
        log("找不到门户。", "ERR")
        return 6
    portal = Portal(base, cfg, log)
    templates = load_templates(log)

    log("开始补齐字形库。当前已有：%s" % "".join(sorted(templates)))
    rounds = 0
    while rounds < 40:
        missing = [d for d in "0123456789" if d not in templates]
        if not missing:
            log("10 个数字字形已全部就绪！", "OK")
            return 0
        rounds += 1
        png = portal.fetch_captcha()
        if not png:
            log("验证码下载失败，重试。", "WARN")
            continue
        unknown = []
        code, why = recognize(png, templates, expected_len=int(cfg.get("captcha_length", 4)),
                              interactive=True, log=log, unknown_sink=unknown)
        if code:
            log("第 %d 张：识别为 %s（已知数字）" % (rounds, code))
        else:
            log("第 %d 张：%s" % (rounds, why or "需要人工确认"))
        time.sleep(0.3)

    log("40 张还没补齐，剩下的数字出现概率较低，可以过几天再跑一次。", "WARN")
    return 0


# ---------------------------------------------------------------------------
# 诊断模式
# ---------------------------------------------------------------------------

def do_probe(cfg, log, probe_login=False):
    lines = []

    def flush():
        """每一行都立刻落盘。

        校园网里没有外网，出问题时只能靠这份文件回传；
        如果只在最后统一写，一旦中途被关窗/断网打断就什么都留不下。
        """
        try:
            with open(REPORT_PATH, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass

    def add(s=""):
        lines.append(s)
        flush()
        log(s)

    def note(tag):
        lines.append(tag)
        flush()

    add("CTBU 校园网自动登录 · 诊断报告")
    add("生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    add("程序版本：%s" % VERSION)
    add("操作系统：%s %s  Python %s" % (platform.system(), platform.release(), platform.python_version()))
    add("脚本位置：%s" % HERE)
    add("")

    add("=== 1. 网络环境 ===")
    on_campus, info = campus_status(cfg, log)
    add("本机 IP        : %s" % info.get("local_ip"))
    add("默认网关      : %s" % info.get("gateway"))
    add("WiFi 名称     : %s" % (info.get("ssid") or "(识别不到)"))
    add("SSID 来源     : %s" % info.get("ssid_source"))
    add("匹配 CTBU     : %s" % info.get("ssid_match"))
    add("校园网段命中  : %s" % info.get("in_subnet"))
    add("门户 80 可达  : %s" % info.get("portal_tcp"))
    add("判定在校园网  : %s" % on_campus)
    add("")

    add("=== 2. Captive 门户探测 ===")
    for url in cfg.get("captive_probe_urls", []):
        code, headers, body, final = http_get(url, timeout=cfg.get("http_timeout", 6),
                                             allow_redirect=False)
        loc = headers.get("Location") or headers.get("location") or ""
        add("URL   : %s" % url)
        add("  code=%s  redirect=%s" % (code, loc[:300] or "(无)"))
        add("  body=%s" % smart_decode(body)[:200].replace("\n", " "))
    add("")

    add("=== 3. 门户发现 ===")
    base = discover_portal(cfg, log)
    add("选定门户：%s" % base)
    if not base:
        add("门户不可达，后续探测跳过。")
        report = "\n".join(lines)
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            f.write(report)
        log("诊断报告已写入 %s" % REPORT_PATH, "OK")
        return 6

    portal = Portal(base, cfg, log)

    add("")
    add("=== 4. 登录状态 ===")
    online, acct, raw = portal.online_info()
    add("在线       : %s" % online)
    add("账号       : %s" % acct)
    add("原始返回   : %s" % (raw or "").strip()[:500])
    add("")

    add("=== 5. 抓 queryString ===")
    qs = portal.capture_querystring()
    add("queryString: %s" % (qs or "(没抓到)"))
    add("")

    add("=== 6. 验证码与识别 ===")
    templates = load_templates(log)
    add("已有字形   : %s" % "".join(sorted(templates)))
    add("缺失字形   : %s" % ("".join(d for d in "0123456789" if d not in templates) or "无"))
    for i in range(3):
        png = portal.fetch_captcha()
        if not png:
            add("第 %d 张：下载失败" % (i + 1))
            continue
        path = os.path.join(HERE, "captcha-sample-%d.png" % (i + 1))
        try:
            with open(path, "wb") as f:
                f.write(png)
        except Exception:
            pass
        unknown = []
        code, why = recognize(png, templates, expected_len=int(cfg.get("captcha_length", 4)),
                              interactive=False, log=None, unknown_sink=unknown)
        add("第 %d 张：%s" % (i + 1, code if code else "未识别（%s）" % why))
        try:
            glyphs, ginfo = image_to_glyphs(png)
            add("  %s" % ginfo)
            for w, rows in glyphs:
                add("  字形宽 %d：" % w)
                for r in rows:
                    add("    " + "".join("#" if (r >> (w - 1 - j)) & 1 else "." for j in range(w)))
        except Exception as e:
            add("  字形拆分失败：%s" % e)
        time.sleep(0.2)

    add("")
    add("=== 7. 登录页与前端 JS 抓取 ===")
    page_url = base + "/eportal/index.jsp"
    if qs:
        page_url += "?" + qs
    else:
        page_url += "?wlanuserip=%s&wlanacname=&nasip=&ssid=CTBU-Student&mac=&t=wireless-v2" % (
            info.get("local_ip") or "0.0.0.0")
    add("抓取地址：%s" % page_url)
    code, headers, body, final = http_get(page_url, timeout=cfg.get("http_timeout", 6),
                                          cookie_jar=portal.jar)
    add("HTTP %s，正文 %d 字节，最终地址 %s" % (code, len(body), final))
    page_path = os.path.join(HERE, "portal-login.html")
    try:
        with open(page_path, "wb") as f:
            f.write(body)
        add("已保存登录页原文：portal-login.html")
    except Exception as e:
        add("登录页保存失败：%s" % e)

    text = smart_decode(body)
    js_refs = re.findall(r"""(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", text)
    add("页面引用的 JS：%s" % (js_refs or "无"))

    # 隐藏字段：passwordEncrypt 决定密码是否需要加密后再提交，是关键开关
    add("")
    add("--- 登录页隐藏字段 ---")
    hidden_count = 0
    for m in re.finditer(r"<input[^>]*>", text, re.I):
        tag = m.group(0)
        if "hidden" in tag.lower() or "passwordEncrypt" in tag or "net_access_type" in tag:
            add("  " + re.sub(r"\s+", " ", tag)[:300])
            hidden_count += 1
    if hidden_count == 0:
        add("  （没找到隐藏 input，可能由 JS 动态生成）")
    pe = None
    for pat in (r"""id=["']passwordEncrypt["'][^>]*value=["']([^"']*)["']""",
                r"""value=["']([^"']*)["'][^>]*id=["']passwordEncrypt["']""",
                r"""name=["']passwordEncrypt["'][^>]*value=["']([^"']*)["']"""):
        m = re.search(pat, text, re.I)
        if m:
            pe = m.group(1)
            break
    add("passwordEncrypt = %s   ← 决定密码是否加密提交" % (pe if pe is not None else "(页面上没找到)"))
    mac_m = re.search(r"""[\?&]mac=([^&\s"'<>]+)""", qs or "")
    add("queryString 里的 mac = %s   ← 加密时密码要拼上它" % (mac_m.group(1) if mac_m else "(没有)"))

    saved = []
    for ref in js_refs[:8]:
        if ref.startswith("http://") or ref.startswith("https://"):
            js_url = ref
        elif ref.startswith("/"):
            js_url = base + ref
        else:
            js_url = base + "/eportal/" + ref
        jcode, jheaders, jbody, jfinal = http_get(js_url, timeout=cfg.get("http_timeout", 6),
                                                  cookie_jar=portal.jar)
        if jcode == 200 and jbody:
            name = os.path.basename(urllib.parse.urlsplit(ref).path) or "ref.js"
            out_name = "portal-js-" + name
            try:
                with open(os.path.join(HERE, out_name), "wb") as f:
                    f.write(jbody)
                saved.append(out_name)
                add("  %s -> %s（%d 字节）" % (js_url, out_name, len(jbody)))
            except Exception as e:
                add("  %s 保存失败：%s" % (js_url, e))
        else:
            add("  %s 下载失败（HTTP %s）" % (js_url, jcode))

    # 在 JS / 页面里找密码加密相关线索
    hints = []
    for blob, tag in [(text, "login.html")] + [
            (smart_decode(open(os.path.join(HERE, n), "rb").read()), n) for n in saved]:
        for kw in ("passwordEncrypt", "encrypt", "publicKey", "setPublicKey", "RSA", "base64"):
            if kw in blob:
                hints.append("%s 里出现 %s" % (tag, kw))
    add("加密相关线索：%s" % ("；".join(sorted(set(hints))) or "无（很可能就是明文提交）"))

    # ---- 服务出口（service）线索 ----
    # CTBU 门户首页有「统一身份用户 / 其他用户」+ 一排出口（教职员工专用 / 学生移动出口 /
    # 学生联通出口 / 学生电信出口...），登录必须带上被选中的那个出口对应的 service 值。
    add("")
    add("--- 服务出口（service）线索 ---")
    blobs = [(text, "login.html")] + [
        (smart_decode(open(os.path.join(HERE, n), "rb").read()), n) for n in saved]

    # 页面可见文字（去掉标签），便于直接看清出口名称
    plain = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    plain = re.sub(r"<style.*?</style>", " ", plain, flags=re.S | re.I)
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = re.sub(r"&nbsp;?", " ", plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    if plain:
        add("登录页可见文字（前 900 字）：")
        add("  " + plain[:900])

    seen = set()
    emitted = 0
    for blob, tag in blobs:
        for pat, label in ((r".{0,120}service.{0,220}", "service"),
                           (r".{0,80}出口.{0,120}", "出口")):
            for m in re.finditer(pat, blob, re.I | re.S):
                frag = re.sub(r"\s+", " ", m.group(0)).strip()
                key = (tag, label, frag[:100])
                if key in seen:
                    continue
                seen.add(key)
                emitted += 1
                if emitted > 60:
                    break
                add("  [%s/%s] %s" % (tag, label, frag[:320]))
    if not emitted:
        add("  （页面和 JS 里都没有 service 字样，可能出口是登录后才选）")

    # 页面/JS 里出现过的、可能返回出口列表的地址
    urls = set()
    for blob, tag in blobs:
        for m in re.finditer(r"""["']([^"']*(?:[Ss]ervice|getService|servicelist)[^"']*)["']""", blob):
            u = m.group(1)
            if len(u) < 200 and not u.startswith("data:"):
                urls.add("%s <- %s" % (u, tag))
    if urls:
        add("疑似出口列表接口：")
        for u in sorted(urls)[:15]:
            add("  %s" % u)

    # 用与登录时相同的逻辑解析一遍出口，确保报告里给出最终会用的那个值
    add("")
    add("--- 出口自动解析结果（登录时会用这个）---")
    try:
        assets_map = {}
        for n in saved:
            try:
                assets_map[n] = smart_decode(open(os.path.join(HERE, n), "rb").read())
            except Exception:
                pass
        kv_pairs, bare_names = discover_services(text, assets_map)
        add("带 service 值的候选（%d 个）：" % len(kv_pairs))
        for label, val in kv_pairs[:30]:
            add("  %-24s -> %s" % (label or "(无标签)", val))
        add("只有中文名的兜底候选（%d 个）：" % len(bare_names))
        for label, val in bare_names[:15]:
            add("  %s" % label)
        chosen, why, cand_list = resolve_service(portal, qs, cfg, log=None)
        add("最终选择：%s（%s）" % (chosen if chosen else "(没挑出来)", why))
        add("重试顺序：%s" % (" -> ".join(v for _, v in cand_list[:8]) or "(无)"))
    except Exception as e:
        add("出口解析失败：%s" % e)

    # 顺手存一份去标签后的纯文本，方便直接阅读
    try:
        with open(os.path.join(HERE, "portal-login.txt"), "w", encoding="utf-8") as f:
            f.write(plain)
        add("登录页纯文本已保存：portal-login.txt")
    except Exception:
        pass

    # ---- RSA 公钥探测 ----
    # security.js 是 RSAUtils（RSA 加密库），说明密码可能是 RSA 加密后提交的。
    # 公钥通常由一个接口下发。这里把常见接口都探一遍，并从 JS 里搜长十六进制串。
    add("")
    add("=== 8. RSA 公钥探测 ===")
    key_endpoints = [
        "InterFace.do?method=getPublicKey",
        "InterFace.do?method=getKeyPair",
        "InterFace.do?method=getRSAKey",
        "userV2.do?method=getPublicKey",
        "userV2.do?method=getKeyPair",
        "InterFace.do?method=pageInfo",
    ]
    for ep in key_endpoints:
        url = base + "/eportal/" + ep
        kc, kh, kb, kf = http_get(url, timeout=cfg.get("http_timeout", 6), cookie_jar=portal.jar)
        ktext = smart_decode(kb)
        add("  %-40s code=%s len=%d" % (ep, kc, len(kb)))
        if ktext.strip():
            add("      %s" % re.sub(r"\s+", " ", ktext)[:400])

    # 从页面和 JS 里找公钥痕迹
    add("")
    add("--- JS 里的密钥痕迹 ---")
    allblobs = [(text, "login.html")] + [
        (smart_decode(open(os.path.join(HERE, n), "rb").read()), n) for n in saved]
    for kw in ("RSAUtils", "setMaxDigits", "getKeyPair", "encryptedString",
               "publicKey", "modulus", "exponent", "passwordEncrypt", "encrypt"):
        hits = []
        for blob, tag in allblobs:
            if kw in blob:
                hits.append(tag)
        if hits:
            add("  %-18s 出现在：%s" % (kw, ", ".join(hits)))

    # 长十六进制串（很可能是 RSA 模数）
    add("")
    add("--- 页面/JS 里的长十六进制串（疑似 RSA 模数）---")
    found_hex = set()
    for blob, tag in allblobs:
        for m in re.finditer(r"""['"]([0-9a-fA-F]{64,512})['"]""", blob):
            found_hex.add((tag, m.group(1)[:80] + ("..." if len(m.group(1)) > 80 else ""),
                           len(m.group(1))))
    if found_hex:
        for tag, preview, ln in sorted(found_hex)[:10]:
            add("  [%s] 长度%d：%s" % (tag, ln, preview))
    else:
        add("  （没找到，公钥可能是运行时通过接口下发的，见上面的接口探测结果）")

    # 在 JS 里找 RSA 调用点，直接看它怎么用
    for blob, tag in allblobs:
        if "RSAUtils" in blob and "encryptedString" in blob:
            add("")
            add("--- %s 中的 RSA 调用上下文 ---" % tag)
            for m in list(re.finditer(r".{200}encryptedString.{260}", blob, re.S))[:3]:
                add("  " + re.sub(r"\s+", " ", m.group(0))[:460])
            for m in list(re.finditer(r".{160}getKeyPair.{220}", blob, re.S))[:3]:
                add("  " + re.sub(r"\s+", " ", m.group(0))[:380])

    # ---- SSO（统一身份认证）跳转探测 ----
    # 出口按钮的真实行为是 redirectSSO(name) -> login_sso.jsp?...&serviceName=<双重编码>
    add("")
    add("=== 9. SSO 跳转探测（login_sso.jsp）===")
    if not qs:
        add("  没有 queryString，跳过。")
    else:
        for name in ("移动", "default"):
            enc = urllib.parse.quote(urllib.parse.quote(name))
            sso_url = base + "/eportal/login_sso.jsp?" + qs + "&serviceName=" + enc
            sc, sh, sb, sf = http_get(sso_url, timeout=cfg.get("http_timeout", 6),
                                      cookie_jar=portal.jar, allow_redirect=False)
            loc = sh.get("Location") or sh.get("location") or ""
            add("  serviceName=%s（编码 %s）" % (name, enc))
            add("    code=%s  Location=%s" % (sc, loc[:400] or "(无)"))
            stext = smart_decode(sb)
            if stext.strip():
                add("    正文(%d字节)：%s" % (len(sb), re.sub(r"\s+", " ", stext)[:400]))
                for m in re.finditer(r"""(?:action|href|location)\s*[=:]\s*["']([^"']{1,200})["']""",
                                     stext, re.I):
                    add("      链接: %s" % m.group(1)[:200])
            # 再跟一层，看看最终落到哪
            if loc:
                fc, fh, fb, ff = http_get(loc, timeout=cfg.get("http_timeout", 6),
                                          cookie_jar=portal.jar)
                add("    跟随一跳 -> code=%s 最终=%s" % (fc, ff[:300]))
                ftxt = smart_decode(fb)
                if ftxt.strip():
                    add("      正文(%d字节)：%s" % (len(fb), re.sub(r"\s+", " ", ftxt)[:500]))

    if probe_login:
        add("")
        add("=== 8. 登录接口探测（用假账号，不碰你的真账号） ===")
        result, code, raw = portal.login("test0000000", "wrongpass", qs or "", "0000", False)
        add("code=%s" % code)
        add("raw =%s" % (raw or "").strip()[:500])

    add("")
    add("=== 完 ===")
    report = "\n".join(lines)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)
    log("诊断报告已写入：%s" % REPORT_PATH, "OK")
    log("把这份文件发给我，我就能把细节对准。")
    return 0


# ---------------------------------------------------------------------------
# 离线自检
# ---------------------------------------------------------------------------

def do_selftest(log):
    templates = load_templates(log)
    log("内置字形：%s" % "".join(sorted(BUILTIN_TEMPLATES)))
    log("当前字形库：%s" % "".join(sorted(templates)))
    ok_all = True
    for expected, b64 in SELFTEST_SAMPLES:
        png = base64.b64decode(b64)
        code, why = recognize(png, templates, expected_len=len(expected), interactive=False)
        good = (code == expected)
        ok_all = ok_all and good
        log("样本 %s -> 识别 %s   %s" % (expected, code or "(失败)", "✔" if good else "✘ %s" % why),
            "OK" if good else "ERR")
    if ok_all:
        log("离线自检全部通过：识别引擎工作正常（准确率 100%）。", "OK")
        return 0
    log("离线自检未通过，请把上面的输出发给我。", "ERR")
    return 1


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main():
    setup_console_encoding()

    parser = argparse.ArgumentParser(
        description="CTBU 校园网自动登录（重庆工商大学 CTBU-Student）")
    parser.add_argument("--check", action="store_true", help="只看状态，不提交登录")
    parser.add_argument("--train", action="store_true", help="校园网内补齐缺失字形（跑一次即可）")
    parser.add_argument("--probe", action="store_true", help="校园网内生成诊断报告")
    parser.add_argument("--probe-login", action="store_true", help="诊断时额外探测登录接口（用假账号）")
    parser.add_argument("--self-test", action="store_true", help="离线自检识别引擎，不联网")
    parser.add_argument("--quiet", action="store_true", help="不写日志文件")
    parser.add_argument("--config", metavar="路径", default=None, help="指定配置文件（默认同目录 config.json）")
    args = parser.parse_args()

    log = Log(None if args.quiet else LOG_PATH)

    if args.self_test:
        code = do_selftest(log)
        log.close()
        return code

    cfg = load_config(log, args.config)
    if cfg is None:
        log.close()
        return 3

    try:
        if args.probe or args.probe_login:
            code = do_probe(cfg, log, probe_login=args.probe_login)
        elif args.train:
            code = do_train(cfg, log)
        else:
            code = do_login(cfg, log, check_only=args.check)
    except KeyboardInterrupt:
        log("已取消。", "WARN")
        code = 1
    except Exception as e:
        import traceback
        log("未预期的错误：%s" % e, "ERR")
        tb = traceback.format_exc()
        for line in tb.splitlines():
            log("  " + line, "ERR")
        # 诊断模式下把崩溃现场也追加进报告，否则这一趟校园网就白跑了
        if args.probe or args.probe_login:
            try:
                with open(REPORT_PATH, "a", encoding="utf-8") as f:
                    f.write("\n=== 诊断过程崩溃 ===\n")
                    f.write("错误：%s\n" % e)
                    f.write(tb)
                log("崩溃现场已追加到 %s" % REPORT_PATH, "WARN")
            except Exception:
                pass
        code = 1

    log.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
