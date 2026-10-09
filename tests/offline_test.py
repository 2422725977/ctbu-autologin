#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线端到端测试 —— 用一个"模拟锐捷 ePortal"把整条链路跑通，不需要校园网。

模拟服务端严格复刻我们在真实门户上观测到的行为：
  * 未认证时任意 http 请求 302 到 /eportal/index.jsp?wlanuserip=...&wlanacname=...&nasip=...
  * GET  /eportal/validcode                  -> 80x30 PNG 验证码（会话绑定）
  * GET  /eportal/InterFace.do?method=getOnlineUserInfo -> JSON
  * POST /eportal/InterFace.do?method=login  -> 校验 queryString / validcode / 账号密码
  * queryString 为空时返回 {"result":"fail","message":"用户名不能为空"}
    —— 这正是我们在真实门户上用空 body 测试时观察到的原始行为
  * JSON 一律 UTF-8（与真实门户一致）

用法：
    python3 tests/offline_test.py
"""

import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import campus_login as cl  # noqa: E402

USER = "2025000000"  # 虚构学号，切勿写入真实账号
PWD = "TestPassword123"
QUERY = ("wlanuserip=127.0.0.1&wlanacname=MOCK-AC&nasip=127.0.0.1"
         "&ssid=CTBU-Student&mac=aabbccddeeff&t=wireless-v2"
         "&url=http%3A%2F%2Fwww.baidu.com")

CAPTCHA_IMAGES = [(ans, base64.b64decode(b64)) for ans, b64 in cl.SELFTEST_SAMPLES]


class State(object):
    def __init__(self):
        self.logged_in = False
        self.sessions = {}            # sid -> 验证码答案
        self.captcha_seq = 0
        self.captcha_served = 0
        self.login_posts = 0
        self.captcha_rejects_left = 0
        self.last_querystring = None
        self.last_service = None
        self.expected_user = USER
        self.expected_pwd = PWD


STATE = State()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # --- 工具 ---
    def log_message(self, *a):
        pass

    def sid(self):
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("JSESSIONID="):
                return part.split("=", 1)[1]
        return None

    def send(self, code, body=b"", ctype="text/html;charset=UTF-8", extra=None, sid=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if sid:
            self.send_header("Set-Cookie", "JSESSIONID=%s; Path=/" % sid)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def json_resp(self, obj, sid=None):
        self.send(200, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                  "application/json;charset=UTF-8", sid=sid)

    def portal_login_url(self):
        return "/eportal/index.jsp?" + QUERY

    # --- GET ---
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        sid = self.sid() or ("S%d" % (len(STATE.sessions) + 1))

        if path == "/hotspot-detect.html":
            if STATE.logged_in:
                self.send(200, b"<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
                               b"<BODY>Success</BODY></HTML>", sid=sid)
            else:
                self.send(302, b"", extra={"Location": "http://%s%s"
                                           % (self.headers.get("Host"), self.portal_login_url())},
                          sid=sid)
            return

        if path == "/":
            if STATE.logged_in:
                self.send(200, b"ok", sid=sid)
            else:
                self.send(302, b"", extra={"Location": "http://%s%s"
                                           % (self.headers.get("Host"), self.portal_login_url())},
                          sid=sid)
            return

        if path == "/eportal/index.jsp":
            html = ("<html><head><title>校园网认证</title>"
                    "<script src='/eportal/interface/index_files/js/AuthInterFace.js'></script>"
                    "</head><body><form id='loginForm'>"
                    "<input id='userId'><input id='password' type='password'>"
                    "<img id='validcode' src='/eportal/validcode'></form></body></html>")
            self.send(200, html.encode("utf-8"), "text/html;charset=GBK", sid=sid)
            return

        if path == "/eportal/validcode":
            ans, png = CAPTCHA_IMAGES[STATE.captcha_seq % len(CAPTCHA_IMAGES)]
            STATE.captcha_seq += 1
            STATE.captcha_served += 1
            STATE.sessions[sid] = ans
            self.send(200, png, "image/png", sid=sid)
            return

        if path == "/eportal/interface/index_files/js/AuthInterFace.js":
            # 模拟真实门户的登录脚本：出口列表就写在前端 JS 里（真实门户也是这样）
            js = ("// mock AuthInterFace.js\n"
                  "var serviceList = [\n"
                  "  {name:'教职员工专用', service:'staff_only'},\n"
                  "  {name:'学生移动出口', service:'student_mobile'},\n"
                  "  {name:'学生联通出口', service:'student_unicom'},\n"
                  "  {name:'学生电信出口', service:'student_telecom'}\n"
                  "];\n"
                  "function selectService(name, service){ window.service = service; }\n"
                  "function loginSubmit(){\n"
                  "  var passwordEncrypt = false;\n"
                  "  $.post('/eportal/InterFace.do?method=login', {\n"
                  "    userId:userId, password:password, service:service,\n"
                  "    queryString:queryString, operatorPwd:'', operatorUserId:'',\n"
                  "    validcode:validcode, passwordEncrypt:passwordEncrypt});\n"
                  "}\n").encode("utf-8")
            self.send(200, js, "application/javascript;charset=UTF-8", sid=sid)
            return

        if path == "/eportal/InterFace.do":
            qs = urllib.parse.parse_qs(parsed.query)
            method = (qs.get("method") or [""])[0]
            if method == "getOnlineUserInfo":
                if STATE.logged_in:
                    idx = ("3264336637313937303830313737313162616138346531306336656231646630"
                           "5f31302e3230332e31332e3137345f" + USER.encode().hex())
                    self.json_resp({"userIndex": idx, "result": "success",
                                    "message": "查询成功", "userId": USER}, sid=sid)
                else:
                    self.json_resp({"userIndex": None, "result": "fail",
                                    "message": "用户未在线"}, sid=sid)
                return
            if method == "pageInfo":
                self.send(200, b"var pageInfo = {\"queryString\":\"%s\"};"
                          % QUERY.encode("utf-8"), "text/html;charset=UTF-8", sid=sid)
                return
            if method == "logout":
                STATE.logged_in = False
                self.json_resp({"result": "success", "message": "下线成功"}, sid=sid)
                return
            self.json_resp({"result": "fail", "message": "不支持的 method"}, sid=sid)
            return

        self.send(404, b"not found", sid=sid)

    # --- POST ---
    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        sid = self.sid() or "anon"

        if parsed.path == "/eportal/InterFace.do":
            method = (urllib.parse.parse_qs(parsed.query).get("method") or [""])[0]
            if method != "login":
                self.json_resp({"result": "fail", "message": "不支持的 method"}, sid=sid)
                return

            STATE.login_posts += 1
            qs = (form.get("queryString") or "").strip()
            STATE.last_querystring = qs
            STATE.last_service = form.get("service") or ""

            # 复刻真实行为：queryString 为空 -> 用户名不能为空
            if not qs:
                self.json_resp({"userIndex": None, "result": "fail",
                                "message": "用户名不能为空"}, sid=sid)
                return

            # 复刻 CTBU 门户：必须先选对「学生移动出口」才能登录
            if (form.get("service") or "") != "student_mobile":
                self.json_resp({"userIndex": None, "result": "fail",
                                "message": "请先选择服务出口"}, sid=sid)
                return

            if STATE.captcha_rejects_left > 0:
                STATE.captcha_rejects_left -= 1
                self.json_resp({"userIndex": None, "result": "fail",
                                "message": "验证码错误"}, sid=sid)
                return

            expect = STATE.sessions.get(sid)
            if not expect or (form.get("validcode") or "") != expect:
                self.json_resp({"userIndex": None, "result": "fail",
                                "message": "验证码错误"}, sid=sid)
                return

            if (form.get("userId") or "") != STATE.expected_user or \
               (form.get("password") or "") != STATE.expected_pwd:
                self.json_resp({"userIndex": None, "result": "fail",
                                "message": "用户名或密码错误"}, sid=sid)
                return

            STATE.logged_in = True
            self.json_resp({"userIndex": "mock_" + form.get("userId", ""),
                            "result": "success", "message": "认证成功"}, sid=sid)
            return

        self.json_resp({"result": "fail", "message": "not found"}, sid=sid)


# ---------------------------------------------------------------------------
# 测试脚手架
# ---------------------------------------------------------------------------

def start_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def make_config(port, **over):
    cfg = {
        "username": USER,
        "password": PWD,
        "portal_candidates": ["http://127.0.0.1:%d" % port],
        "ssid_keywords": ["CTBU"],
        "detect_ssid": False,
        "campus_subnets": ["127.0.0.0/8"],
        "captive_probe_urls": ["http://127.0.0.1:%d/hotspot-detect.html" % port],
        "verify_url": "http://127.0.0.1:%d/hotspot-detect.html" % port,
        "password_encrypt": False,
    }
    cfg.update(over)
    path = os.path.join(HERE, "test-config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return path


def run_login(cfg_path, extra_args=None, timeout=90):
    args = [sys.executable, os.path.join(ROOT, "campus_login.py"),
            "--config", cfg_path, "--quiet"] + (extra_args or [])
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, cwd=ROOT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("  %s %s%s" % ("✔" if cond else "✘", name, ("  —— " + detail) if detail and not cond else ""))
    return cond


def scenario(name, fn):
    global STATE
    STATE = State()
    import campus_login
    print("\n【%s】" % name)
    try:
        fn()
    except Exception as e:
        import traceback
        check(name + " (异常)", False, "%s\n%s" % (e, traceback.format_exc()))


def main():
    srv, port = start_server()
    print("模拟锐捷 ePortal 已启动：http://127.0.0.1:%d" % port)

    # --- 场景 1：全新登录成功 ---
    def s1():
        cfg = make_config(port)
        code, out = run_login(cfg)
        check("退出码为 0", code == 0, "实际 %s\n%s" % (code, out))
        check("模拟门户进入已登录状态", STATE.logged_in)
        check("queryString 非空（核心字段抓取成功）",
              bool(STATE.last_querystring) and "wlanuserip" in (STATE.last_querystring or ""),
              "实际 %r" % STATE.last_querystring)
        check("登录 POST 恰好 1 次", STATE.login_posts == 1, "实际 %d" % STATE.login_posts)
        check("验证码下载 1 次", STATE.captcha_served == 1, "实际 %d" % STATE.captcha_served)
        check("日志里出现识别出的验证码", "验证码识别为" in out)
        check("日志里出现登录成功", "登录成功" in out)
        # 出口自动发现：门户要求带对「学生移动出口」，程序必须自己从 JS 里挖出来
        check("自动选中「学生移动出口」", STATE.last_service == "student_mobile",
              "实际提交的 service=%r" % STATE.last_service)
        check("日志里报告了出口选择", "使用出口 service" in out)
        check("出口候选被打印出来", "学生移动出口" in out)
    scenario("场景 1：全新登录成功（含出口自动发现）", s1)

    # --- 场景 2：已登录时不做多余动作 ---
    def s2():
        STATE.logged_in = True
        cfg = make_config(port)
        code, out = run_login(cfg)
        check("退出码为 0", code == 0, "实际 %s\n%s" % (code, out))
        check("没有发起登录 POST", STATE.login_posts == 0, "实际 %d" % STATE.login_posts)
        check("没有下载验证码", STATE.captcha_served == 0, "实际 %d" % STATE.captcha_served)
        check("日志声明已在线", "已在线" in out)
    scenario("场景 2：已经登录，直接退出", s2)

    # --- 场景 3：密码错误 -> 立即停止，不锁号 ---
    def s3():
        cfg = make_config(port, password="WrongPassword")
        code, out = run_login(cfg)
        check("退出码为 4（账号密码被拒）", code == 4, "实际 %s\n%s" % (code, out))
        check("只提交了 1 次密码（不暴力重试）", STATE.login_posts == 1,
              "实际 %d" % STATE.login_posts)
        check("日志给出明确提示", "已停止重试" in out)
        check("没有误判为成功", not STATE.logged_in)
    scenario("场景 3：密码错误应立即停止", s3)

    # --- 场景 4：验证码被判错两次后成功（重试链路） ---
    def s4():
        STATE.captcha_rejects_left = 2
        cfg = make_config(port)
        code, out = run_login(cfg)
        check("退出码为 0", code == 0, "实际 %s\n%s" % (code, out))
        check("共提交 3 次登录", STATE.login_posts == 3, "实际 %d" % STATE.login_posts)
        check("共下载 3 张验证码", STATE.captcha_served == 3, "实际 %d" % STATE.captcha_served)
        check("最终登录成功", STATE.logged_in)
    scenario("场景 4：验证码错误自动换图重试", s4)

    # --- 场景 5：不在校园网 -> 不动手 ---
    def s5():
        cfg = make_config(port, portal_candidates=["http://127.0.0.1:1"],
                          campus_subnets=[], captive_probe_urls=[])
        code, out = run_login(cfg)
        check("退出码为 2（不在校园网）", code == 2, "实际 %s\n%s" % (code, out))
        check("明确说明没有执行任何动作", "不执行任何登录动作" in out)
        check("没有发起登录 POST", STATE.login_posts == 0)
    scenario("场景 5：不在校园网时不动作", s5)

    # --- 场景 6：诊断模式能抓到登录页与前端 JS，且不泄露密码 ---
    def s6():
        cfg = make_config(port)
        code, out = run_login(cfg, ["--probe"])
        check("退出码为 0", code == 0, "实际 %s\n%s" % (code, out))
        check("生成了诊断报告", os.path.exists(cl.REPORT_PATH))
        check("抓到了登录页原文", "已保存登录页原文" in out)
        check("抓到了 AuthInterFace.js", "portal-js-AuthInterFace.js" in out)
        check("识别出加密线索", "加密相关线索" in out)
        report = open(cl.REPORT_PATH, encoding="utf-8").read()
        check("报告里含 queryString", "queryString:" in report and "wlanuserip" in report)
        check("报告里含验证码字形图", "字形宽" in report)
        # 安全断言：诊断报告绝不能包含真实密码
        check("诊断报告不含真实密码", PWD not in report)
        check("诊断报告不含配置里的密码字段", '"password"' not in report)
    scenario("场景 6：诊断模式抓登录页与 JS", s6)

    # --- 场景 7：日志文件必须真的有内容（回归 strftime 格式化 bug） ---
    # 曾经的 bug：time.strftime("[%Y-...] 启动 %s" % VERSION) 里 % 优先级高于函数调用，
    # 整个字符串被当成格式串 -> ValueError -> 被 except 静默吞掉 -> 文件日志全程失效，
    # 只在日志里留下一串分隔线。这种静默失效必须用测试守住。
    def s7():
        cfg = make_config(port)
        logpath = os.path.join(ROOT, "login.log")
        if os.path.exists(logpath):
            os.remove(logpath)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "campus_login.py"),
                            "--config", cfg, "--check"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           cwd=ROOT, timeout=90)
        txt = open(logpath, encoding="utf-8").read() if os.path.exists(logpath) else ""
        check("日志文件已生成", os.path.exists(logpath))
        check("日志里有启动行（strftime bug 回归）", "启动 campus_login" in txt,
              "实际内容：%r" % txt[:300])
        check("日志里有实际运行内容", ("本机 IP" in txt) or ("校园门户" in txt),
              "实际内容：%r" % txt[:500])
        check("日志行数合理（>3 行）", len(txt.splitlines()) > 3,
              "实际 %d 行" % len(txt.splitlines()))
    scenario("场景 7：日志文件必须真的有内容", s7)

    srv.shutdown()

    # 清理测试产生的文件，保持交付目录干净
    for name in ("test-config.json", "diagnostic-report.txt", "portal-login.html",
                 "portal-login.txt",
                 "portal-js-AuthInterFace.js", "captcha-sample-1.png",
                 "captcha-sample-2.png", "captcha-sample-3.png", "login.log"):
        for base_dir in (ROOT, HERE):
            try:
                os.remove(os.path.join(base_dir, name))
            except OSError:
                pass

    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print("结果：%d/%d 项通过" % (passed, total))
    for name, ok, detail in RESULTS:
        if not ok:
            print("  失败：%s\n%s" % (name, detail))
    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
