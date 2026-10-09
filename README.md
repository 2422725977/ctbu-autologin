# CTBU 校园网自动登录（重庆工商大学 · CTBU-Student）

连上 `CTBU-Student` 之后双击一下，自动填学号、密码和验证码，完成校园网认证。
macOS 和 Windows 通用，**不需要安装任何第三方库**（不用 requests、不用 PIL、不用 ddddocr、不用浏览器自动化）。

---

## 一、快速开始

### 1. 填账号

用记事本 / 文本编辑器打开同目录的 `config.json`，把这两行填上：

```json
"username": "你的10位学号",
"password": "你的统一身份认证密码",
```

> 密码只保存在你自己电脑的这个文件里，程序不会把它发到任何第三方。

### 2. 连上 WiFi

连 `CTBU-Student`（或 `CTBU`）。

### 3. 双击运行

| 系统 | 双击这个文件 |
|---|---|
| macOS | `启动-macOS.command` |
| Windows | `启动-Windows.bat` |

看到 `[成功] 登录成功，外网已通` 就完事了。

> **macOS 第一次双击**可能提示"无法打开，因为它来自身份不明的开发者"。
> 解决办法：右键点这个文件 → 选"打开" → 再点"打开"。只需一次。
> 如果提示没有权限，在终端里执行一次：`chmod +x "启动-macOS.command"`

---

## 二、这个程序到底做了什么

### 校园网认证的真实流程

```
你的电脑 ──连上 CTBU-Student──▶ 校园 AC（接入控制器）
                                    │
        任意 http 请求被 302 劫持 ──┤
                                    ▼
                        http://211.83.192.55/eportal/index.jsp
                        ?wlanuserip=...&wlanacname=...&nasip=...
                        &ssid=...&mac=...&t=wireless-v2&url=...
                                    │
                        GET /eportal/validcode  ← 4 位数字验证码图片
                                    │
                        POST /eportal/InterFace.do?method=login
                        userId / password / queryString / validcode
                                    ▼
                             认证通过，放行外网
```

程序严格按这个流程走：

1. **判断在不在校园网** —— 连不上校园门户、网段也不对，就直接退出，**一个请求都不发**（满足"只在连着 CTBU-Student 时才动作"）
2. **判断是不是已经登录了** —— 已登录就退出，不做多余动作
3. **抓 `queryString`** —— 从 AC 的 302 跳转里**原样抓取**（实测 14 个字段，且值是 AES 加密的，没法自己构造）
4. **自动选服务出口** —— 见下一节
5. **拉验证码并识别** —— 见下下节
6. **POST 登录**，然后**二次验证**：重新探测外网，确认真的通了才算成功

### 服务出口是自动选的（"学生移动出口"那一步）

CTBU 门户登录页是「统一身份用户 / 其他用户」两个标签页 + 一排出口按钮：
教职员工专用 / **学生移动出口** / 学生联通出口 / 学生电信出口……

以前要手点这一下，现在程序自动完成：

1. 拉登录页 + 它引用的所有 JS
2. 从 JS 里把出口列表解析出来 —— 形如 `{name:'学生移动出口', service:'student_mobile'}`
3. 按 `service_keyword`（默认「移动」）挑出对应的出口，登录时带上
4. 如果服务器回「请先选择服务出口」，就**按优先级换下一个候选重试**，逐个试完为止

> 踩过的坑：一开始用「service 前后 300 字符」找标签，结果 `service:'student_mobile'`
> 配到了**上一条**的 `name:'教职员工专用'`，"移动"关键字就选错了出口。
> 现在改成取**紧邻 service 之前的最后一个 name**，并有自动化测试守着。

### 从真实 JS 里挖出来的前端协议细节（已全部确认）

以下每一条都来自在校园网里抓下来的真实前端代码，**照抄才能登录成功**。

**① 提交体是"裸字符串拼接"，字段做双重 URL 编码**

`login_bch.js` 先把各字段编码两遍：

```js
var userId   = encodeURIComponent(encodeURIComponent(username));
var password = encodeURIComponent(encodeURIComponent(password));
encrypt      = encodeURIComponent(encodeURIComponent(encrypt));
```

`AuthInterFace.js` 再**裸拼**成 body 直接 `send()`，**不再编码**：

```js
var content = "userId=" + userId + "&password=" + password + "&service=" + service
            + "&queryString=" + queryString + "&operatorPwd=" + operatorPwd
            + "&operatorUserId=" + operatorUserId + "&validcode=" + validcode
            + "&passwordEncrypt=" + passwordEncrypt;
post(ePortalUrl + "login", content, callback);
```

> ⚠️ 这里最容易踩坑：如果用 `urlencode()` 再包一层，服务端会多解一层，
> **认证必然失败**。程序用 `http_post_raw()` 发送，并有用例逐字段校验 body 格式。

**每一个字段（含 `queryString`）都要双重 URL 编码，一个都不能漏：**

```js
// login_bch.js:678  ← 就是漏了这行，实测报「设备未注册」
var queryString = encodeURIComponent(encodeURIComponent(getQueryString()));
```

> ⚠️ **踩坑记录**：`redirectSSO()` 里用的是**原样**的 `getQueryString()`
> （那是拼进跳转 URL 的场景），我据此误以为登录提交也不编码。
> 结果 `queryString` 里的 `&` 把表单解析切碎，服务端只收到第一个
> `wlanuserip`，于是回报「设备未注册,请在ePortal上添加认证设备」。
> **同一份代码里两处上下文编码方式不同，不能想当然推广。**

`queryString` 必须从 AC 的 302 跳转里**原样抓取**：里面的 `wlanuserip` /
`mac` / `nasip` 都是 **AES 加密值**（32 位十六进制），自己造不出来。

程序在登录前还会**先访问一次 `index.jsp?<qs>`**（浏览器就是这个顺序，
门户据此登记设备会话），然后用 `http_post_raw()` 发送裸拼接的 body。

**② 密码不加密（明文提交）**

页面隐藏字段实测为：

```html
<input id="passwordEncrypt"  name="passwordEncrypt"  value="false" type="hidden">
<input id="publicKeyExponent" name="publicKeyExponent" value=""    type="hidden">
<input id="publicKeyModulus"  name="publicKeyModulus"  value=""    type="hidden">
```

密钥字段是空的，而且 `AuthInterFace.js` 里那段 RSA 分支**整段被 `/* */` 注释掉了**
（注释里还写着"老的加密算法有问题"）。所以 `security.js`（RSAUtils）只是被引进来但没启用。

**③ 出口（service）列表走 `getServices` 接口**

```js
getServices: function(queryString, callback){
    post(ePortalUrl + "getServices" + "&queryString=" + queryString, '', callback);
}
```

即 `POST /eportal/InterFace.do?method=getServices&queryString=<原样 queryString>`，
**body 为空**，返回里含 `serviceJson` 字段。程序优先用它拿权威出口列表，
拿不到才退回正则爬页面/JS。

**④ 有两条登录路径，程序走的是经典表单那条**

| 路径 | 触发方式 | 说明 |
|---|---|---|
| 统一身份（SSO） | 点「学生移动出口」→ `redirectSSO('移动')` → `login_sso.jsp?...&serviceName=移动` | 302 到 `cas.ctbu.edu.cn` 的 OAuth2 统一身份认证 |
| 其他用户（经典表单） | 学号 + 密码 + 验证码 → `InterFace.do?method=login` | **程序实现的是这条**（也是学校使用指南描述的那条） |

`redirectSSO` 的出口名取值是 `default` / `移动` / `联通` / `电信` / `校园网`，
并做双重 URL 编码后拼进 URL。

### 验证码是怎么识别的（重点）

CTBU 门户（锐捷 ePortal）的验证码是 4 位数字，经实测有两个关键性质：

* **纯 2 色**：只有 `#FFFFFF` 白底和 `#E39D41` 橙色字，**没有任何抗锯齿**
* **逐像素确定性**：同一个数字，在任何一张验证码里渲染出的位图**完全一致**

实测证据（4 张真实验证码，跨样本比对）：

```
'1': 像素完全一致=True      '4': 像素完全一致=True
'7': 像素完全一致=True      '8': 像素完全一致=True
```

所以这里**不用 OCR 去猜**，而是把每个数字的位图存成模板做**精确匹配**：

* 准确率 **100%**（不是"高"，是逐像素相等）
* 完全离线，**零依赖**、**零额外内存**
* 不像 OCR 那样会"认错"，所以不会因为认错而浪费登录次数

内置模板已覆盖 `1 2 3 4 6 7 8 9`。
第一次遇到 `0` 或 `5` 时，程序会把这几个字形**直接画在终端里**让你确认一次（约 2 秒），确认后永久记到 `learned_templates.json`，之后全自动。

### 安全性设计

| 情况 | 程序行为 |
|---|---|
| 不在校园网 | 立即退出，不发任何请求 |
| 已经在线 | 立即退出，不重复登录 |
| **验证码识别错** | 换一张重试，最多 6 次（验证码错误不计入账号错误） |
| **密码被拒绝** | **立刻停止**，绝不连续尝试 —— 避免账号被锁定 / 冻结 |
| 服务器说"已在线" | 视为成功 |

---

## 三、文件说明

| 文件 | 作用 |
|---|---|
| `campus_login.py` | 主程序（单文件，纯标准库） |
| `config.json` | 你的账号和参数配置 |
| `启动-macOS.command` | macOS 双击运行 |
| `启动-Windows.bat` | Windows 双击运行 |
| `诊断-macOS.command` / `诊断-Windows.bat` | 出问题时生成诊断报告 |
| `learned_templates.json` | 自动学会的验证码字形（程序自己生成） |
| `login.log` | 运行日志（程序自己生成） |
| `diagnostic-report.txt` | 诊断报告（运行诊断后生成） |
| `tests/offline_test.py` | 离线端到端测试 |

---

## 四、命令行用法（可选）

```bash
python3 campus_login.py              # 正常登录
python3 campus_login.py --check      # 只看状态，不提交登录
python3 campus_login.py --self-test  # 离线自检识别引擎（不联网，秒出结果）
python3 campus_login.py --train      # 校园网内补齐缺失字形
python3 campus_login.py --probe      # 生成诊断报告
python3 campus_login.py --quiet      # 不写日志文件
python3 campus_login.py --config 别的配置.json
```

退出码：`0` 成功 ｜ `2` 不在校园网 ｜ `3` 没填账号 ｜ `4` 账号密码被拒 ｜ `5` 验证码失败 ｜ `6` 找不到门户

---

## 五、常见问题

**Q：双击后一闪而过？**
在终端里手动跑一次，就能看到报错：
```bash
cd 到本目录 && python3 campus_login.py
```

**Q：提示"当前不在校园网"？**
程序连不上 `211.83.192.55`，且你本机网段不在 `10.203.0.0/17`。
确认你连的是 `CTBU-Student`。如果学校换了门户地址，把新地址填进 `config.json` 的 `portal_candidates`。

**Q：提示"账号或密码被服务器拒绝"？**
学号是 10 位、工号是 7 位；密码是**统一身份认证密码**（不是你自设的上网密码）。
密码忘了：企业微信 → 工作台 → 重置密码 → 统一身份认证密码。

**Q：一直"验证码识别失败"？**
说明门户换验证码样式了。运行 `--probe` 生成报告发我，我重新提取字形模板。

**Q：macOS 上能自动识别 WiFi 名字吗？**
新版 macOS 出于隐私保护，会把 WiFi 名称脱敏成 `<redacted>`，任何程序都拿不到（除非给终端授予定位权限）。
所以程序**主要靠"能不能连上校园门户"来判断**，这比看名字更可靠。Windows 上则能正常读到 `CTBU-Student`。

**Q：占多少内存？**
纯标准库单进程，跑完即退，**峰值约 15~25 MB**，比一个浏览器标签页还小。

---

## 六、验证状态

| 项目 | 状态 |
|---|---|
| 门户类型 / 地址 / 接口协议 | ✅ 已在真实校园网抓包确认 |
| 验证码格式与字形确定性 | ✅ 已用 4 张真实样本逐像素验证 |
| 验证码识别引擎 | ✅ 离线自检 4/4 全部正确 |
| queryString 参数格式（14 字段 / AES 加密） | ✅ 已由真实门户地址确认 |
| **服务出口（学生移动出口）自动发现** | ✅ 从 JS 自动解析，已在模拟门户验证 |
| 完整登录链路（**7 个场景 38 项断言**） | ✅ 用模拟 ePortal 全部通过 |
| 不在校园网时不动作 | ✅ 已在真实环境验证（手机热点下退出码 2，零请求） |
| 日志文件真的落盘 | ✅ 有回归测试守着（曾因 `%` 优先级 bug 静默失效） |
| 诊断报告不泄露密码 | ✅ 有专门断言 |
| **对真实门户提交登录** | ⏳ **待你在校园网内实测** |

最后一项需要连着校园网才能验证，因为登录接口依赖 `queryString`，
而 `queryString` 只有 AC 在**未认证状态**下才会下发。

> 之所以没有当场测试，是因为抓包时你正处于**已登录状态**，
> 后来网络又切到了手机热点（网关 `172.20.10.1`），校园门户变得不可达。

还有一个**尚未确认的点**：登录接口的 `passwordEncrypt` 参数。
锐捷 ePortal 的不同部署这里行为不一样（有的收明文，有的要求前端加密后提交）。
程序已经做了两件事来兜底：

1. 默认按**明文 + `passwordEncrypt=false`** 提交（这是绝大多数部署的行为）
2. 如果服务器明确回"密码错误"，会自动换一种编码方式**再试一次**，然后停止

如果你实测时卡在"账号或密码被服务器拒绝"，跑一次诊断模式即可 ——
它会顺手把真实登录页 `portal-login.html` 和它引用的 `AuthInterFace.js`
一起抓下来存到目录里，把这两个文件发我，我就能把加密方式对准。

---

## 七、出问题时怎么办

1. 连上校园网
2. 双击 `诊断-macOS.command`（或 `诊断-Windows.bat`）
3. 把下面这些发给我：
   * **`diagnostic-report.txt`**（主报告）
   * `portal-login.html`（真实登录页）
   * `portal-js-AuthInterFace.js`（登录逻辑，用来确认密码提交方式）
   * `captcha-sample-1.png` ~ `3.png`（验证码样本）

报告里包含：本机 IP、网关、WiFi 名称、门户探测结果、`queryString`、
验证码字形图、登录接口返回的原始 JSON、加密相关线索 —— 有这些就能精确定位。

报告**不包含**你的密码（这一条有自动化测试专门守着）。
