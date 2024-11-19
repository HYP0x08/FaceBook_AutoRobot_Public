import re
import json
import time
import copy
import random
import string
import requests
import facebookCrypto

user = ""
pwd = ""

# 获取指定的 Page 定义信息
saveDefine = [
    "DTSGInitialData",
    "LSD"
]

# 初始化 头信息
init_headers = {
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    'Sec-Fetch-Dest': 'document',
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Mode": "navigate"
}

# 初始化 请求数据
graphql_init_PostData = {
    'av': "0",
    '__aaid': '1',
    '__user': "0",
    '__a': "1",
    '__hs': "",
    'dpr': "",
    '__ccg': "EXCELLENT",
    '__rev': "",
    '__s': "",
    '__hsi': "",
    '__comet_req': "",
    'fb_dtsg': "",
    'jazoest': "",
    'lsd': "",
    '__spin_r': "",
    '__spin_b': "",
    '__spin_t': "",
    'server_timestamps': "true"
}

# 页面 Js Json 集合
page_jsons = {
}

# 页面定义信息
page_Define = {
}

session = requests.Session()

# 初始化 facebook 基本参数
def facebook_Info():
    url = "https://www.facebook.com/"
    
    headers = {
        "Sec-Fetch-Site" : "none"
    }
    headers = {**headers, **init_headers}
    req = session.get(url=url, headers=headers, verify=True)
    
    # 匹配参数cle
    pattern = r'name="(jazoest|lsd)" value="(.*?)"|\"publicKey\":\"([a-fA-F0-9]+)\",\"keyId\":(\d+)'
    matches = re.findall(pattern, req.text)
    
    result = {}
    for match in matches:
        if match[0]:  # 对应 jazoest 和 lsd 的匹配
            result[match[0]] = match[1]
        else:  # 对应 publicKey 和 keyId 的匹配
            result["publicKey"] = match[2]
            result["key_id"] = int(match[3])  # 转换 keyId 为整数
    
    if len(result) == 4:
        return result
    
    return {}

# 刷新获取 facebook 页面参数
def facebook_Refresh():
    url = "https://www.facebook.com/"
    
    headers = {
        "Sec-Fetch-Site" : "none"
    }
    headers = {**headers, **init_headers}
    response = session.get(url=url, headers=headers, verify=True)
    
    resultPage = response.text
    facebook_UpdatePageData(resultPage)
    
    return
    
# 更新页面信息 （请求用得到）
def facebook_UpdatePageData(html):
    
    def p(length):
        characters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(characters) for _ in range(length))
    
    # Copy 请求头信息
    requset_graphql = graphql_init_PostData.copy()
    json_strings = re.findall(r'<script type="application/json"[^>]*>(.*?)</script>', html)
    
    # 过滤 Json
    for json_str in json_strings:
        if 'login_data' in json_str:
            page_jsons['login_data'] = json.loads(json_str)
        elif 'IS_WORK_MESSENGER_CALL_GUEST_USER' in json_str:
            graphql_vaule = json.loads(json_str)
            
            try:
                # 通过测试是否可以取出来这里的值来判断是否有效
                test = graphql_vaule["require"][0][3][0]["__bbox"]["define"][0]
                page_jsons['graphql_vaule'] = graphql_vaule
            except:
                continue
    
    # 获取 登录数据
    login_data = page_jsons['login_data']["require"][0][3][0]["__bbox"]["require"][0][3][1]["__bbox"]["result"]["data"]["login_data"]
    for defineName in login_data:
        
        # 获取指定定义信息
        if defineName in ['lsd', 'jazoest']:
            requset_graphql[login_data[defineName]["name"]] = login_data[defineName]["value"]
    
    # 获取 站点 JS 定义信息
    for define in page_jsons['graphql_vaule']["require"][0][3][0]["__bbox"]["define"]:
        defineName = define[0]
        
        # 获取指定定义信息
        if defineName in saveDefine:
            page_Define[defineName] = define[2]["token"]
        elif defineName in ['SiteData', 'CurrentUserInitialData']:
            page_Define[defineName] = define[2]
    
    # 更新 graphql 请求参数
    requset_graphql["lsd"] = page_Define["LSD"] if requset_graphql["lsd"] == '' else ''
    requset_graphql["__hs"] = page_Define["SiteData"]["haste_session"]
    requset_graphql["dpr"] = page_Define["SiteData"]["pr"]
    requset_graphql["__rev"] = page_Define["SiteData"]["client_revision"]
    requset_graphql["__s"] = ":mo4k3l:" + p(6)
    requset_graphql["__hsi"] = page_Define["SiteData"]["hsi"]
    requset_graphql["__comet_req"] = page_Define["SiteData"]["comet_env"]
    requset_graphql["__spin_r"] = page_Define["SiteData"]["__spin_r"]
    requset_graphql["__spin_b"] = page_Define["SiteData"]["__spin_b"]
    requset_graphql["__spin_t"] = page_Define["SiteData"]["__spin_t"]
    
    return requset_graphql
    
# 获取两步验证选择
def facebook_TwoStepSelect(html):
    
    # 初始化基本 请求参数
    requset_PostData = facebook_UpdatePageData(html)
    
    # 获取加密 Key
    encrypted_context = page_jsons['graphql_vaule']["require"][0][3][0]["__bbox"]["require"][7][3][0]["initialRouteInfo"]["route"]["params"]["encrypted_context"]
    
    url = "https://www.facebook.com/api/graphql/"
    
    # 构建请求参数
    postData = {
        'doc_id': 25242075608770205,
        "__req": "3",
        'fb_api_caller_class': "RelayModern",
        'fb_api_req_friendly_name': "TwoStepVerificationChallengePickerDialogQuery",
        'variables': json.dumps({
            "encryptedContext" : encrypted_context
        })
    }
    postData = {**requset_PostData, **postData}
    
    headers = {
        "Sec-Fetch-Site" : "same-origin"
    }
    headers = {**headers, **init_headers}
    
    response = session.post(url=url, data=postData, verify=True)
    
    # 身份应用方式 返回
    
    result = {}
    methods = response.json()["data"]["xfb_two_factor_login_methods"]["methods"]
    for method in methods:
        result [method["method"]] = {
            "method" : method["method"],
            "heading" : method["method_picker_content"]["heading"],
            "subheading": method["method_screen_content"]["subheading"][0],
        }
    
    return result

# 两步验证
def facebook_TowStepVerify(html, method, code):
    # 初始化基本 请求参数
    requset_PostData = facebook_UpdatePageData(html)
    
    # 获取加密 Key
    encrypted_context = page_jsons['graphql_vaule']["require"][0][3][0]["__bbox"]["require"][7][3][0]["initialRouteInfo"]["route"]["params"]["encrypted_context"]
    
    url = "https://www.facebook.com/api/graphql/"
    
    # 构建请求参数
    postData = {
        'doc_id': 7404767032917067,
        "__req": "5",
        'fb_api_caller_class': "RelayModern",
        'fb_api_req_friendly_name': "useTwoFactorLoginValidateCodeMutation",
        'variables': json.dumps({
            "code" : {
                "sensitive_string_value" : code
            },
            "method" : method,
            "flow" : "TWO_FACTOR_LOGIN",
            "encryptedContext" : encrypted_context,
            "maskedContactPoint": "null"
        })
    }
    postData = {**requset_PostData, **postData}
    
    headers = {
        "Sec-Fetch-Site" : "same-origin",
    }
    headers = {**headers, **init_headers}
    
    response = session.post(url=url, headers=headers ,data=postData, verify=True)
    return response.json()

# 登录
def facebook_Login(username, password):
    # 初始化前置加密条件
    defaultInfo = facebook_Info()
    jazoest = defaultInfo["jazoest"]
    lsd = defaultInfo["lsd"]
    publicKey = defaultInfo["publicKey"]
    keyId = defaultInfo["key_id"]
    date = str(int(time.time()))
    
    # 对密码进行加密
    encrypt = facebookCrypto.encrypt(keyId, publicKey, password, date)
    requsetPwd = "#PWD_BROWSER:5:" + date + ":" + encrypt
    
    # 开始登录请求
    url = "https://www.facebook.com/login/device-based/regular/login/?login_attempt=1&next=https%3A%2F%2Fwww.facebook.com%2F&lwv=120&lwc=1348131"
    
    # 构建基础请求
    postData = {
        "jazoest": jazoest,
        "lsd": lsd,
        "display": "",
        "isprivate": "",
        "return_session": "",
        "skip_api_login": "",
        "signed_next": "",
        "trynum": "2",
        "timezone": "-480",
        "lgndim": "eyJ3IjoyNTYwLCJoIjoxNDQwLCJhdyI6MjU2MCwiYWgiOjEzOTIsImMiOjI0fQ==",
        "lgnrnd": "065841_k9_M",
        "lgnjs": date,
        "email": username,
        "prefill_contact_point": username,
        "prefill_source": "browser_onload",
        "prefill_type": "password",
        "first_prefill_source": "browser_dropdown",
        "first_prefill_type": "contact_point",
        "had_cp_prefilled": "true",
        "had_password_prefilled": "true",
        "ab_test_data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAB",
        "encpass": requsetPwd
    }
    
    headers = {
        "Sec-Fetch-Site" : "same-origin"
    }
    
    headers = {**headers, **init_headers}
    
    # 开始请求
    response = session.post(url=url, headers=headers, data=postData, verify=True)
    
    # 获取返回页面
    resultPage = response.text
    
    # 判断是否需要两步验证
    if 'checkpoint' in session.cookies:
        # 获取验证方式
        verifyMethod = facebook_TwoStepSelect(resultPage)
        
        print(verifyMethod)
        method = input("需要进行二步安全验证, 输入身份验证方式，例如 TOTP: ")
        while method not in verifyMethod:
            print("不存在的验证方式！")
            method = input("输入身份验证方式，例如 TOTP: ")
        
        code = input("请输入验证码: ")
        verifyMsg = facebook_TowStepVerify(resultPage, method, code)
        
        if verifyMsg['data']["xfb_two_factor_login_validate_code"] is None:
            print(verifyMsg['errors'][0]['description_raw'])
            return "验证码验证失败！"
        
        # 刷新数据
        facebook_Refresh()
        return "登录成功！"
    
    return "登录失败！大概率是账户密码错误，也有可能直接通过验证了，暂时没号做直接转跳判断"

print(facebook_Login(user, pwd))

print(json.dumps(page_Define["CurrentUserInitialData"], indent=2))
