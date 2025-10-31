#!/usr/bin/env python3
"""
CheckIn 类
"""

import json
import hashlib
import os
import tempfile
from urllib.parse import urlparse

import httpx
from playwright.async_api import async_playwright
from utils.config import AccountConfig, ProviderConfig
from utils.wait_for_secrets import WaitForSecrets

class CheckIn:
    """newapi.ai 签到管理类"""

    account_config: AccountConfig
    account_name: str
    provider_config: ProviderConfig

    def __init__(self, account_config: AccountConfig, provider_config: ProviderConfig, account_index: int):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
        """
        self.account_name = account_config.name or f"Account {account_index + 1}"
        self.account_info = account_config
        self.provider_config = provider_config

    @staticmethod
    def parse_cookies(cookies_data) -> dict:
        """解析 cookies 数据"""
        if isinstance(cookies_data, dict):
            return cookies_data

        if isinstance(cookies_data, str):
            cookies_dict = {}
            for cookie in cookies_data.split(";"):
                if "=" in cookie:
                    key, value = cookie.strip().split("=", 1)
                    cookies_dict[key] = value
            return cookies_dict
        return {}

    async def get_waf_cookies_with_playwright(self) -> dict | None:
        """使用 Playwright 获取 WAF cookies（隐私模式）"""
        print(f"ℹ️ {self.account_name}: Starting browser to get WAF cookies")

        async with async_playwright() as p:

            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=False,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--no-sandbox",
                    ],
                )

                page = await context.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url())

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    cookies = await page.context.cookies()

                    waf_cookies = {}
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(waf_cookies)} WAF cookies after step 1")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: No WAF cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got WAF cookies: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting WAF cookies: {e}")
                    return None
                finally:
                    await page.close()
                    await context.close()

    def get_auth_client_id(self, client: httpx.Client, headers: dict, provider: str) -> dict:
        """获取状态信息"""
        try:
            response = client.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth is not enabled.",
                        }

                    client_id = status_data.get(f"{provider}_client_id", "")
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id: {e}",
            }

    def get_auth_state(self, client: httpx.Client, headers: dict) -> dict:
        """获取认证状态"""
        try:
            response = client.get(self.provider_config.get_auth_state_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    auth_data = data.get("data")

                    # 将 httpx Cookies 对象转换为 Playwright 格式
                    playwright_cookies = []
                    if response.cookies:
                        parsed_domain = urlparse(self.provider_config.origin).netloc

                        for cookie in response.cookies.jar:
                            http_only = cookie.httponly if cookie.has_nonstandard_attr("httponly") else False
                            same_site = cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax"
                            print(f"ℹ️ Cookie: {cookie.name}, Domain: {cookie.domain}, Path: {cookie.path}, Expires: {cookie.expires}, HttpOnly: {http_only}, Secure: {cookie.secure}, SameSite: {same_site}")
                            playwright_cookies.append(
                                {
                                    "name": cookie.name,
                                    "domain": cookie.domain if cookie.domain else parsed_domain,
                                    "value": cookie.value,
                                    "path": cookie.path,
                                    "expires": cookie.expires,
                                    "secure": cookie.secure,
                                    "httpOnly": http_only,
                                    "sameSite": same_site,
                                }
                            )

                    return {
                        "success": True,
                        "auth_data": auth_data,
                        "cookies": playwright_cookies,  # 直接返回 Playwright 格式的 cookies
                    }
            return {
                "success": False,
                "error": f"Failed to get auth state: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get auth state: {e}",
            }

    def get_user_info(self, client: httpx.Client, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = client.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    user_data = data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info: {e}",
            }

    def execute_check_in(self, client, headers: dict):
        """执行签到请求"""
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        response = client.post(self.provider_config.get_sign_in_url(), headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        if response.status_code == 200:
            try:
                result = response.json()
                if result.get("ret") == 1 or result.get("code") == 0 or result.get("success"):
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return True
                else:
                    error_msg = result.get("msg", result.get("message", "Unknown error"))
                    print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
                    return False
            except json.JSONDecodeError:
                # 如果不是 JSON 响应，检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return True
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return False
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return False

    async def check_in_with_cookies(
        self, cookies: dict, api_user: str | int, needs_check_in: bool | None = None
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作"""
        print(f"ℹ️ {self.account_name}: Executing check-in with existing cookies")

        client = httpx.Client(http2=True, timeout=30.0)
        try:
            client.cookies.update(cookies)

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.origin,
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: f"{api_user}",
            }

            user_info = self.get_user_info(client, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {success_msg}")
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get user info"}

            if needs_check_in is None and self.provider_config.needs_manual_check_in():
                success = self.execute_check_in(client, headers)
                return success, user_info if user_info else {"error": "No user info available"}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")
                return True, user_info if user_info else {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            client.close()

    async def check_in_with_github(
        self, username: str, password: str, waf_cookies: dict, cache_dir: str = ""
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作"""
        print(f"ℹ️ {self.account_name}: Executing check-in with GitHub account")

        client = httpx.Client(http2=True, timeout=30.0)
        try:
            client.cookies.update(waf_cookies)

            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{cache_dir}/github_{username_hash}_storage_state.json"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.origin,
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            client_id = self.get_auth_client_id(client, headers, "github")
            if client_id and client_id.get("success"):
                print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id['client_id']}")
            else:
                error_msg = client_id.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub client ID"}

            auth_state = self.get_auth_state(client, headers)
            if auth_state and auth_state.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state['auth_data']}")
            else:
                error_msg = auth_state.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            async with async_playwright() as p:

                with tempfile.TemporaryDirectory() as temp_dir:
                    context = await p.chromium.launch_persistent_context(
                        user_data_dir=temp_dir,
                        headless=False,
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                        viewport={"width": 1920, "height": 1080},
                        args=[
                            "--disable-blink-features=AutomationControlled",
                            "--disable-dev-shm-usage",
                            "--disable-web-security",
                            "--disable-features=VizDisplayCompositor",
                            "--no-sandbox",
                        ],
                    )

                    # 检查缓存文件是否存在, 从缓存文件中恢复会话cookies
                    if os.path.exists(cache_file_path):
                        print(f"ℹ️ {self.account_name}: Found cache file, restoring session state")
                        try:
                            with open(cache_file_path, "r", encoding="utf-8") as f:
                                cache_data = json.load(f)
                                cookies = cache_data.get("cookies", [])
                                if cookies:
                                    # 获取域名用于设置 cookies
                                    parsed_domain = urlparse(self.provider_config.origin).netloc
                                    playwright_cookies = []
                                    for cookie in cookies:
                                        cookie_data = {
                                            "name": cookie["name"],
                                            "value": cookie["value"],
                                            "domain": cookie.get("domain", parsed_domain),
                                            "path": cookie.get("path", "/"),
                                            "expires": cookie.get("expires"),
                                            "httpOnly": cookie.get("httpOnly", False),
                                            "secure": cookie.get("secure", False),
                                            "sameSite": cookie.get("sameSite", "Lax"),
                                        }
                                        playwright_cookies.append(cookie_data)

                                    await context.add_cookies(playwright_cookies)
                                    print(
                                        f"✅ {self.account_name}: Restored {len(playwright_cookies)} cookies from cache"
                                    )
                                else:
                                    print(f"⚠️ {self.account_name}: No cookies found in cache file")
                        except json.JSONDecodeError as e:
                            print(f"⚠️ {self.account_name}: Invalid JSON in cache file: {e}")
                        except FileNotFoundError:
                            print(f"⚠️ {self.account_name}: Cache file not found: {cache_file_path}")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to restore cache: {e}")
                    else:
                        print(f"ℹ️ {self.account_name}: No cache file found, proceeding with fresh login")

                    # 设置从 auth_state 获取的 session cookies 到页面上下文
                    auth_cookies = auth_state.get("cookies", [])
                    if auth_cookies:
                        await context.add_cookies(auth_cookies)
                        print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
                    else:
                        print(f"ℹ️ {self.account_name}: No auth cookies to set")

                    page = await context.new_page()
                    try:
                        # 检查是否已经登录（通过缓存恢复）
                        is_logged_in = False
                        oauth_url = f"https://github.com/login/oauth/authorize?response_type=code&client_id={client_id['client_id']}&state={auth_state['auth_data']}&scope=user:email"
                        if os.path.exists(cache_file_path):
                            try:
                                print(f"ℹ️ {self.account_name}: open {oauth_url}")
                                # 直接访问授权页面检查是否已登录
                                response = await page.goto(oauth_url)
                                print(f"ℹ️ {self.account_name}: redirected to app page {response.url if response else 'N/A'}")
                                
                                # GitHub 登录后可能直接跳转回应用页面
                                if response and response.url.startswith(self.provider_config.origin):
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                    )
                                else:
                                    # 检查是否出现授权按钮（表示已登录）
                                    authorize_btn = await page.query_selector('button[type="submit"]')
                                    if authorize_btn:
                                        is_logged_in = True
                                        print(
                                            f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                        )
                                        await authorize_btn.click()
                                    else:
                                        print(f"ℹ️ {self.account_name}: Approve button not found, need to login again")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                        # 如果未登录，则执行登录流程
                        if not is_logged_in:
                            try:
                                print(f"ℹ️ {self.account_name}: start to sign in GitHub")

                                await page.goto("https://github.com/login")
                                await page.fill("#login_field", username)
                                await page.fill("#password", password)
                                await page.click('input[type="submit"][value="Sign in"]')
                                await page.wait_for_timeout(10000)

                                # 处理两步验证（如果需要）
                                try:
                                    # 检查是否需要两步验证
                                    otp_input = await page.query_selector('input[name="otp"]')
                                    if otp_input:
                                        print(f"ℹ️ {self.account_name}: Two-factor authentication required")

                                        # 尝试通过 wait-for-secrets 自动获取 OTP
                                        otp_code = None
                                        try:
                                            print(f"🔐 {self.account_name}: Attempting to retrieve OTP via wait-for-secrets...")
                                            # Define secret object
                                            wait_for_secrets = WaitForSecrets()
                                            secret_obj = {'OTP': {'name': 'GitHub 2FA OTP', 'description': 'OTP from authenticator app'}}
                                            secrets = wait_for_secrets.get(secret_obj, timeout=5)
                                            if secrets and 'OTP' in secrets:
                                                otp_code = secrets['OTP']
                                                print(f"✅ {self.account_name}: Retrieved OTP via wait-for-secrets")
                                        except Exception as e:
                                            print(f"⚠️ {self.account_name}: wait-for-secrets failed: {e}")

                                        if otp_code:
                                            # 自动填充 OTP
                                            print(f"✅ {self.account_name}: Auto-filling OTP code")
                                            await otp_input.fill(otp_code)
                                            # 提交表单
                                            submit_btn = await page.query_selector('button[type="submit"]')
                                            if submit_btn:
                                                await submit_btn.click()
                                                print(f"✅ {self.account_name}: OTP submitted successfully")
                                            await page.wait_for_timeout(5000)  # 等待5秒确认提交
                                        else:
                                            # 回退到手动输入
                                            print(f"ℹ️ {self.account_name}: Please enter OTP manually in the browser")
                                            await page.wait_for_timeout(30000)  # 等待30秒让用户手动输入
                                except Exception as e:
                                    print(f"⚠️ {self.account_name}: Error handling 2FA: {e}")
                                    pass

                                # 保存新的会话状态
                                await context.storage_state(path=cache_file_path)

                            except Exception as e:
                                print(f"❌ {self.account_name}: Error occurred while signing in GitHub: {e}")
                                return False, {"error": "GitHub sign-in error"}

                            # 登录后访问授权页面
                            try:
                                print(f"ℹ️ {self.account_name}: open {oauth_url}")
                                response = await page.goto(oauth_url)
                                print(f"ℹ️ {self.account_name}: redirected to app page {response.url if response else 'N/A'}")
                                
                                # GitHub 登录后可能直接跳转回应用页面
                                if response and response.url.startswith(self.provider_config.origin):
                                    print(f"✅ {self.account_name}: logged in, proceeding to authorization")
                                else:
                                       # 检查是否出现授权按钮（表示已登录）
                                    authorize_btn = await page.query_selector('button[type="submit"]')
                                    if authorize_btn:
                                        is_logged_in = True
                                        print(
                                            f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                        )
                                        await authorize_btn.click()
                                    else:
                                        print(f"ℹ️ {self.account_name}: Approve button not found")
                            except Exception as e:
                                print(f"❌ {self.account_name}: Error occurred while authorization approve: {e}")
                                return False, {"error": "GitHub authorization approval failed"}

                        # 统一处理授权逻辑（无论是否通过缓存登录）
                        try:
                            await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)
                            
                            # 从 localStorage 获取 user 对象并提取 id
                            api_user = None
                            try:
                                # 等待5秒, 登录完成后 localStorage 可能需要时间更新
                                await page.wait_for_timeout(5000)
                                user_data = await page.evaluate("() => localStorage.getItem('user')")
                                if user_data:
                                    user_obj = json.loads(user_data)
                                    api_user = user_obj.get("id")
                                    if api_user:
                                        print(f"✅ {self.account_name}: Got api user: {api_user}")
                                    else:
                                        print(f"⚠️ {self.account_name}: User id not found in localStorage")
                                else:
                                    print(f"⚠️ {self.account_name}: User data not found in localStorage")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

                            if api_user:
                                print(f"✅ {self.account_name}: OAuth authorization successful")

                                # 提取 session cookie
                                cookies = await page.context.cookies()
                                user_cookies = {}
                                for cookie in cookies:
                                    cookie_name = cookie.get("name")
                                    cookie_value = cookie.get("value")
                                    if cookie_name and cookie_value:
                                        user_cookies[cookie_name] = cookie_value
                                all_cookies = {**waf_cookies, **user_cookies}
                                result = await self.check_in_with_cookies(all_cookies, api_user, needs_check_in=False)
                                return result
                            else:
                                print(f"❌ {self.account_name}: OAuth failed")
                                return False, {"error": "GitHub OAuth failed - no user ID found"}

                        except Exception as e:
                            print(f"❌ {self.account_name}: Error occurred while authorization redirecting: {e}")
                            return False, {"error": "GitHub authorization redirecting failed"}
                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while signing in GitHub: {e}")
                        return False, {"error": "GitHub sign-in process error"}
                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while goto GitHub page: {e}")
                        return False, {"error": "GitHub page navigation error"}
                    finally:
                        await page.close()
                        await context.close()

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}

    async def check_in_with_linuxdo(
        self, username: str, password: str, waf_cookies: dict, cache_dir: str = ""
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作"""
        print(f"ℹ️ {self.account_name}: Executing check-in with Linux.do account")

        client = httpx.Client(http2=True, timeout=30.0)
        try:
            client.cookies.update(waf_cookies)

            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{cache_dir}/linuxdo_{username_hash}_storage_state.json"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.origin,
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            client_id = self.get_auth_client_id(client, headers, "linuxdo")
            if client_id and client_id.get("success"):
                print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id['client_id']}")
            else:
                error_msg = client_id.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do client ID"}

            auth_state = self.get_auth_state(client, headers)
            if auth_state and auth_state.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state['auth_data']}")
            else:
                error_msg = auth_state.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            async with async_playwright() as p:

                with tempfile.TemporaryDirectory() as temp_dir:
                    context = await p.chromium.launch_persistent_context(
                        user_data_dir=temp_dir,
                        headless=False,
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                        viewport={"width": 1920, "height": 1080},
                        args=[
                            "--disable-blink-features=AutomationControlled",
                            "--disable-dev-shm-usage",
                            "--disable-web-security",
                            "--disable-features=VizDisplayCompositor",
                            "--no-sandbox",
                        ],
                    )

                    # 检查缓存文件是否存在, 从缓存文件中恢复会话cookies
                    if os.path.exists(cache_file_path):
                        print(f"ℹ️ {self.account_name}: Found cache file, restoring session state")
                        try:
                            with open(cache_file_path, "r", encoding="utf-8") as f:
                                cache_data = json.load(f)
                                cookies = cache_data.get("cookies", [])
                                if cookies:
                                    # 获取域名用于设置 cookies
                                    parsed_domain = urlparse(self.provider_config.origin).netloc
                                    playwright_cookies = []
                                    for cookie in cookies:
                                        cookie_data = {
                                            "name": cookie["name"],
                                            "value": cookie["value"],
                                            "domain": cookie.get("domain", parsed_domain),
                                            "path": cookie.get("path", "/"),
                                            "expires": cookie.get("expires"),
                                            "httpOnly": cookie.get("httpOnly", False),
                                            "secure": cookie.get("secure", False),
                                            "sameSite": cookie.get("sameSite", "Lax"),
                                        }
                                        playwright_cookies.append(cookie_data)

                                    await context.add_cookies(playwright_cookies)
                                    print(
                                        f"✅ {self.account_name}: Restored {len(playwright_cookies)} cookies from cache"
                                    )
                                else:
                                    print(f"⚠️ {self.account_name}: No cookies found in cache file")
                        except json.JSONDecodeError as e:
                            print(f"⚠️ {self.account_name}: Invalid JSON in cache file: {e}")
                        except FileNotFoundError:
                            print(f"⚠️ {self.account_name}: Cache file not found: {cache_file_path}")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to restore cache: {e}")
                    else:
                        print(f"ℹ️ {self.account_name}: No cache file found, proceeding with fresh login")

                    # 设置从 auth_state 获取的 session cookies 到页面上下文
                    auth_cookies = auth_state.get("cookies", [])
                    if auth_cookies:
                        await context.add_cookies(auth_cookies)
                        print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
                    else:
                        print(f"ℹ️ {self.account_name}: No auth cookies to set")

                    page = await context.new_page()
                    try:
                        # 检查是否已经登录（通过缓存恢复）
                        is_logged_in = False
                        oauth_url = f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={client_id['client_id']}&state={auth_state['auth_data']}"
                        if os.path.exists(cache_file_path):
                            try:
                                print(f"ℹ️ {self.account_name}: open {oauth_url}")
                                # 直接访问授权页面检查是否已登录
                                await page.goto(oauth_url)
                                

                                # 检查是否出现授权按钮（表示已登录）
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if allow_btn:
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                    )
                                else:
                                    print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                        # 如果未登录，则执行登录流程
                        if not is_logged_in:
                            try:
                                print(f"ℹ️ {self.account_name}: start to sign in linux.do")

                                await page.goto("https://linux.do/login")
                                await page.fill("#login-account-name", username)
                                await page.fill("#login-account-password", password)
                                await page.click("#login-button")
                                await page.wait_for_timeout(10000)

                                # 保存新的会话状态
                                await context.storage_state(path=cache_file_path)

                            except Exception as e:
                                print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                                return False, {"error": "Linux.do sign-in error"}

                            # 登录后访问授权页面
                            try:
                                print(f"ℹ️ {self.account_name}: open {oauth_url}")
                                await page.goto(oauth_url)
                            except Exception as e:
                                print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
                                return False, {"error": "Linux.do authorization page navigation failed"}

                        # 统一处理授权逻辑（无论是否通过缓存登录）
                        try:
                            # 等待授权按钮出现，最多等待5秒
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=5000)
                            allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn_ele:
                                await allow_btn_ele.click()
                                await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)

                                # 从 localStorage 获取 user 对象并提取 id
                                api_user = None
                                try:
                                    # 等待5秒, 登录完成后 localStorage 可能需要时间更新
                                    await page.wait_for_timeout(5000)
                                    user_data = await page.evaluate("() => localStorage.getItem('user')")
                                    if user_data:
                                        user_obj = json.loads(user_data)
                                        api_user = user_obj.get("id")
                                        if api_user:
                                            print(f"✅ {self.account_name}: Got api user: {api_user}")
                                        else:
                                            print(f"⚠️ {self.account_name}: User id not found in localStorage")
                                    else:
                                        print(f"⚠️ {self.account_name}: User data not found in localStorage")
                                except Exception as e:
                                    print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

                                if api_user:
                                    print(f"✅ {self.account_name}: OAuth authorization successful")

                                    # 提取 session cookie
                                    cookies = await page.context.cookies()
                                    user_cookies = {}
                                    for cookie in cookies:
                                        cookie_name = cookie.get("name")
                                        cookie_value = cookie.get("value")
                                        if cookie_name and cookie_value:
                                            user_cookies[cookie_name] = cookie_value
                                    all_cookies = {**waf_cookies, **user_cookies}
                                    result = await self.check_in_with_cookies(
                                        all_cookies, api_user, needs_check_in=False
                                    )
                                    return result
                                else:
                                    print(f"❌ {self.account_name}: OAuth failed")
                                    return False, {"error": "Linux.do OAuth failed - no user ID found"}
                            else:
                                print(f"❌ {self.account_name}: Approve button not found")
                                return False, {"error": "Linux.do allow button not found"}
                        except Exception as e:
                            print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                            return False, {"error": "Linux.do authorization failed"}
                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while goto linux.do page: {e}")
                        return False, {"error": "Linux.do page navigation error"}
                    finally:
                        await page.close()
                        await context.close()

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        waf_cookies = {}
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_playwright()
            if not waf_cookies:
                print(f"❌ {self.account_name}: Unable to get WAF cookies")
                # 即使 WAF cookies 失败，也继续尝试其他认证方式
                print(f"✅ {self.account_name}: WAF cookies obtained")
        else:
            print(f"ℹ️ {self.account_name}: Bypass WAF not required, using user cookies directly")

        cache_dir = "caches"
        os.makedirs(cache_dir, exist_ok=True)

        # 解析账号配置
        cookies_data = self.account_info.cookies
        github_info = self.account_info.github
        linuxdo_info = self.account_info.linux_do
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: Trying cookies authentication")
            try:
                user_cookies = self.parse_cookies(cookies_data)
                if not user_cookies:
                    print(f"❌ {self.account_name}: Invalid cookies format")
                    results.append(("cookies", False, {"error": "Invalid cookies format"}))
                else:
                    api_user = self.account_info.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append(("cookies", False, {"error": "API user identifier not found"}))
                    else:
                        # 使用已有 cookies 执行签到
                        all_cookies = {**waf_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, api_user)
                        if success:
                            print(f"✅ {self.account_name}: Cookies authentication successful")
                            results.append(("cookies", True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Cookies authentication failed")
                            results.append(("cookies", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Cookies authentication error: {e}")
                results.append(("cookies", False, {"error": str(e)}))

        # 尝试 GitHub 认证
        if github_info:
            print(f"\nℹ️ {self.account_name}: Trying GitHub authentication")
            try:
                username = github_info.get("username")
                password = github_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete GitHub account information")
                    results.append(("github", False, {"error": "Incomplete GitHub account information"}))
                else:
                    # 使用 GitHub 账号执行签到
                    success, user_info = await self.check_in_with_github(username, password, waf_cookies, cache_dir)
                    if success:
                        print(f"✅ {self.account_name}: GitHub authentication successful")
                        results.append(("github", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: GitHub authentication failed")
                        results.append(("github", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: GitHub authentication error: {e}")
                results.append(("github", False, {"error": str(e)}))

        # 尝试 Linux.do 认证
        if linuxdo_info:
            print(f"\nℹ️ {self.account_name}: Trying Linux.do authentication")
            try:
                username = linuxdo_info.get("username")
                password = linuxdo_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete Linux.do account information")
                    results.append(("linux.do", False, {"error": "Incomplete Linux.do account information"}))
                else:
                    # 使用 Linux.do 账号执行签到
                    success, user_info = await self.check_in_with_linuxdo(username, password, waf_cookies, cache_dir)
                    if success:
                        print(f"✅ {self.account_name}: Linux.do authentication successful")
                        results.append(("linux.do", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: Linux.do authentication failed")
                        results.append(("linux.do", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Linux.do authentication error: {e}")
                results.append(("linux.do", False, {"error": str(e)}))

        if not results:
            print(f"❌ {self.account_name}: No valid authentication method found in configuration")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} authentication results:")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} authentication")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} authentication methods successful")

        return results
