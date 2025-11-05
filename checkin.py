#!/usr/bin/env python3
"""
CheckIn 类
"""

import json
import hashlib
import os
import tempfile
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import httpx
from playwright.async_api import async_playwright
from utils.config import AccountConfig, ProviderConfig
from utils.browser_utils import parse_cookies, get_random_user_agent


class CheckIn:
    """newapi.ai 签到管理类"""

    account_config: AccountConfig
    account_name: str
    provider_config: ProviderConfig
    cache_dir: str

    def __init__(
        self,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        account_index: int,
        cache_dir: str = "caches",
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
        """
        self.account_name = account_config.name or f"Account {account_index + 1}"
        self.account_info = account_config
        self.provider_config = provider_config
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    async def _take_screenshot(self, page, reason: str) -> None:
        """截取当前页面的屏幕截图

        Args:
            page: Playwright 页面对象
            reason: 截图原因描述
        """
        try:
            # 创建 screenshots 目录
            screenshots_dir = "screenshots"
            os.makedirs(screenshots_dir, exist_ok=True)

            # 生成文件名: 账号名_时间戳_原因.png
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_account_name = "".join(c if c.isalnum() else "_" for c in self.account_name)
            safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
            filename = f"{safe_account_name}_{timestamp}_{safe_reason}.png"
            filepath = os.path.join(screenshots_dir, filename)

            await page.screenshot(path=filepath, full_page=True)
            print(f"📸 {self.account_name}: Screenshot saved to {filepath}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to take screenshot: {e}")

    async def get_waf_cookies_with_playwright(self) -> dict | None:
        """使用 Playwright 获取 WAF cookies（隐私模式）"""
        print(f"ℹ️ {self.account_name}: Starting browser to get WAF cookies")

        async with async_playwright() as p:

            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=False,
                    user_agent=get_random_user_agent(),
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
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

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

    async def get_status_with_playwright(self) -> dict | None:
        """使用 Playwright 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        # 生成缓存文件路径
        cache_file_path = f"{self.cache_dir}/{self.provider_config.name}_status.json"

        # 检查缓存文件是否存在
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                    print(f"ℹ️ {self.account_name}: Loaded status from cache: {cache_file_path}")
                    return cached_data
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to load status cache: {e}")

        print(f"ℹ️ {self.account_name}: Starting browser to get status")

        async with async_playwright() as p:

            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=False,
                    user_agent=get_random_user_agent(),
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
                    print(f"ℹ️ {self.account_name}: Access status page to get status from localStorage")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")

                            # 保存到缓存文件
                            self.cache_status_data(status_data, cache_file_path=cache_file_path)
                        else:
                            print(f"⚠️ {self.account_name}: No status found in localStorage")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Error reading status from localStorage: {e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting status: {e}")
                    return None
                finally:
                    await page.close()
                    await context.close()

    def cache_status_data(self, status_data: dict, cache_file_path: str) -> None:
        """缓存状态信息"""
        try:
            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(status_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to save status cache: {e}")

    async def get_auth_client_id(self, client: httpx.Client, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            client: httpx 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            response = client.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError as json_err:
                    print(f"❌ {self.account_name}: Failed to parse JSON response")
                    print(f"    📄 Response content (first 500 chars): {response.text[:500]}")
                    print(f"ℹ️ {self.account_name}: Attempting to get status from browser localStorage")

                    # 尝试从浏览器 localStorage 获取状态
                    try:
                        status_data = await self.get_status_with_playwright()
                        if status_data:
                            oauth = status_data.get(f"{provider}_oauth", False)
                            if not oauth:
                                return {
                                    "success": False,
                                    "error": f"{provider} OAuth is not enabled.",
                                }

                            client_id = status_data.get(f"{provider}_client_id", "")
                            if client_id:
                                print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                                return {
                                    "success": True,
                                    "client_id": client_id,
                                }
                    except Exception as browser_err:
                        print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": f"Failed to get client id: Invalid JSON response - {json_err}",
                    }

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
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get client id: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id, {e}",
            }

    async def get_auth_state_with_playwright(self, status: dict, wait_for_url: str) -> dict:
        """使用 Playwright 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(f"ℹ️ {self.account_name}: Starting browser to get auth URL")

        async with async_playwright() as p:
            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=False,
                    user_agent=get_random_user_agent(),
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
                    # 1. Open the login page first
                    print(f"ℹ️ {self.account_name}: Opening login page")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    # 2. Store status in localStorage (after page is loaded)
                    print(f"ℹ️ {self.account_name}: Storing status in localStorage")
                    status_json = json.dumps(status, ensure_ascii=False)
                    # Escape single quotes for JavaScript string literal
                    status_json_escaped = status_json.replace("'", "\\'")
                    await page.evaluate(f"() => localStorage.setItem('status', '{status_json_escaped}')")

                    # 3. Reload the page to apply localStorage changes
                    print(f"ℹ️ {self.account_name}: Reloading page after setting localStorage")
                    await page.reload(wait_until="networkidle")

                    # Wait for page to be fully loaded after reload
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    # 4. Click the main button[0] and wait for new tab
                    print(f"ℹ️ {self.account_name}: Clicking main button")
                    buttons = await page.query_selector_all("main button")
                    if buttons and len(buttons) > 0:
                        # Wait for new tab to open when clicking the button
                        async with context.expect_page() as new_page_info:
                            await buttons[0].click()
                        new_page = await new_page_info.value
                        print(f"ℹ️ {self.account_name}: New tab opened")
                    else:
                        print(f"⚠️ {self.account_name}: No buttons found on page")
                        await self._take_screenshot(page, "no_buttons_found")
                        return {"success": False, "error": "No buttons found on login page"}

                    # 5. Get the first URL of the new tab (don't wait for loading)
                    print(f"ℹ️ {self.account_name}: Getting new tab's initial URL")
                    # Wait a short moment for the URL to be set
                    # await new_page.wait_for_timeout(1000)
                    current_url = new_page.url
                    print(f"ℹ️ {self.account_name}: New tab URL: {current_url}")

                    # Check if URL matches the expected pattern
                    if wait_for_url in current_url:
                        print(f"✅ {self.account_name}: New tab URL matches expected pattern")
                    else:
                        print(f"⚠️ {self.account_name}: URL doesn't match pattern but continuing anyway")

                    # 6. Get cookies from the context
                    cookies = await context.cookies()
                    print(f"ℹ️ {self.account_name}: Got {len(cookies)} cookies from context")

                    # 7. Return the new tab URL and cookies
                    print(f"✅ {self.account_name}: Got auth URL from new tab: {current_url}")

                    return {"success": True, "url": current_url, "cookies": cookies}

                except Exception as e:
                    print(f"❌ {self.account_name}: Error getting auth URL: {e}")
                    await self._take_screenshot(page, "auth_url_error")
                    return {"success": False, "error": f"Error getting auth URL: {e}"}
                finally:
                    await page.close()
                    await context.close()

    async def get_auth_state(
        self,
        client: httpx.Client,
        client_id: str,
        headers: dict,
        provider: str,
        wait_for_url: str,
        return_to_key: str = "return_to",
    ) -> dict:
        """获取认证状态"""
        try:
            response = client.get(self.provider_config.get_auth_state_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError as json_err:
                    print(f"❌ {self.account_name}: Invalid JSON response - {json_err}")
                    print(f"    📄 Response content (first 500 chars): {response.text[:500]}")

                    print(f"ℹ️ {self.account_name}: Getting auth state from browser")
                    auth_result = await self.get_auth_state_with_playwright(
                        {f"{provider}_client_id": client_id, f"{provider}_oauth": True},
                        wait_for_url,
                    )

                    if not auth_result.get("success"):
                        error_msg = auth_result.get("error", "Unknown error")
                        print(f"❌ {self.account_name}: {error_msg}")
                        return False, {"error": "Failed to get auth URL with Playwright"}

                    # 提取 return_to 参数
                    auth_url = auth_result.get("url")
                    print(f"ℹ️ {self.account_name}: Extracted auth url: {auth_url}")
                    parsed_url = urlparse(auth_url)
                    query_params = parse_qs(parsed_url.query)
                    return_to = query_params.get(return_to_key, [None])[0]

                    if return_to:
                        print(f"ℹ️ {self.account_name}: Extracted return_to: {return_to}")

                        # 从 return_to URL 中提取 state 参数
                        return_to_parsed = urlparse(return_to)
                        return_to_params = parse_qs(return_to_parsed.query)
                        auth_state = return_to_params.get("state", [None])[0]

                        if auth_state:
                            print(f"ℹ️ {self.account_name}: Extracted state from return_to: {auth_state}")
                            return {
                                "success": True,
                                "state": auth_state,
                                "cookies": auth_result.get("cookies", []),
                            }
                        else:
                            print(f"⚠️ {self.account_name}: No state parameter found in return_to URL")
                            return False, {"error": "No state parameter found in return_to URL"}
                    else:
                        print(f"⚠️ {self.account_name}: No return_to parameter found in URL")
                        return False, {"error": "No return_to parameter found in URL"}

                if data.get("success"):
                    auth_data = data.get("data")

                    # 将 httpx Cookies 对象转换为 Playwright 格式
                    playwright_cookies = []
                    if response.cookies:
                        parsed_domain = urlparse(self.provider_config.origin).netloc

                        for cookie in response.cookies.jar:
                            http_only = cookie.httponly if cookie.has_nonstandard_attr("httponly") else False
                            same_site = cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax"
                            print(
                                f"ℹ️ Cookie: {cookie.name}, Domain: {cookie.domain}, "
                                f"Path: {cookie.path}, Expires: {cookie.expires}, "
                                f"HttpOnly: {http_only}, Secure: {cookie.secure}, "
                                f"SameSite: {same_site}"
                            )
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
                        "state": auth_data,
                        "cookies": playwright_cookies,  # 直接返回 Playwright 格式的 cookies
                    }
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get auth state: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get auth state: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get auth state, {e}",
            }

    def get_user_info(self, client: httpx.Client, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = client.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError as json_err:
                    print(f"❌ {self.account_name}: Failed to parse JSON response")
                    print(f"    📄 Response content (first 500 chars): {response.text[:500]}")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: Invalid JSON response - {json_err}",
                    }

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
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info, {e}",
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
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
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

    async def check_in_with_github(self, username: str, password: str, waf_cookies: dict) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作"""
        print(f"ℹ️ {self.account_name}: Executing check-in with GitHub account")

        client = httpx.Client(http2=True, timeout=30.0)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config: " f"{client_id_result['client_id']}")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                client=client,
                client_id=client_id_result["client_id"],
                headers=headers,
                provider="github",
                wait_for_url="https://github.com/login",
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.cache_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path,
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and result_data.get("cookies") and result_data.get("api_user"):
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                merged_cookies = {**waf_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, api_user, needs_check_in=False)
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            client.close()

    async def check_in_with_linuxdo(
        self, username: str, password: str, waf_cookies: dict, use_camoufox: bool = True
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            waf_cookies: WAF cookies
            use_camoufox: 是否使用 Camoufox 绕过 Cloudflare (默认 True)
        """
        print(f"ℹ️ {self.account_name}: Executing check-in with Linux.do account")

        client = httpx.Client(http2=True, timeout=30.0)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": get_random_user_agent(),
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                self.provider_config.api_user_key: "-1",
            }

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(
                    f"ℹ️ {self.account_name}: Using Linux.do client ID from config: " f"{client_id_result['client_id']}"
                )
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get Linux.do client ID"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                client=client,
                client_id=client_id_result["client_id"],
                headers=headers,
                provider="linuxdo",
                wait_for_url="https://linux.do/login",
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.cache_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )
            # 如果使用 Camoufox 绕过
            if use_camoufox:
                success, result_data = await linuxdo.signin_bypass(
                    client_id=client_id_result["client_id"],
                    auth_state=auth_state_result["state"],
                    auth_cookies=auth_state_result.get("cookies", []),
                    cache_file_path=cache_file_path,
                )
            else:
                success, result_data = await linuxdo.signin(
                    client_id=client_id_result["client_id"],
                    auth_state=auth_state_result["state"],
                    auth_cookies=auth_state_result.get("cookies", []),
                    cache_file_path=cache_file_path,
                )

            # 检查是否成功获取 cookies 和 api_user
            if success and result_data.get("cookies") and result_data.get("api_user"):
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                merged_cookies = {**waf_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, api_user, needs_check_in=False)
            else:
                # 返回错误信息
                return False, result_data

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

        # 解析账号配置
        cookies_data = self.account_info.cookies
        github_info = self.account_info.github
        linuxdo_info = self.account_info.linux_do
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: Trying cookies authentication")
            try:
                user_cookies = parse_cookies(cookies_data)
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
                    success, user_info = await self.check_in_with_github(username, password, waf_cookies)
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
                    use_camoufox = linuxdo_info.get("use_camoufox", True)
                    success, user_info = await self.check_in_with_linuxdo(
                        username, password, waf_cookies, use_camoufox=use_camoufox
                    )
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
