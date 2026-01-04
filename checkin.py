#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import json
import hashlib
import os
import tempfile
from urllib.parse import urlparse

import httpx
from curl_cffi import requests as curl_requests
from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType
from utils.config import AccountConfig, ProviderConfig
from utils.browser_utils import parse_cookies, get_random_user_agent, take_screenshot, aliyun_captcha_check
from utils.http_utils import proxy_resolve, response_resolve
from utils.topup import topup
from utils.get_headers import get_browser_headers, print_browser_headers, get_curl_cffi_impersonate

class CheckIn:
    """newapi.ai 签到管理类"""

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config

        # 将全局代理存入 account_config.extra，供 get_cdk 和 check_in_status 等函数使用
        if global_proxy:
            self.account_config.extra["global_proxy"] = global_proxy

        # 代理优先级: 账号配置 > 全局配置
        self.camoufox_proxy_config = account_config.proxy if account_config.proxy else global_proxy
        # httpx.Client proxy 转换
        self.http_proxy_config = proxy_resolve(self.camoufox_proxy_config)

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get WAF cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
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

    async def get_cf_clearance_with_browser(self) -> tuple[dict | None, dict | None]:
        """使用 Camoufox 获取 Cloudflare cf_clearance cookie（隐私模式）
        
        使用 playwright-captcha 库自动点击 Cloudflare 验证按钮。
        
        Returns:
            tuple: (cf_cookies, browser_headers)
                - cf_cookies: Cloudflare cookies 字典，如果失败则为 None
                - browser_headers: 浏览器指纹头部信息字典，包含 User-Agent 和 Client Hints
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get cf_clearance cookie (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_cf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
                config={
                    "forceScopeAccess": True,
                }
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to trigger Cloudflare challenge")
                    
                    async with ClickSolver(
                        framework=FrameworkType.CAMOUFOX,
                        page=page,
                        max_attempts=5,
                        attempt_delay=3
                    ) as solver:
                        await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")
                        
                        # 检查是否在 Cloudflare 验证页面
                        page_title = await page.title()
                        page_content = await page.content()
                        
                        if "Just a moment" in page_title or "Checking your browser" in page_content:
                            print(f"ℹ️ {self.account_name}: Cloudflare challenge detected, auto-solving...")
                            try:
                                # 使用 ClickSolver 自动点击验证
                                await solver.solve_captcha(
                                    captcha_container=page,
                                    captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL
                                )
                                print(f"✅ {self.account_name}: Cloudflare challenge auto-solved")
                            except Exception as solve_err:
                                print(f"⚠️ {self.account_name}: Auto-solve failed: {solve_err}, waiting for manual verification...")
                                # 自动求解失败，回退到手动等待
                                await self._wait_for_cf_clearance_manually(browser, page)
                        else:
                            print(f"⚠️ {self.account_name}: No Cloudflare challenge detected")
                            # 不需要手动操作，但需要等待后台完成 Cloudflare 验证
                            await self._wait_for_cf_clearance_manually(browser, page)

                    # 最终获取所有 cookies
                    cookies = await browser.cookies()

                    cf_cookies = {}
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value[:50] if cookie_value and len(cookie_value) > 50 else cookie_value}...)")
                        # 获取 Cloudflare 相关的 cookies
                        if cookie_name in ["cf_clearance", "__cf_bm", "cf_chl_2", "cf_chl_prog"] and cookie_value is not None:
                            cf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(cf_cookies)} Cloudflare cookies")


                    # 使用工具函数获取浏览器指纹信息（User-Agent 和 Client Hints）
                    browser_headers = await get_browser_headers(page)
                    print_browser_headers(self.account_name, browser_headers)

                    # 检查是否获取到 cf_clearance cookie
                    if "cf_clearance" not in cf_cookies:
                        print(f"⚠️ {self.account_name}: cf_clearance cookie not obtained")
                        await take_screenshot(page, "cf_clearance_failed", self.account_name)
                        return None, browser_headers

                    # 显示获取到的 cookies
                    cookie_names = list(cf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got Cloudflare cookies: {cookie_names}")

                    return cf_cookies, browser_headers

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting cf_clearance cookie: {e}")
                    await take_screenshot(page, "cf_clearance_error", self.account_name)
                    return None, None
                finally:
                    await page.close()

    async def _wait_for_cf_clearance_manually(self, browser, page) -> None:
        """等待 Cloudflare 验证完成（手动）
        
        Args:
            browser: Camoufox 浏览器实例
            page: 页面实例
        """
        max_wait_time = 60000  # 60 秒
        check_interval = 2000  # 每 2 秒检查一次
        elapsed_time = 0

        while elapsed_time < max_wait_time:
            # 检查是否已经获取到 cf_clearance cookie
            cookies = await browser.cookies()
            cf_clearance = None
            for cookie in cookies:
                if cookie.get("name") == "cf_clearance":
                    cf_clearance = cookie.get("value")
                    break

            if cf_clearance:
                print(f"✅ {self.account_name}: cf_clearance cookie obtained")
                break

            # 检查页面是否还在 Cloudflare 验证页面
            page_title = await page.title()
            page_content = await page.content()
            
            if "Just a moment" in page_title or "Checking your browser" in page_content:
                print(f"ℹ️ {self.account_name}: Cloudflare challenge in progress, waiting...")
            else:
                # 页面已经加载完成，但可能还没有 cf_clearance
                print(f"ℹ️ {self.account_name}: Page loaded, checking for cf_clearance...")

            await page.wait_for_timeout(check_interval)
            elapsed_time += check_interval

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get Aliyun captcha cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: Captcha verification failed, "
                                f"traceid still present: {traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: Captcha verification successful, " f"traceid cleared")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: Aliyun Captcha cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"Got {len(aliyun_captcha_cookies)} "
                        f"Aliyun Captcha cookies after step 1"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"No Aliyun Captcha cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"Successfully got Aliyun Captcha cookies: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"Error occurred while getting Aliyun Captcha cookies, {e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access status page to get status from localStorage")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")
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
                data = response_resolve(response, f"get_auth_client_id_{provider}", self.account_name)
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get client id: Invalid response type (saved to logs)",
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

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. Open the login page first
                    print(f"ℹ️ {self.account_name}: Opening login page")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    response = await page.evaluate(
                        f"""async () => {{
                            try{{
                                const response = await fetch('{self.provider_config.get_auth_state_url()}');
                                const data = await response.json();
                                return data;
                            }}catch(e){{
                                return {{
                                    success: false,
                                    message: e.message
                                }};
                            }}
                        }}"""
                    )

                    if response and "data" in response:
                        cookies = await browser.cookies()
                        return {
                            "success": True,
                            "state": response.get("data"),
                            "cookies": cookies,
                        }

                    return {"success": False, "error": f"Failed to get state, \n{json.dumps(response, indent=2)}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get state, {e}")
                    await take_screenshot(page, "auth_url_error", self.account_name)
                    return {"success": False, "error": "Failed to get state"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        client: httpx.Client,
        headers: dict,
    ) -> dict:
        """获取认证状态
        
        Args:
            client: httpx 客户端
            headers: 请求头
        """
        try:
            response = client.get(self.provider_config.get_auth_state_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_auth_state", self.account_name)
                if json_data is None:
                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting auth state from browser")
                    # try:
                    #     auth_result = await self.get_auth_state_with_browser()

                    #     if not auth_result.get("success"):
                    #         error_msg = auth_result.get("error", "Unknown error")
                    #         print(f"❌ {self.account_name}: {error_msg}")
                    #         return {
                    #             "success": False,
                    #             "error": "Failed to get auth state with browser",
                    #         }

                    #     return auth_result
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get auth state from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get auth state: Invalid response type (saved to logs)",
                    }

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 httpx Cookies 对象转换为 Camoufox 格式
                    cookies = []
                    if response.cookies:
                        parsed_domain = urlparse(self.provider_config.origin).netloc

                        print(f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request")
                        for cookie in response.cookies.jar:
                            http_only = cookie.httponly if cookie.has_nonstandard_attr("httponly") else False
                            same_site = cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax"
                            print(
                                f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                                f"Path: {cookie.path}, Expires: {cookie.expires}, "
                                f"HttpOnly: {http_only}, Secure: {cookie.secure}, "
                                f"SameSite: {same_site})"
                            )
                            cookies.append(
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
                        "cookies": cookies,  # 直接返回 Camoufox 格式的 cookies
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
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

    async def get_auth_state_with_curl_cffi(
        self,
        headers: dict,
        bypass_cookies: dict,
        impersonate: str = "firefox135",
    ) -> dict:
        """使用 curl_cffi 获取认证状态（模拟浏览器 TLS 指纹）
        
        curl_cffi 可以模拟真实浏览器的 TLS 指纹，这对于严格的 Cloudflare 配置是必要的。
        httpx 使用 Python 的 TLS 实现，指纹与浏览器完全不同，会被 Cloudflare 拒绝。
        
        Args:
            headers: 请求头
            bypass_cookies: bypass cookies
            impersonate: curl_cffi impersonate 值，指定要模拟的浏览器 TLS 指纹
                        （如 "firefox135", "chrome131" 等）
        """
        try:
            # 使用 curl_cffi 发送请求，模拟浏览器的 TLS 指纹
            # impersonate 参数指定要模拟的浏览器
            print(f"ℹ️ {self.account_name}: Using curl_cffi with impersonate={impersonate}")
            response = curl_requests.get(
                self.provider_config.get_auth_state_url(),
                headers=headers,
                cookies=bypass_cookies,
                impersonate=impersonate,
                timeout=30,
                proxy=self.http_proxy_config,
            )

            if response.status_code == 200:
                try:
                    json_data = response.json()
                except Exception:
                    # 保存响应内容到日志
                    log_file = f"logs/get_auth_state_curl_{self.account_name}.html"
                    os.makedirs("logs", exist_ok=True)
                    with open(log_file, "w", encoding="utf-8") as f:
                        f.write(response.text)
                    print(f"⚠️ {self.account_name}: Response saved to {log_file}")
                    return {
                        "success": False,
                        "error": "Failed to get auth state: Invalid response type (saved to logs)",
                    }

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 curl_cffi Cookies 转换为 Camoufox 格式
                    cookies = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc

                    print(f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request")
                    for cookie in response.cookies.jar:
                        print(
                            f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                            f"Path: {cookie.path}, Expires: {cookie.expires}, "
                            f"HttpOnly: {cookie._rest.get('HttpOnly', False)}, Secure: {cookie.secure}, "
                            f"SameSite: {cookie._rest.get('SameSite', 'Lax')})"
                        )
                        cookies.append(
                            {
                                "name": cookie.name,
                                "domain": cookie.domain if cookie.domain else parsed_domain,
                                "value": cookie.value,
                                "path": cookie.path,
                                "expires": cookie.expires,
                                "secure": cookie.secure,
                                "httpOnly": cookie._rest.get("HttpOnly", False),
                                "sameSite": cookie._rest.get("SameSite", "Lax"),
                            }
                        )

                    return {
                        "success": True,
                        "state": auth_data,
                        "cookies": cookies,
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
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
                "error": f"Failed to get auth state with curl_cffi, {e}",
            }

    async def get_user_info_with_browser(self, auth_cookies: list[dict]) -> dict:
        """使用 Camoufox 获取用户信息

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get user info (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                browser.add_cookies(auth_cookies)

                try:
                    # 1. 打开登录页面
                    print(f"ℹ️ {self.account_name}: Opening main page")
                    await page.goto(self.provider_config.origin, wait_until="networkidle")

                    # 等待页面完全加载
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 获取用户信息
                    response = await page.evaluate(
                        f"""async () => {{
                           const response = await fetch(
                               '{self.provider_config.get_user_info_url()}'
                           );
                           const data = await response.json();
                           return data;
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: "
                            f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get user info, \n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await take_screenshot(page, "user_info_error", self.account_name)
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

    async def get_user_info(self, client: httpx.Client, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = client.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_user_info", self.account_name)
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "Failed to get user info: Invalid response type (saved to logs)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "bonus_quota": bonus_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
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

    def execute_check_in(
        self,
        client: httpx.Client,
        headers: dict,
        api_user: str | int,
    ) -> dict:
        """执行签到请求
        
        Returns:
            包含 success, message, data 等信息的字典
        """
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        check_in_url = self.provider_config.get_check_in_url(api_user)
        if not check_in_url:
            print(f"❌ {self.account_name}: No check-in URL configured")
            return {"success": False, "error": "No check-in URL configured"}

        response = client.post(check_in_url, headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        # 尝试解析响应（200 或 400 都可能包含有效的 JSON）
        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_check_in", self.account_name)
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return {"success": True, "message": "Check-in successful"}
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return {"success": False, "error": "Invalid response format"}

            # 检查签到结果
            message = json_data.get("message", json_data.get("msg", ""))

            if (
                json_data.get("ret") == 1
                or json_data.get("code") == 0
                or json_data.get("success")
                or "已经签到" in message
                or "签到成功" in message
            ):
                # 提取签到数据
                check_in_data = json_data.get("data", {})
                checkin_date = check_in_data.get("checkin_date", "")
                quota_awarded = check_in_data.get("quota_awarded", 0)
                
                if quota_awarded:
                    quota_display = round(quota_awarded / 500000, 2)
                    print(f"✅ {self.account_name}: Check-in successful! Date: {checkin_date}, Quota awarded: ${quota_display}")
                else:
                    print(f"✅ {self.account_name}: Check-in successful! {message}")
                
                return {
                    "success": True,
                    "message": message or "Check-in successful",
                    "data": check_in_data,
                }
            else:
                error_msg = json_data.get("msg", json_data.get("message", "Unknown error"))
                print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
                return {"success": False, "error": error_msg}
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return {"success": False, "error": f"HTTP {response.status_code}"}

    async def execute_topup(
        self,
        headers: dict,
        cookies: dict,
        api_user: str | int,
        topup_interval: int = 60,
    ) -> dict:
        """执行完整的 CDK 获取和充值流程

        直接调用 get_cdk 生成器函数，每次 yield 一个 CDK 字符串并执行 topup
        每次 topup 之间保持间隔时间，如果 topup 失败则停止

        Args:
            headers: 请求头
            cookies: cookies 字典
            api_user: API 用户 ID（通过参数传递，因为登录方式可能不同）
            topup_interval: 多次 topup 之间的间隔时间（秒），默认 60 秒

        Returns:
            包含 success, topup_count, errors 等信息的字典
        """
        http_proxy = proxy_resolve(self.camoufox_proxy_config)

        # 获取 topup URL
        topup_url = self.provider_config.get_topup_url()
        if not topup_url:
            print(f"❌ {self.account_name}: No topup URL configured for provider {self.provider_config.name}")
            return {
                "success": False,
                "topup_count": 0,
                "errors": ["No topup URL configured"],
            }

        # 检查是否配置了 get_cdk 函数
        if not self.provider_config.get_cdk:
            print(f"ℹ️ {self.account_name}: No get_cdk function configured for provider {self.provider_config.name}")
            return {
                "success": True,
                "topup_count": 0,
                "topup_success_count": 0,
                "error": "",
            }

        # 构建 topup 请求头
        topup_headers = headers.copy()
        topup_headers.update({
            "Referer": f"{self.provider_config.origin}/console/topup",
            "Origin": self.provider_config.origin,
            self.provider_config.api_user_key: f"{api_user}",
        })

        results = {
            "success": True,
            "topup_count": 0,
            "topup_success_count": 0,
            "error": "",
        }

        # 直接调用 get_cdk 生成器函数，每次 yield 一个 CDK 字符串
        cdk_generator = self.provider_config.get_cdk(self.account_config)
        topup_count = 0
        error_msg = ""

        for cdk in cdk_generator:
            # 如果不是第一个 CDK，等待间隔时间
            if topup_count > 0 and topup_interval > 0:
                print(f"⏳ {self.account_name}: Waiting {topup_interval} seconds before next topup...")
                await asyncio.sleep(topup_interval)

            topup_count += 1
            print(f"💰 {self.account_name}: Executing topup #{topup_count} with CDK: {cdk}")

            topup_result = topup(
                account_name=self.account_name,
                topup_url=topup_url,
                headers=topup_headers,
                cookies=cookies,
                key=cdk,
                proxy=http_proxy,
            )

            results["topup_count"] += 1

            if topup_result.get("success"):
                results["topup_success_count"] += 1
                if not topup_result.get("already_used"):
                    print(f"✅ {self.account_name}: Topup #{topup_count} successful")
            else:
                # topup 失败，记录错误并停止
                error_msg = topup_result.get("error", "Topup failed")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: Topup #{topup_count} failed, stopping topup process")
                break

        if topup_count == 0:
            print(f"ℹ️ {self.account_name}: No CDK available for topup")
        elif results["topup_success_count"] > 0:
            print(f"✅ {self.account_name}: Total {results['topup_success_count']}/{results['topup_count']} topup(s) successful")

        return results

    async def check_in_with_cookies(
        self,
        cookies: dict,
        common_headers: dict,
        api_user: str | int,
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作
        
        Args:
            cookies: cookies 字典
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询函数，先检查是否已签到
                if self.provider_config.has_check_in_status():
                    checked_in_today = self.provider_config.check_in_status(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=cookies,
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: Already checked in today, skipping check-in")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(client, headers, api_user)
                        if not check_in_result.get("success"):
                            return False, {"error": check_in_result.get("error", "Check-in failed")}
                        # 签到成功后再次查询状态（显示最新状态）
                        self.provider_config.check_in_status(
                            provider_config=self.provider_config,
                            account_config=self.account_config,
                            cookies=cookies,
                            headers=headers,
                        )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(client, headers, api_user)
                    if not check_in_result.get("success"):
                        return False, {"error": check_in_result.get("error", "Check-in failed")}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: Provider requires manual topup, executing...")
                topup_result = await self.execute_topup(headers, cookies, api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: Topup completed - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} successful"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "Topup failed"
                    print(f"❌ {self.account_name}: Topup failed, stopping check-in process")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(client, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get user info"}
            else:
                return False, {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            client.close()

    async def check_in_with_github(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作
        
        Args:
            username: GitHub 用户名
            password: GitHub 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with GitHub account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # 获取 OAuth 认证状态
            # 如果使用 cf_clearance bypass，需要使用 curl_cffi 模拟 Firefox TLS 指纹
            if self.provider_config.needs_cf_clearance():
                # 使用 curl_cffi 模拟浏览器 TLS 指纹
                # 根据 User-Agent 自动推断 impersonate 值
                user_agent = headers.get("User-Agent", "")
                impersonate = get_curl_cffi_impersonate(user_agent)
                auth_state_result = await self.get_auth_state_with_curl_cffi(
                    headers=headers,
                    bypass_cookies=bypass_cookies,
                    impersonate=impersonate,
                )
            else:
                # 使用 httpx 发送请求
                auth_state_result = await self.get_auth_state(
                    client=client,
                    headers=headers,
                )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data, oauth_browser_headers = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_github_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = client.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "github_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            client.close()

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with Linux.do account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using Linux.do client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get Linux.do client ID"}

            # 获取 OAuth 认证状态
            # 如果使用 cf_clearance bypass，需要使用 curl_cffi 模拟 Firefox TLS 指纹
            if self.provider_config.needs_cf_clearance():
                # 使用 curl_cffi 模拟浏览器 TLS 指纹
                # 根据 User-Agent 自动推断 impersonate 值
                user_agent = headers.get("User-Agent", "")
                impersonate = get_curl_cffi_impersonate(user_agent)
                auth_state_result = await self.get_auth_state_with_curl_cffi(
                    headers=headers,
                    bypass_cookies=bypass_cookies,
                    impersonate=impersonate,
                )
            else:
                # 使用 httpx 发送请求
                auth_state_result = await self.get_auth_state(
                    client=client,
                    headers=headers,
                )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data, oauth_browser_headers = await linuxdo.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result["state"],
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_linuxdo_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = client.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "linuxdo_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, updated_headers, api_user)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        bypass_cookies = {}
        browser_headers = None  # 浏览器指纹头部信息
        
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if waf_cookies:
                bypass_cookies = waf_cookies
                print(f"✅ {self.account_name}: WAF cookies obtained")
            else:
                print(f"⚠️ {self.account_name}: Unable to get WAF cookies, continuing with empty cookies")

        elif self.provider_config.needs_cf_clearance():
            # get_cf_clearance_with_browser 现在返回 (cookies, browser_headers) 元组
            cf_result = await self.get_cf_clearance_with_browser()
            
            if cf_result[0]:
                bypass_cookies = cf_result[0]
                print(f"✅ {self.account_name}: Cloudflare cookies obtained")
            else:
                print(f"⚠️ {self.account_name}: Unable to get Cloudflare cookies, continuing with empty cookies")

            # 因为 Cloudflare 验证需要一致的浏览器指纹
            if cf_result[1]:
                browser_headers = cf_result[1]
                print(f"✅ {self.account_name}: Cloudflare fingerprint headers obtained")
        else:
            print(f"ℹ️ {self.account_name}: Bypass not required, using user cookies directly")

        # 生成公用请求头（只生成一次 User-Agent，整个签到流程保持一致）
        # 注意：Referer 和 Origin 不在这里设置，由各个签到方法根据实际请求动态设置
        if browser_headers:
            # 如果有浏览器指纹头部（来自 cf_clearance 获取），使用它
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": browser_headers.get("User-Agent", get_random_user_agent()),
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            
            # 只有当 browser_headers 中包含 sec-ch-ua 时才添加 Client Hints 头部
            # Firefox 浏览器不支持 Client Hints，所以 browser_headers 中不会有这些头部
            # 如果强行添加会导致 Cloudflare 检测到指纹不一致而返回 403
            if "sec-ch-ua" in browser_headers:
                common_headers.update({
                    "sec-ch-ua": browser_headers.get("sec-ch-ua", ""),
                    "sec-ch-ua-mobile": browser_headers.get("sec-ch-ua-mobile", "?0"),
                    "sec-ch-ua-platform": browser_headers.get("sec-ch-ua-platform", ""),
                    "sec-ch-ua-platform-version": browser_headers.get("sec-ch-ua-platform-version", ""),
                    "sec-ch-ua-arch": browser_headers.get("sec-ch-ua-arch", ""),
                    "sec-ch-ua-bitness": browser_headers.get("sec-ch-ua-bitness", ""),
                    "sec-ch-ua-full-version": browser_headers.get("sec-ch-ua-full-version", ""),
                    "sec-ch-ua-full-version-list": browser_headers.get("sec-ch-ua-full-version-list", ""),
                    "sec-ch-ua-model": browser_headers.get("sec-ch-ua-model", '""'),
                })
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (with Client Hints)")
            else:
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (Firefox, no Client Hints)")
        else:
            # 没有浏览器指纹，生成一次随机 User-Agent 并在整个流程中使用
            random_ua = get_random_user_agent()
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": random_ua,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            print(f"ℹ️ {self.account_name}: Using random User-Agent (generated once)")

        # 解析账号配置
        cookies_data = self.account_config.cookies
        github_info = self.account_config.github
        linuxdo_info = self.account_config.linux_do
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
                    api_user = self.account_config.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append(("cookies", False, {"error": "API user identifier not found"}))
                    else:
                        # 使用已有 cookies 执行签到，传入公用请求头
                        all_cookies = {**bypass_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, common_headers, api_user)
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
                    # 使用 GitHub 账号执行签到，传入公用请求头
                    success, user_info = await self.check_in_with_github(
                        username, password, bypass_cookies, common_headers
                    )
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
                    # 使用 Linux.do 账号执行签到，传入公用请求头
                    success, user_info = await self.check_in_with_linuxdo(
                        username,
                        password,
                        bypass_cookies,
                        common_headers,
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

   