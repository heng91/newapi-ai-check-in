#!/usr/bin/env python3
"""
获取浏览器指纹头部信息的工具函数
用于 Cloudflare cf_clearance cookie 验证时保持指纹一致性
"""


async def get_browser_headers(page) -> dict:
    """从浏览器页面获取指纹头部信息
    
    获取 User-Agent 和 Client Hints (sec-ch-ua 系列头部)，
    用于后续 HTTP 请求时保持与浏览器指纹一致。
    
    Args:
        page: Playwright/Camoufox 页面对象
        
    Returns:
        包含 User-Agent 和 Client Hints 的字典
    """
    browser_headers = await page.evaluate(
        """() => {
            const ua = navigator.userAgent;
            const hints = {};
            
            // 基础 User-Agent
            hints['User-Agent'] = ua;
            
            // 解析 User-Agent 获取浏览器信息
            const chromeMatch = ua.match(/Chrome\\/([\\d.]+)/);
            const chromeVersion = chromeMatch ? chromeMatch[1] : '120.0.0.0';
            const chromeMajor = chromeVersion.split('.')[0];
            
            // 检测平台
            const platform = navigator.platform || 'Unknown';
            let platformName = 'Unknown';
            let platformVersion = '10.0.0';
            let arch = 'x86';
            let bitness = '64';
            let isMobile = false;
            
            if (platform.includes('Win')) {
                platformName = 'Windows';
                platformVersion = '10.0.0';
            } else if (platform.includes('Mac')) {
                platformName = 'macOS';
                platformVersion = '15.0.0';
                arch = 'arm';
            } else if (platform.includes('Linux')) {
                platformName = 'Linux';
                platformVersion = '6.5.0';
            }
            
            // 构建 sec-ch-ua 头部
            hints['sec-ch-ua'] = `"Google Chrome";v="${chromeMajor}", "Chromium";v="${chromeMajor}", "Not A(Brand";v="24"`;
            hints['sec-ch-ua-mobile'] = isMobile ? '?1' : '?0';
            hints['sec-ch-ua-platform'] = `"${platformName}"`;
            hints['sec-ch-ua-platform-version'] = `"${platformVersion}"`;
            hints['sec-ch-ua-arch'] = `"${arch}"`;
            hints['sec-ch-ua-bitness'] = `"${bitness}"`;
            hints['sec-ch-ua-full-version'] = `"${chromeVersion}"`;
            hints['sec-ch-ua-full-version-list'] = `"Google Chrome";v="${chromeVersion}", "Chromium";v="${chromeVersion}", "Not A(Brand";v="24.0.0.0"`;
            hints['sec-ch-ua-model'] = '""';
            
            return hints;
        }"""
    )
    
    return browser_headers


def print_browser_headers(account_name: str, browser_headers: dict) -> None:
    """打印浏览器指纹头部信息
    
    Args:
        account_name: 账号名称
        browser_headers: 浏览器指纹头部字典
    """
    print(f"ℹ️ {account_name}: Browser fingerprint captured:")
    print(f"  📱 User-Agent: {browser_headers.get('User-Agent', 'N/A')[:80]}...")
    print(f"  🔧 sec-ch-ua: {browser_headers.get('sec-ch-ua', 'N/A')}")
    print(f"  💻 sec-ch-ua-platform: {browser_headers.get('sec-ch-ua-platform', 'N/A')}")