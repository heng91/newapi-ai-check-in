#!/usr/bin/env python3
"""
获取浏览器指纹头部信息的工具函数
用于 Cloudflare cf_clearance cookie 验证时保持指纹一致性
"""


async def get_browser_headers(page) -> dict:
    """从浏览器页面获取指纹头部信息
    
    获取 User-Agent 和 Client Hints (sec-ch-ua 系列头部)，
    用于后续 HTTP 请求时保持与浏览器指纹一致。
    
    注意：Firefox 浏览器不支持 Client Hints (sec-ch-ua 系列头部)，
    只有 Chromium 系浏览器才会发送这些头部。如果检测到 Firefox，
    则只返回 User-Agent，不返回 sec-ch-ua 头部。
    
    Args:
        page: Playwright/Camoufox 页面对象
        
    Returns:
        包含 User-Agent 和可能的 Client Hints 的字典
    """
    browser_headers = await page.evaluate(
        """() => {
            const ua = navigator.userAgent;
            const hints = {};
            
            // 基础 User-Agent
            hints['User-Agent'] = ua;
            
            // 检测是否为 Firefox 浏览器
            // Firefox 不支持 Client Hints (sec-ch-ua 系列头部)
            // 只有 Chromium 系浏览器才发送这些头部
            const isFirefox = ua.includes('Firefox');
            
            if (isFirefox) {
                // Firefox 浏览器不发送 sec-ch-ua 头部
                // 标记为 Firefox 以便调用方知道
                hints['_isFirefox'] = true;
                return hints;
            }
            
            // 解析 User-Agent 获取 Chrome 版本信息
            const chromeMatch = ua.match(/Chrome\\/([\\d.]+)/);
            if (!chromeMatch) {
                // 如果不是 Chrome/Chromium 浏览器，也不发送 sec-ch-ua
                hints['_isChromium'] = false;
                return hints;
            }
            
            const chromeVersion = chromeMatch[1];
            const chromeMajor = chromeVersion.split('.')[0];
            
            // 从 User-Agent 中检测平台，而不是使用 navigator.platform
            // 因为在某些环境（如 GitHub Actions Windows）中，navigator.platform 可能返回错误的值
            // 这会导致 User-Agent 和 platform 不一致，被 Cloudflare 检测为 Bot
            let platformName = 'Unknown';
            let platformVersion = '10.0.0';
            let arch = 'x86';
            let bitness = '64';
            let isMobile = false;
            
            // 从 User-Agent 解析平台信息
            if (ua.includes('Windows NT')) {
                platformName = 'Windows';
                platformVersion = '10.0.0';
                arch = 'x86';
            } else if (ua.includes('Macintosh') || ua.includes('Mac OS X')) {
                platformName = 'macOS';
                platformVersion = '15.0.0';
                arch = 'arm';
            } else if (ua.includes('Linux') && !ua.includes('Android')) {
                platformName = 'Linux';
                platformVersion = '6.5.0';
                arch = 'x86';
            } else if (ua.includes('Android')) {
                platformName = 'Android';
                platformVersion = '14.0.0';
                isMobile = true;
            }
            
            // 构建 sec-ch-ua 头部（仅 Chromium 系浏览器）
            hints['sec-ch-ua'] = `"Google Chrome";v="${chromeMajor}", "Chromium";v="${chromeMajor}", "Not A(Brand";v="24"`;
            hints['sec-ch-ua-mobile'] = isMobile ? '?1' : '?0';
            hints['sec-ch-ua-platform'] = `"${platformName}"`;
            hints['sec-ch-ua-platform-version'] = `"${platformVersion}"`;
            hints['sec-ch-ua-arch'] = `"${arch}"`;
            hints['sec-ch-ua-bitness'] = `"${bitness}"`;
            hints['sec-ch-ua-full-version'] = `"${chromeVersion}"`;
            hints['sec-ch-ua-full-version-list'] = `"Google Chrome";v="${chromeVersion}", "Chromium";v="${chromeVersion}", "Not A(Brand";v="24.0.0.0"`;
            hints['sec-ch-ua-model'] = '""';
            hints['_isChromium'] = true;
            
            return hints;
        }"""
    )
    
    # 移除内部标记字段，不需要发送给服务器
    browser_headers.pop('_isFirefox', None)
    browser_headers.pop('_isChromium', None)
    
    return browser_headers


def print_browser_headers(account_name: str, browser_headers: dict) -> None:
    """打印浏览器指纹头部信息
    
    Args:
        account_name: 账号名称
        browser_headers: 浏览器指纹头部字典
    """
    print(f"ℹ️ {account_name}: Browser fingerprint captured:")
    for key, value in browser_headers.items():
        # User-Agent 较长，截断显示
        if key == "User-Agent":
            print(f"  📱 {key}: {value[:100]}...")
        else:
            print(f"  🔧 {key}: {value}")