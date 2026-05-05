# Burp 漏洞扫描插件

一款面向 Burp Suite 的漏洞扫描扩展插件，支持对 Log4j RCE、Apache Shiro、Fastjson RCE 和 Next.js RCE 进行被动和主动扫描检测。

## 功能特性

- **被动扫描**：自动检测经过 Burp Proxy 的 HTTP 流量中的漏洞
- **主动扫描**：主动向目标发送特定 Payload 验证漏洞存在性
- **右键菜单集成**：支持对指定请求快速发起定向扫描
- **仪表盘面板**：在独立标签页中查看漏洞日志和扫描结果
- **流量详情查看器**：点击漏洞记录查看对应的 HTTP 请求/响应数据包
- **灵活配置**：可独立开关各漏洞检测器及扫描模式

## 支持检测的漏洞

| 漏洞类型 | 检测方式 |
|---------|---------|
| Log4j RCE (CVE-2021-44228) | 检测请求中的 JNDI 模式 (`${jndi:`) |
| Apache Shiro | 检测 rememberMe Cookie 及响应指纹 |
| Fastjson RCE | 多策略 Payload 检测（语法错误、AutoCloseable 版本识别、DNS 通道、版本绕过） |
| Next.js RCE | 检测框架指纹特征 |

## 环境要求

- **JDK 17+**
- **Burp Suite Professional/Community Edition** (需支持 Montoya API)
- **Maven 3.6+** (用于构建)

## 安装方法

### 方式一：下载预构建 JAR

从 [Releases](https://github.com/your-repo/burp-scanner-plugin/releases) 页面下载最新版本。

### 方式二：源码构建

```bash
git clone https://github.com/your-repo/burp-scanner-plugin.git
cd burp-scanner-plugin
mvn clean package
```

构建产物位于 `target/burp-scanner-plugin-1.0.0.jar`。

### 加载到 Burp Suite

1. 打开 Burp Suite
2. 进入 **Extensions** → **Installed** → **Add new extension**
3. 选择 **Java** 作为扩展类型
4. 选择 JAR 文件
5. 点击 **Next** 加载

## 使用说明

### 仪表盘

加载插件后，Burp Suite 会新增 **"Vuln Scanner"** 标签页：

- **Scanner Controls**：开关被动扫描、主动扫描及各漏洞检测器
- **Vulnerability Logs**：表格展示发现的漏洞，包含域名、漏洞名称、URL
- **Scan Log**：实时显示扫描活动日志
- **Traffic Detail**：点击漏洞记录查看 HTTP 请求/响应详情

### 右键菜单

在 Proxy、Target、Repeater 或 Intruder 中选中请求后右键：

- **Vuln Scanner** → **Scan Log4j RCE**
- **Vuln Scanner** → **Scan Apache Shiro**
- **Vuln Scanner** → **Scan Fastjson RCE**
- **Vuln Scanner** → **Scan Next.js RCE**
- **Vuln Scanner** → **Scan All Enabled**

### Fastjson 检测策略

Fastjson 检测采用多 Payload 策略：

1. **语法错误 Payload**：通过触发解析错误检测 fastjson
2. **AutoCloseable 版本识别**：利用 AutoCloseable 类型探测 fastjson 版本
3. **版本绕过 Payload**：针对不同版本绕过类型限制
4. **DNS 外带检测**：通过 Burp Collaborator 利用 DNS 通道检测
5. **JNDI 漏洞利用**：测试 JdbcRowSetImpl 和 ShiroAutoType Payload

## 项目结构

```
src/main/java/com/scanner/
├── BurpScannerExtension.java      # 插件主入口
├── ApiLogger.java               # 统一日志输出
├── checks/
│   ├── PassiveScanChecks.java   # 被动扫描实现
│   └── ActiveScanChecks.java     # 主动扫描实现
├── ui/
│   ├── ScannerDashboard.java     # 仪表盘主界面
│   ├── TrafficDetailPanel.java  # 请求/响应查看器
│   ├── ScanContextMenu.java     # 右键菜单项
│   └── ScanLogger.java          # 扫描日志工具
├── vuln/
│   ├── VulnerabilityDetector.java # 检测器基类接口
│   ├── Log4jDetector.java        # Log4j 检测
│   ├── ShiroDetector.java        # Shiro 检测
│   ├── FastjsonDetector.java     # Fastjson 检测
│   ├── FastjsonPayloads.java    # Fastjson Payload 库
│   └── NextJsDetector.java       # Next.js 检测
└── util/
    └── CollaboratorHelper.java    # Burp Collaborator 集成
```

## 配置说明

通过仪表盘中的复选框可进行精细配置：

| 选项 | 说明 |
|-----|------|
| Passive Scan | 开关被动扫描（检测代理流量） |
| Active Scan | 开关主动扫描（发送探测 Payload） |
| Log4j RCE | 开关 Log4j 检测器 |
| Apache Shiro | 开关 Shiro 检测器 |
| Fastjson RCE | 开关 Fastjson 检测器 |
| Next.js RCE | 开关 Next.js 检测器 |

## 免责声明

本工具仅用于授权的安全测试和教育目的。扫描任何目标前请确保已获得明确授权。作者不对工具的滥用承担责任。

## 开源协议

Apache License 2.0 - 详见 LICENSE 文件。