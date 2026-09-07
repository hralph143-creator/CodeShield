# CodeShield——多语言代码敏感信息扫描与泄露风险评估工具

## 1. 项目简介

CodeShield 是一套本地运行的多语言代码敏感信息扫描与泄露风险评估工具，用于发现软件项目中密码、API Key、Token、Private Key、数据库连接凭证及个人敏感信息等潜在泄露风险。

系统全程本地离线分析，不上传用户源码；对敏感内容默认脱敏，原始 Secret 不写入扫描历史、报告和日志。

## 2. 功能说明

- 本地代码项目目录扫描；
- 支持将本地项目文件夹直接拖入扫描页面；
- 支持 Python、Java、JavaScript/TypeScript、C/C++、R、Rust 及常见配置文件；
- 检测 Password、API Key、Secret、Token、JWT、Private Key、数据库凭证、邮箱、手机号、身份证号等敏感信息；
- 正则规则匹配；
- 敏感变量与硬编码上下文分析；
- Shannon 信息熵检测；
- 0～100 可解释风险评分；
- 严重、高、中、低四级风险分级；
- 敏感信息默认脱敏；
- 扫描结果搜索与多维筛选；
- 复制风险脱敏摘要、打开源文件所在目录；
- SQLite 扫描历史保存与回看；
- 风险处理状态（未处理、已确认、误报、已忽略、已修复）；
- 指纹、文件、目录、规则四类白名单；
- 内置规则启用 / 禁用；
- 自定义检测规则；
- 同一项目扫描前后风险对比；
- 离线 HTML 报告与 JSON 报告导出；
- 后台线程扫描、实时进度与协作式取消；
- 标准、完整、自定义三种扫描模式；
- 测试/演示、第三方依赖/元数据、生成产物和检测器规则特征的来源分析；
- 本地安全日志、日志轮转与未处理异常保护；
- SQLite 升级前自动备份、事务迁移与失败回滚；
- 全程本地离线处理。

## 3. 支持的编程语言与文件类型

| 类型 | 后缀 / 文件名 |
| --- | --- |
| Python | `.py` |
| Java | `.java` |
| JavaScript | `.js`、`.jsx` |
| TypeScript | `.ts`、`.tsx` |
| C | `.c`、`.h` |
| C++ | `.cpp`、`.hpp` |
| R | `.r` |
| Rust | `.rs` |
| 配置文件 | `.env`、`.ini`、`.conf`、`.cfg`、`.properties`、`.yaml`、`.yml`、`.json`、`.xml`、`.toml` |

扫描会递归遍历所选目录，跳过符号链接、二进制文件与超过大小上限的文件。标准模式默认忽略 `.git`、`node_modules`、`build`、`venv` 等明确高噪声目录；完整模式会纳入依赖和构建产物；自定义模式使用用户配置的扩展名与忽略目录。

## 4. 支持检测的敏感信息类型

- 硬编码密码（Password）
- API Key
- Secret
- Token
- JWT Token
- Private Key（私钥文件头）
- 带认证信息的数据库连接串（URI / JDBC）
- 邮箱（Email）
- 手机号（Phone）
- 身份证号（ID Card）

其中邮箱、手机号、身份证号属于个人信息检测，可在扫描配置中关闭。

## 5. 核心检测原理

```
规则匹配
+ 上下文关键词分析
+ Shannon 信息熵
+ 结构验证
+ 误报降权
↓
可解释风险评分
```

- 先由正则规则在源码行中定位候选凭证，只对命中规则的候选进行后续分析；
- 上下文分析识别敏感变量名、直接字符串赋值、注释、测试或演示路径、第三方依赖/元数据、生成产物、检测器规则特征与占位值；
- Shannon 信息熵与字符串长度作为凭证可信度因子；**高信息熵只是风险因子之一，不会单独作为严重风险判定依据**；
- 身份证校验位、JWT 三段式结构与数据库凭证来源做结构验证；
- 环境变量读取、动态配置读取、测试目录、第三方来源、生成产物、注释、占位值等因素参与误报控制，降低评分而不直接删除结果；测试和演示代码不会被直接忽略。
- Private Key 只有在起始标记、合理的 PEM/Base64 主体和匹配的结束标记同时存在时才获得完整结构证据；单独 Header 只作为低可信格式特征。

## 6. 风险评分与风险等级

- 0～29：低
- 30～49：中
- 50～74：高
- 75～100：严重

| 等级 | 颜色 |
| --- | --- |
| 严重 | 红色 |
| 高 | 橙色 |
| 中 | 黄色 |
| 低 | 蓝色 |

每条风险会列出评分因子明细（规则命中、敏感变量、直接赋值、信息熵、格式证据、注释 / 测试路径 / 占位值 / 动态来源降权等），评分依据可解释。

## 7. 项目目录结构

```
CodeShield/
├── main.py                    # 程序入口（GUI / 自检 / 命令行扫描）
├── requirements.txt           # 第三方依赖
├── rules/
│   └── builtin_rules.json     # 内置检测规则
├── resources/                 # 图标资源
├── demo_project/              # 虚构演示项目
├── tests/                     # 自动化测试
├── docs/
│   └── ARCHITECTURE.md        # 架构说明
└── codeshield/
    ├── bootstrap.py           # 运行时装配
    ├── config.py              # 配置加载与校验
    ├── database.py            # SQLite 持久化与迁移
    ├── scanner.py             # 目录扫描与文件读取
    ├── language.py            # 语言识别
    ├── rules.py               # 规则加载与匹配
    ├── context.py             # 上下文分析
    ├── entropy.py             # Shannon 信息熵
    ├── risk.py                # 风险评分
    ├── masking.py             # 敏感信息脱敏
    ├── validation.py          # 结构校验
    ├── comparison.py          # 扫描前后比较
    ├── reporting.py           # HTML / JSON 报告
    ├── models.py              # 数据模型
    └── ui/                    # 桌面界面
```

## 8. 环境配置

- 操作系统：Windows 10 / Windows 11
- Python：3.12（发布构建实际验证版本）

## 9. 安装依赖

在项目根目录执行：

```powershell
python -m venv .venv
```

Windows CMD：

```cmd
.venv\Scripts\activate
```

安装依赖：

```cmd
python -m pip install -r requirements.txt
```

## 10. 运行步骤

启动配置与数据库自检：

```cmd
python main.py --check
```

启动桌面程序：

```cmd
python main.py
```

使用流程：

1. 启动 CodeShield；
2. 点击左侧“项目扫描”；
3. 点击“选择项目”并选择本地源码目录；
4. 选择标准、完整或自定义扫描模式；自定义模式可调整文件大小、个人信息、扩展名和忽略目录；
5. 点击“开始扫描”；
6. 等待扫描完成；
7. 进入“扫描结果”查看风险；
8. 点击具体风险查看检测依据、评分和修复建议；
9. 可通过“扫描历史”查看历史记录；
10. 可在“检测规则”页面的“白名单”页签中管理误报；
11. 可在“检测规则”页面的“规则管理”页签中管理规则；
12. 可通过扫描对比查看风险变化；
13. 可在“报告中心”导出 HTML 或 JSON 报告。

命令行模式：

```cmd
python main.py --scan-demo
```

```cmd
python main.py --scan-demo --explain
```

```cmd
python main.py --scan C:\Projects\example
```

命令行只显示相对路径、位置和脱敏值，不输出匹配到的完整凭证。

## 11. 软件使用说明

- **概览**：展示累计扫描项目、文件、风险与严重风险统计，以及风险等级分布、最近扫描、候选/跳过/读取失败/白名单抑制统计、当前启用策略数量和最近项目语言构成；可直接重新扫描最近项目或打开最近结果；
- **项目扫描**：选择或拖入目录，设置扫描模式、调整自定义配置、开始或取消扫描，实时显示进度与当前文件；
- **扫描结果**：按关键词、等级、类型、语言筛选风险项，查看风险来源、脱敏内容、检测依据、评分因子、脱敏上下文与修复建议，可修改处置状态、加入白名单、复制脱敏摘要或打开源文件所在目录；
- **扫描历史**：回看历史扫描快照，支持搜索、状态筛选、详情打开与删除，并可发起扫描对比；
- **检测规则**：通过“规则管理”和“白名单”两个页签统一管理检测策略；支持启用 / 禁用内置规则，新增、编辑、删除自定义规则，并按风险指纹、文件路径、目录前缀、规则四类管理白名单；
- **报告中心**：选择已完成扫描，导出离线 HTML 或 JSON 报告；
- **设置**：保存或恢复默认扫描模式、文件大小和个人信息检测设置，并可打开数据目录或日志目录。恢复默认扫描设置不会删除历史、白名单或自定义规则。

## 12. 团队分工

**孙兴舟——项目负责人 / 核心功能开发**：负责项目需求分析与功能设计、软件整体架构设计、核心代码扫描流程、多语言文件识别与文件安全处理、敏感信息规则检测、上下文分析、Shannon 信息熵检测、风险评分与风险分级、敏感信息脱敏、扫描前后风险比较，以及核心功能联调与整体质量把控。

**李亚龙——桌面界面与数据管理开发**：负责 PySide6 桌面界面实现与交互优化、项目扫描页面、扫描结果与风险详情展示、SQLite 扫描历史、风险处理状态、白名单管理、检测规则管理界面、HTML / JSON 报告功能，以及 GUI 功能联调与使用体验优化。

**郭奕博——测试验证与文档整理**：负责功能测试、测试用例整理、演示测试数据检查、软件运行环境验证、依赖核对、README 整理、项目目录与提交材料检查，并辅助整体功能验收。

## 13. 数据安全与隐私说明

设置与扫描历史存放在当前 Windows 用户的 `%LOCALAPPDATA%\CodeShield`，受限环境无法写入时回退到项目内的 `.codeshield_data`。日志存放在其 `logs` 子目录，单个 `codeshield.log` 最大 3 MB，并保留 4 个轮转文件。日志格式化器会再次脱敏密码、Token、API Key、数据库凭证、身份证号和完整私钥结构。

数据库只在实际需要 schema migration 时，于 `backups` 子目录创建升级前备份并保留最近 5 份；迁移在单个事务中执行，失败会回滚且保留备份。

数据库只保存脱敏值、脱敏上下文、风险因子和 SHA-256 指纹，不保存完整密码、Token、私钥等原始 Secret。扫描对比与报告导出只读取 SQLite 中的脱敏快照，不会为展示或导出重新读取源码。历史中的本地项目路径不会上传或发送到任何外部服务。

## 14. 第三方依赖说明

本项目仅依赖一个第三方 Python 包：

```text
PySide6==6.11.2
```

其余功能全部使用 Python 标准库实现，无其它运行时依赖。

## 15. Windows 下载安装

普通用户不需要安装 Python。获取 `CodeShield_Setup_1.0.0.exe` 后双击运行，按安装向导完成安装，再从 Windows 开始菜单启动 CodeShield。默认安装目录为：

```text
C:\Program Files\CodeShield
```

安装向导提供一个默认不勾选的桌面快捷方式选项。当前安装包未进行商业代码签名，Windows 可能显示未知发布者或 SmartScreen 提示；不要为此关闭系统安全功能。

安装程序、便携测试构建和源码运行方式用途不同：正式交付使用安装程序；`release\CodeShield-1.0.0\CodeShield` 是发布验收使用的 onedir 构建。

## 16. 卸载与用户数据

可从 Windows“设置 → 应用 → 已安装的应用”卸载 CodeShield，也可使用开始菜单中的“卸载 CodeShield”。卸载会删除程序文件和快捷方式，默认保留 `%LOCALAPPDATA%\CodeShield` 中的历史、白名单、自定义规则、设置、日志和数据库备份，重装后可以继续使用。

若要彻底清除个人数据，请先关闭 CodeShield，再手动删除：

```text
%LOCALAPPDATA%\CodeShield
```

## 17. 发布构建

构建机使用 Python 3.12。先建立干净虚拟环境并分别安装运行依赖与构建依赖：

```powershell
py -3.12 -m venv .venv-release
.\.venv-release\Scripts\python.exe -m pip install --upgrade pip
.\.venv-release\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-release\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv-release\Scripts\python.exe scripts\build_release.py
```

构建脚本会运行测试、自检和编译检查，再根据 `CodeShield.spec` 生成无控制台的 PyInstaller onedir 构建，并整理到 `release\CodeShield-1.0.0`。安装 Inno Setup 后执行：

```powershell
.\.venv-release\Scripts\python.exe scripts\build_installer.py
```

安装器输出为 `installer\Output\CodeShield_Setup_1.0.0.exe`。构建脚本不会上传产物，也不会读取或删除 `%LOCALAPPDATA%\CodeShield`。

## 18. 已验证平台范围

CodeShield 1.0 发布版已在 64 位 Windows 11 25H2（内部版本 26200.9168）和 150% 系统缩放下完成安装、启动、扫描、持久化、卸载与重装验证；等效 100% 缩放的 1280×720 窗口也完成了核心按钮验收。Windows 10、125% 缩放以及独立的 1920×1080 / 1366×768 / 2560×1440 设备仍待外部设备验证，不在 README 中宣称已实测。
