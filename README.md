# HashCrack — hashcat 图形化破解工具

以 hashcat 为内核的图形化密码恢复工具。**拖入文件 → 自动识别类型 → 自动提取哈希 → 自动破解 → 显示明文**，全程无需人工干预。

## 核心特性

- **零依赖绿色便携**：内置 hashcat 内核、便携 Python 运行时、全部提取工具。整包拷到任意 Windows 电脑双击即用，不需要安装 Python、hashcat 或任何运行环境
- **无路径依赖**：所有路径基于可执行文件所在目录相对解析，代码里没有任何写死的绝对路径
- **全自动流水线**：识别 → 提取 → 破解 → 展示，用户只需要拖一个文件
- **自动破解策略**：先跑字典，未命中再逐级掩码（4 位数字 → 8 位数字 → 字母 → 全字符）
- **手动暴力破解**：自动策略没命中时，可按「字符集 + 长度」自行发起穷举。
  开始前先算出**组合空间**与**预计耗时**（基于本机实测速度），可选限时或不限时，
  跑起来后随时能取消 —— 不会让用户在不知情的情况下把电脑押上去
- **实时进度**：进度条、速度、ETA、已测/总数，并显示当前策略明细
  （如「掩码 3/11：?d?d?d?d?d（10 万 种组合，预计 2 分）」）
- **手机远程**：Android 端可通过局域网把文件发给 PC 端破解，实时查看进度；
  手机端也能对失败任务发起暴力破解（只传参数，哈希留在 PC）
- **MIFARE 卡片分析器**：拖入 Flipper / Proxmark 的门禁卡转储，直接讲明白
  「这是什么卡、哪些密钥已知、哪些扇区读不出来」；能生成 Proxmark/Flipper
  通用的密钥字典，还能导入 mfkey32 nonce 日志**纯离线算出未知密钥**
  （纯本地计算，不占 GPU、不用连 PC，手机上单机可用）

## 支持的文件类型

所有 hashcat 可识别的格式都内置在注册表里——拖进来就自动分流。

| 分类 | 格式 | 提取工具 | hashcat 模式 |
|---|---|---|---|
| 压缩包 | ZIP（ZipCrypto） | zip2john.py | 17200 / 17210 / 17220 / 17225 |
| 压缩包 | ZIP（WinZip AES） | zip2john.py | 13600 |
| 压缩包 | RAR3 / RAR5 | （需用 rar2john） | 12500 / 13000 |
| 压缩包 | 7-Zip | （需用 7z2john） | 11600 |
| 压缩包 | AES Crypt | （需用 aescrypt2hashcat） | 22400 |
| 文档 | PDF | pdf2john.py | 10400 / 10500 / 10600 / 10700 |
| 文档 | Office 2007+ | office2john.py | 9400 / 9500 / 9600 |
| 文档 | Office 97-2003 | office2john.py | 9700 / 9800 |
| 文档 | OpenDocument (LibreOffice) | （需用 libreoffice2john） | 18400 |
| 文档 | Apple iWork | （需用 iwork2john） | 23300 |
| 无线网络 | WiFi 握手包（.cap/.pcap/.pcapng） | hcxpcapngtool | 22000 |
| 无线网络 | hccapx 二进制 | （建议改用 .cap 抓包） | 2500 |
| 密钥与凭据 | SSH 私钥（RSA/ECDSA/OpenSSH） | （需用 ssh2john） | 22911 / 22921 / 22931 / 22941 / 22951 |
| 密钥与凭据 | PGP / GPG 私钥 | （需用 gpg2john） | 17010 / 17020 / 17030 |
| 密钥与凭据 | KeePass KDBX | （需用 keepass2john） | 13400 / 34300 |
| 密钥与凭据 | 1Password / LastPass / Bitwarden / Apple 钥匙串 | 各专用工具 | 6800 / 8200 / 23100 / 23400 |
| 卷与磁盘加密 | BitLocker | bitlocker2hashcat.py | 22100 |
| 卷与磁盘加密 | LUKS v1/v2 | luks2hashcat.py | 29511–29543 / 34100 |
| 卷与磁盘加密 | TrueCrypt | truecrypt2hashcat.py | 29311 / 29321 / 29331 |
| 卷与磁盘加密 | VeraCrypt | veracrypt2hashcat.py | 29411 / 29421 / 29431 / 29451 / 29471 |
| 卷与磁盘加密 | VirtualBox 加密磁盘 | virtualbox2hashcat.py | 27500 / 27600 |
| 卷与磁盘加密 | VMware VMX 加密 | vmwarevmx2hashcat.py | 27400 |
| 卷与磁盘加密 | Veeam VBK | veeamvbk2hashcat.py | 31200 |
| 卷与磁盘加密 | EncFS | （需用 encfs2john） | 29941 |
| 卷与磁盘加密 | APFS / FileVault 2 | （需用 apfs2hashcat） | 18300 / 16700 |
| 卷与磁盘加密 | Apple DMG 加密 | （需用 dmg2john） | 16700 |
| 应用与浏览器数据 | Firefox key3/key4.db | （需用 mozilla2hashcat） | 26000 / 26100 |
| 应用与浏览器数据 | MetaMask 保险库 | metamask2hashcat.py | 26600 / 26610 |
| 应用与浏览器数据 | Exodus 种子文件 | exodus2hashcat.py | 28200 |
| 应用与浏览器数据 | Windows 账户缓存 (CacheData) | cachedata2hashcat.py | 31500 |
| 加密货币钱包 | Bitcoin Core wallet.dat | （需用 bitcoin2john） | 11300 |
| 加密货币钱包 | Ethereum keystore | （需用 ethereum2john） | 15600 / 15700 |
| 加密货币钱包 | Monero / Electrum | （需用专用工具） | 16600 / 21700 / 21800 |
| Windows 系统 | SAM / SYSTEM / SECURITY | （需用 secretsdump.py） | 1000 |
| Windows 系统 | NTDS.dit（域控） | （需用 secretsdump.py） | 1000 |
| 移动端 | Android Backup (.ab) | （需用 androidbackup2john） | 18900 |
| Java | Apache Shiro | shiro1-to-hashcat.py | 12150 |
| Java | Kremlin Encrypt | kremlin2hashcat.py | 32700 |
| MIFARE 卡片 | Flipper/Proxmark 转储（.nfc/.shd/.eml/.bin） | 内置解析 | 走「卡片分析器」 |
| MIFARE 卡片 | mfkey32 nonce 日志 | Crypto1 状态恢复 | 走「卡片分析器」 |
| 文本 | 任意哈希（32 hex / bcrypt / $pkzip$ / WPA 等） | 自动 `--identify` | 自动 |

## MIFARE 卡片分析器

门禁卡（MIFARE Classic）的转储分析和密钥恢复。入口在主界面「MIFARE 卡片分析器」，
也可以直接把转储文件拖进拖拽区——会自动分流过去。

支持三种转储载体：

| 载体 | 来源 | 说明 |
|---|---|---|
| `.nfc` / `.shd` | Flipper Zero | 文本格式，读不到的字节写作 `??` |
| `.eml` | Proxmark3 / mfoc | 每行 16 字节十六进制 |
| `.bin` / `.mfd` | 各种读卡器 | 裸二进制，320 / 1024 / 4096 字节 |

**转储分析**输出：UID / ATQA / SAK / 卡型、逐扇区的 Key A / Key B / 访问位、
哪些密钥已知、哪些扇区读不出数据、以及下一步该敲什么命令。一键导出 4 个文件
（密钥字典 + 密钥清单 + 分析报告 + 下一步），字典格式可直接丢进
Proxmark3 的 `mf_classic_dict.nfc` 或 Flipper 的 `/ext/nfc/assets/`。

**密钥恢复**走 mfkey32：导入 Flipper 的 `mfkey32.log`（或 mfkey_extract /
pm3 导出的同类文本），用两次认证会话的 nonce 离线反推 48 位密钥。
这条路的搜索空间是可枚举的，所以能真的算出来，实测一次约 0.8 秒。

### 两个必须说清楚的物理限制

1. **转储文件本身无法离线试密钥。** 里面只有认证后的明文，既没有密文也没有
   nonce —— 猜错了没有任何东西能告诉你错了。所以「纯 dump 离线爆破」不成立，
   不要被「爆破」这个词误导。
2. **Key A 在卡片设计上永远读不出来。** dump 里出现 `??` 是正常现象，不是文件
   损坏。要拿到它只有两条路：实体卡 + nested/hardnested 攻击（需要已知任意一个
   密钥），或者 mfkey32（需要 nonce 日志）。

### 访问位的一个坑：`FF 07 80` 下 Key B 已知但**不能用来认证**

出厂配置（transport configuration，尾块 `FF 07 80`）下 Key B 是可读的，
所以转储里能看到它。但 NXP 规定这种配置下 Key B **不能用于认证**——认证后卡片
会拒绝后续访问。本工具会把它标成「已知但不可认证」，而不是当成一把好用的钥匙，
避免出现「密钥明明有、读卡却失败」的困惑。

### 密钥候选表怎么来的

转储里已知的密钥 + 一小张常见默认密钥表（出厂值 `FFFFFFFFFFFF`、NXP 演示值
`A0A1A2A3A4A5` 等）。它的用途不是「撞开所有扇区」，而是**撞出第一个突破点**：
MIFARE Classic 只要知道同一张卡上任意一个扇区密钥，就能用 nested 攻击在几秒内
展开全卡。

## 产物

```
dist\HashCrack\         便携目录（整个拷走即可用，451 MB）
dist\HashCrack.zip      压缩分发包
dist\HashCrack.apk      Android 安装包（52 MB，可选，用于手机遥控 PC 破解）
```

## 构建

> ⚠️ **构建环境注意**：本项目所在路径含中文（`E:\临时文件\...`），
> Flutter 的 Windows 构建在中文路径下会因编码问题失败（GLSL 着色器
> 包含路径、app.dill 读取都会出错）。构建前请把工程复制到纯英文路径，
> 并通过纯英文路径访问 Flutter SDK，详见下方「构建踩坑记录」。

```powershell
# 完整构建（编译 + 组装 + 压缩）
python scripts/build_portable.py --zip

# 只打包（已编译过）
python scripts/build_portable.py --skip-build
```

## 目录结构

```
hashcat_gui/
├── lib/
│   ├── services/
│   │   ├── app_paths.dart         # 便携化路径解析（无绝对路径依赖的核心）
│   │   ├── hashcat_service.dart   # hashcat 进程管理、输出解析、环境自检
│   │   ├── file_identifier.dart   # magic bytes 文件类型识别
│   │   ├── extractor_service.dart # 哈希提取（内置 Python 优先）
│   │   ├── task_orchestrator.dart # 全自动流水线编排
│   │   ├── dict_service.dart      # 字典管理（自动扫描 runtime\dicts）
│   │   ├── server_service.dart    # PC 端 HTTP 服务（供手机连接）
│   │   ├── remote_client.dart     # 手机端 HTTP 客户端
│   │   └── mifare_service.dart    # MIFARE 转储分析 / nonce 日志解析 / 密钥恢复
│   ├── models/
│   │   ├── mifare.dart            # MIFARE 转储解析与访问位解码（按字节记未知）
│   │   ├── mifare_keys.dart       # 密钥候选生成与字典导出
│   │   └── brute_force.dart       # 暴力破解配置与组合空间估算
│   ├── utils/crypto1.dart         # Crypto1 / Crapto1 移植（mfkey32 离线恢复）
│   ├── state/app_state.dart       # 全局状态 (Provider)
│   ├── screens/                   # 主界面 / 结果 / 设置 / MIFARE 分析器
│   └── widgets/                   # 拖拽区 / 任务卡片 / 进度条
│
├── runtime/                       # ★ 运行时依赖，随包分发
│   ├── hashcat/                   # hashcat 7.1.2 内核（含全部哈希模式模块）
│   ├── python/                    # 便携 Python 3.12（跑提取脚本，无需系统安装）
│   ├── tools/                     # zip2john / pdf2john / office2john
│   │   └── hcxtools/              # hcxpcapngtool.exe 及其 DLL
│   └── dicts/                     # 密码字典（用户可直接往这里加 .txt）
│
├── scripts/
│   ├── build_portable.py          # 编译 + 组装便携包 + 压缩
│   └── fix_plugin_links.py        # 修复 Windows 插件链接（无开发者模式时必需）
├── android/  windows/             # 平台文件
└── flutter_windows_3.47.3-stable/ # 内置 Flutter SDK
```

## 便携化设计

软件能在任意电脑运行，靠三件事：

1. **统一运行时目录**：hashcat、Python、提取工具、字典全部放在可执行文件同级的 `runtime/` 下
2. **相对路径解析**：`lib/services/app_paths.dart` 从可执行文件位置出发逐级向上找 `runtime/`，兼容发布目录和开发调试目录，全程不用绝对路径
3. **内置 Python 运行时**：提取脚本由 `runtime\python\python.exe` 执行，目标机器不需要装 Python

工作目录也放在 `runtime\work` 而不是 `%APPDATA%`，整包可以随时搬走或删除，不在系统里留残渣。

想自定义部署位置，可设环境变量 `HASHCRACK_RUNTIME` 指向 runtime 目录。

## 使用流程

### PC 端
1. 双击 `HashCrack.exe`
2. 拖入加密文件（或点「选择文件」）
3. 自动识别 → 提取 → 破解 → 结果卡片显示明文，可一键复制

### 自动策略没命中怎么办
自动流程是「字典 → 掩码」，都是**有限时**的尝试。如果结果是
「所有策略均未命中」，说明这个范围内没找到，此时可以：

1. **换更大的字典** —— 把 `.txt` 丢进 `runtime\dicts\`
2. **放宽自动掩码的时限** —— 设置 → 自动策略时长 →
   改成 10 分钟 / 30 分钟 / 2 小时 / 不限时。
   WPA 这类慢哈希（几万 H/s）在默认的 3 分钟里连 8 位数字都跑不完
3. **手动暴力破解** —— 失败卡片上的「暴力破解」按钮：
   - 面板会先按你的字符集与长度算出**组合空间**和**预计耗时**，
     耗时超过 1 小时会转黄、超过 1 天转红并给出警告
   - 面板里还有「各长度明细」，能看出从几位开始试最划算
   - 运行方式选「不限时」就可以让它自己在后台跑到穷尽或命中，随时可取消
   - WiFi 握手包会默认推荐「8 位纯数字」等符合 WPA 密码习惯的方案

> 提示：暴力破解是在赌一个巨大的搜索空间。RTX 4060 笔记本跑 ZIP（17200）约
> 1.4 亿次/秒，8 位纯数字 1 秒多就完了；但 WPA（22000）只有几十万次/秒，
> 8 位纯数字要跑十几分钟，加上字母就是几百年。**先看预计耗时再决定**。

### 手机端
1. PC 端启动软件，主界面会显示局域网地址
2. 手机端打开 App → 设置 → 填入 PC 的 IP 和端口（默认 8787）→ 测试连接
3. 选文件上传，PC 端自动处理，手机端实时看进度和结果

### 门禁卡（MIFARE）
不走 hashcat，也不需要连 PC —— 在 PC 或手机上点主界面的
「MIFARE 卡片分析器」即可，或直接把转储文件拖进窗口。
流程与限制见上文 [MIFARE 卡片分析器](#mifare-卡片分析器)。

## 常见问题

**Q: 提示「未找到可用的 OpenCL 运行环境」？**
A: hashcat 依赖显卡的 OpenCL 驱动做计算：
1. 到 NVIDIA / AMD / Intel 官网装最新版显卡驱动
2. 笔记本确认用独立显卡运行本软件
3. 虚拟机通常无法提供 OpenCL，需在物理机上运行

可在「设置 → 运行环境自检 → 检测显卡计算后端」查看当前机器的可用设备。

**Q: 想用自己的字典？**
A: 把 `.txt` 字典直接放进 `runtime\dicts\` 目录，重启软件自动加载。

**Q: 破解速度慢？**
A: 速度取决于显卡性能。参考值：RTX 4060 笔记本版跑 ZIP 约 60 万次/秒。

**Q: 想换新版 hashcat？**
A: 替换 `runtime\hashcat\` 目录内容即可，或在「设置」里指定其他路径。

## 测试

测试要在英文构建目录下跑，并显式指定 runtime（否则 `AppPaths` 找不到
runtime，候选密码校验会被跳过）：

```bash
cd C:\hashcat_build
HASHCRACK_RUNTIME='C:\portable_test\HashCrack\runtime' \
  flutter test
```

| 测试文件 | 覆盖内容 |
|---|---|
| `test/brute_force_test.dart` | 掩码组合空间 / 长度区间 / 参数拼装 / 单位格式化的纯逻辑；**端到端**：真 ZipCrypto 样本穷举破出，以及组合空间与 hashcat 上报 total 的逐位一致性 |
| `test/brute_force_sheet_test.dart` | 暴力破解面板：推荐预设、组合空间与预计耗时渲染、空间过大告警、返回配置正确 |
| `test/extractor_wifi_test.dart` | WiFi 22000 / 4.8GB ZipCrypto 提取链路回归 |
| `test/status_json_test.dart` | hashcat 状态 JSON 的流式抠取 |
| `test/crypto1_test.dart` | Crypto1 移植正确性：公开 mfkey32 向量、6 组密钥往返恢复、换随机数复现、**篡改 nonce 必须恢复失败**（不允许返回错密钥） |
| `test/mifare_test.dart` | 转储解析（Flipper / 裸二进制 / 多扇区缺密钥）、按字节记录的未知掩码、访问位解码、密钥候选与字典格式、nonce 日志多格式解析、**文件识别分流**（nonce 日志不能被误判成哈希文件） |
| `test/mifare_screen_test.dart` | MIFARE 分析器界面：双标签页渲染、手机端不显示拖拽提示、带 nonce 路径进入时自动切页、解析失败展示错误而非白屏 |

造密码已知的 ZipCrypto 测试样本（Bandizip 生成的才是真 ZipCrypto，不是 AES）：

```bash
"C:\Program Files\Bandizip\bz.exe" c -y -fmt:zip -l:5 -p:48217 out.zip payload.txt
```

## 构建踩坑记录

这一版把好几个环境坑都填了，记录在此避免重复踩：

1. **Flutter SDK 产物不全**：`bin/cache/artifacts/engine/common/flutter_patched_sdk*` 是空的，
   导致编译器连 `dart:async`、`dart:core` 都不认识，报一堆「Type 'X' not found」。
   解决：`flutter precache --force --windows --universal`
2. **中文路径**：含中文的工程路径 / SDK 路径会让 MSBuild 的 GLSL 编译和 app.dill 读取失败
   （日志里路径会变成乱码）。解决：通过纯英文的 junction 访问，
   如 `E:\flutter_sdk` → 真实 SDK 目录
   > 注意：**工程目录本身不能只用 junction**。MSBuild 会把 junction 展开成真实路径再传给
   > Dart，如果真实路径含中文，写 `app.dill` 时仍会被 GBK 乱码成 `E:\锟斤拷时...`，
   > 报 `Unable to read file ... app.dill`。工程必须放在**真实的英文目录**里
   > （如 `C:\hashcat_build`），每次改动先 `cp -r lib/. /c/hashcat_build/lib/` 同步源码。
3. **插件符号链接**：未开启 Windows 开发者模式时，Flutter 建符号链接会失败并残留空目录，
   下次构建报 errno 183。解决：`python scripts/fix_plugin_links.py` 建 NTFS junction
4. **objective_c 构建钩子**：`path_provider` → `path_provider_foundation` → `objective_c`
   带 build hook，在 Windows 上跑不起来。解决：改用 `AppPaths` 自解析工作目录，
   去掉 `path_provider` 依赖，钩子链随之消失
5. **file_picker 12.x API 变更**：`FilePicker.platform.pickFiles()` 已移除，
   改为静态方法 `FilePicker.pickFiles()` 且直接返回 `List<PlatformFile>`
6. **不要钉死 hashcat 设备号**：早期写死 `--backend-devices 1`，换机后设备编号不同会选错设备

## 已知修复的功能缺陷

- **AES 加密 ZIP 曾无法破解**：`zip2john.py` 的 `extract_aes_hash()` 算出了 payload 长度
  却没有输出实际数据段，hashcat 拿不到密文。已修复（正确输出 `$zip2$` 第 7 字段的加密数据）

- **ZipCrypto 加密 ZIP 曾无法破解（全模式 Exhausted）**：这是最隐蔽的一个坑。
  hashcat `$pkzip2$` 的 version 2 格式**必须有两个校验字段**：

  ```
  $pkzip2$<count>*<cs_size>*<data_type>*<magic_type>*
    [CL*UL*CR*OF*OX*]  <- 仅 data_type>1
    <CT>*<DL>*<CS_crc:04x>*<CS_ts:04x>*<data>*$/pkzip2$
  ```

  旧脚本只写到 `CS_crc` 就直接接密文，少了一个字段，导致**后面所有字段整体左移一位**，
  密文被当成校验值吃掉。hashcat 因此拿不到真实密文，任何密码都报 Exhausted，
  且不会报错（格式看起来"合法"）。修复后 4.8GB 的 ZipCrypto 安装包实测可破。
  校验值取 `CS_crc = crc32>>16`、`CS_ts = DOS 修改时间`，覆盖两种打包工具实现。

- **大 ZIP 提取会 OOM**：`zip2john.py` 原先用 `f.read()` 把整个文件读进内存，
  4.8GB 的包会直接撑爆内存。改用 `mmap` 按需分页，提取 4.8GB 包耗时 0.24 秒。

- **部分抓包 WiFi 提取失败**：`hcxpcapngtool` 对某些网卡导出的 radiotap pcap
  会只读到前几帧就报 `packet read error` 并拒绝输出（其实抓包里握手是完整的）。
  新增 `runtime/tools/pcap2hashcat.py` 作为兜底：纯 Python 解析 802.11 帧，
  支持 radiotap(127)/裸帧(105)/prism(119)，直接从 M1/M2/M3 还原出可用的 22000 哈希。
  提取链改为三级兜底：`hcxpcapngtool` → `pcap2hashcat.py` → `hcxpcaptool`。

- **WiFi 哈希生成有两个致命细节**（此前表现为"提取成功但任何密码都 Exhausted"）：
  1. 类型字段必须是 `WPA*02*`。`01` 在 22000 里表示 PMKID，hashcat 会把 MIC
     当成 PMKID 去比对，于是任何密码都不匹配，且不报错。
  2. **EAPOL 字段里的 MIC（偏移 81..96）必须清零**。内核
     (`OpenCL/m22000-pure.cl`) 直接对 EAPOL 字段的 `eapol_len` 字节做 HMAC-SHA1，
     不会自己跳过 MIC 字段。若保留真实 MIC，算出的 HMAC 与 keymic 永不相等。
  另外 PTK 需要 (ANonce, SNonce)，而 SNonce 只在 M2 的 Key Nonce 字段里，
  因此**不含 M2 的抓包无法恢复 PSK**。修复后实测可破出真实密码。

- **hashcat 需要以自身目录为工作目录**：`hashcat.exe` 从当前工作目录查找
  `./OpenCL/`，用绝对路径从别处调用会报 `./OpenCL/: No such file or directory`。

- **「所有策略均未命中」曾经是假结论**：自动策略里的每组掩码都被
  `--runtime=180` 硬砍 3 分钟，且整轮进程还有 30 分钟的硬超时。WPA 握手包
  (22000) 在普通机器上只有几万 H/s，3 分钟连 8 位数字的零头都跑不完就被截断，
  于是界面直接报「所有策略均未命中」——其实根本没跑完。现在：
  - 时限可配置（3 分钟 / 10 分钟 / 30 分钟 / 2 小时 / 不限时），不限时时解除进程硬超时
  - 阶段明细会显示组合空间与预计耗时
  - 被限时截断时会明确说「限时 N 秒已用满，组合空间未跑完」，
    不再谎称「已遍历全部组合」
  - 新增手动暴力破解入口，由用户看过组合空间与预计耗时后决定要不要跑

- **`hashcat -a 3` 的位置参数顺序必须是 `<哈希文件> <掩码>`**：写反了 hashcat
  会把哈希文件当成「掩码文件」，报
  `Using --custom-charsetX with mask files is misleading` 然后退出。
  它不会说"掩码顺序错了"，对用户表现为「点了没反应」，很难排查。
  （源码依据：`src/user_options.c` 中以 `hc_path_exist(hc_workv[0])` 判定 maskfile。）

- **多字符集必须用 `-1` 自定义字符集**：`-1 '?l?d' ?1?1?1?1` 表示"每个位置 36 选 1"，
  而 `?l?d?l?d` 是"小写、数字、小写、数字"的**交替掩码**，语义完全不同。

- **关闭应用后 hashcat 不退出，显卡一直满载**：用户报的「破解时关掉应用，显卡占用
  还是满的，半天退不出来」。原因是 Dart 侧虽然会在取消任务时 `kill` 子进程，但
  **直接关窗时 Dart 隔离区先被销毁，来不及执行清理**，`Process.start` 出来的
  `hashcat.exe` 是独立的 Windows 进程，不会跟着走。
  修复：在 `windows/runner/main.cpp` 里用 **Job Object** 兜底 ——
  `CreateJobObjectW` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，把主进程自己放进
  这个 job，则它派生的每个子进程都自动加入同一 job（Dart 的 `CreateProcess`
  不带 `CREATE_BREAKAWAY_FROM_JOB`）。主进程一退出、系统关闭 job 句柄，job 内
  所有进程被强制终止。**即使进程被任务管理器强杀也生效**，实测强杀后
  `hashcat.exe` 立即消失。文件句柄故意不关闭（`KILL_ON_JOB_CLOSE` 的语义是
  「最后一个句柄关闭时终止」）。

- **中文注释导致 Windows 构建失败**：MSVC 默认按系统代码页（简体中文 Windows 是
  936/GBK）解读源文件，遇到 UTF-8 的中文注释报 `C4819`，而项目开了 `/WX`
  （警告即错误），于是直接编译失败。已在 `windows/CMakeLists.txt` 的
  `APPLY_STANDARD_SETTINGS` 里加 `/utf-8`。

- **ATQA 少了前导的 `00`**：`ATQA: 00 04` 被逐字节解析后只取了单字节，界面上显示成
  `04`。修复：`atqa = (v[0] << 8) | v[1]`，显示为 `00 04`。
  （同类问题：MIFARE 转储解析里凡是「多字节字段」，都不能只取首字节。）

- **一个字节读不到就把整个块判成未知**：Flipper 会把读不到的字节写成 `??`。扇区
  14 的尾块里只有 Key A（前 6 字节）是 `??`，访问位和 Key B 都是完整的 —— 但
  早期实现只要发现 `??` 就把整块置为未知，导致**已知的 Key B 和访问位一起丢失**，
  报告误称「扇区 14 完全未知」。修复：按**字节**记录未知掩码
  （`MifareBlock.unknown`），`slice(start, end)` 按需返回已知段。现在能正确说出
  「Key A 未知，但 Key B = FFFFFFFFFFFF、访问位 FF 07 80（transport config，
  可读但不可用于认证），该扇区数据读不出来」。

## 技术栈

- Flutter 3.47.3 / Dart 3.13
- hashcat 7.1.2（内核）
- Python 3.12 便携版（提取脚本运行时）
- hcxtools 7.1.2（WiFi 握手包解析，主路径）
- pcap2hashcat.py（内置 802.11 解析兜底，hcxtools 读不了的抓包走这里）
- shelf（PC 端 HTTP 服务）、provider（状态管理）、desktop_drop（拖拽）
- Crypto1 / Crapto1（MIFARE 流密码，从 Proxmark3 的 crapto1.c 移植到 Dart，GPLv3）

## 声明

本项目仅用于恢复自己遗忘的密码、授权的安全测试与教学用途。请勿用于破解他人文件。
