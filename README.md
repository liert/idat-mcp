# idat-mcp

基于 [IDA Pro](https://hex-rays.com/ida-pro/) 的无头 MCP 服务器，通过 **HTTP (Streamable HTTP)** 暴露二进制分析能力，供 Cursor、Claude 等 MCP 客户端调用。

底层使用 IDA 9+ 的 **idalib**（与 `idat` 文本模式相同的分析引擎）。

## 要求

- IDA Pro 9+（含有效许可证；反编译需要 Hex-Rays）
- Python 3.11+
- Linux / macOS / Windows

## 安装

请根据使用场景在下面两种方式中**选择一种**，不要依次执行两套安装命令。

### 方式一：安装为 systemd 服务（Linux，推荐）

适合需要开机启动、后台常驻或长期提供 MCP 服务的场景。`setup.py` 会完成全部安装
步骤并注册服务，因此不需要再执行“方式二”。

普通用户推荐安装为用户级服务，无需 `sudo`：

```bash
python3 setup.py --user --ida-dir /path/to/ida
```

如果确实需要系统级服务，则改用以下命令；不要同时安装用户级和系统级服务：

```bash
sudo python3 setup.py --ida-dir /path/to/ida
```

默认监听 `127.0.0.1:8745`。如需修改，在首次安装或重新执行安装器时指定：

```bash
python3 setup.py --user --ida-dir /path/to/ida --host 0.0.0.0 --port 9000
```

安装器会自动创建 `.venv`、安装项目依赖与 idalib Python 绑定、激活 idalib，随后
启用并启动服务。未指定 `--ida-dir` 时会读取 `IDADIR` 环境变量。

重复运行安装器是安全的：已完成的步骤会跳过，配置变化时只重新执行对应步骤。
其他安装选项：

- `--dry-run`：只预览 systemd unit，不修改系统
- `--no-start`：安装并启用服务，但不立即启动
- `--force-reinstall`：忽略安装状态并完整重装依赖、重新激活 idalib

安装完成后无需手动运行 `server.py`。用户级服务可通过以下命令管理：

```bash
systemctl --user status idat-mcp
systemctl --user restart idat-mcp
systemctl --user stop idat-mcp
```

系统级服务去掉命令中的 `--user` 即可。

### 方式二：仅安装命令行程序（手动运行）

适合开发调试、不希望注册 systemd 服务，或者使用 macOS / Windows 的场景。完成后
需要自行启动服务器。选择此方式时不要运行 `setup.py`：

```bash
cd idat-mcp
python3 -m venv .venv
source .venv/bin/activate

# 1. 升级 pip
pip install -U pip

# 2. 以可编辑模式安装当前项目及依赖
pip install -e .

# 3. 安装 idalib 的 Python 绑定包（路径换成你的 IDA 安装路径中相应的 whl 文件）
pip install /path/to/ida/idalib/python/idapro-*.whl

# 4. 激活 idalib（只需一次，路径换成你的 IDA 安装目录）
python /path/to/ida/idalib/python/py-activate-idalib.py -d /path/to/ida
```

### 手动启动（仅方式二）

```bash
python server.py --ida-dir /path/to/ida
```

常用参数：

```bash
python server.py --ida-dir /path/to/ida --host 0.0.0.0 --port 8745
python server.py -d /path/to/ida --stateless
```

服务地址：`http://127.0.0.1:8745/mcp`

## MCP 客户端配置

```json
{
  "mcpServers": {
    "idat-mcp": {
      "url": "http://127.0.0.1:8745/mcp"
    }
  }
}
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ida-dir` / `-d` | *(必填)* | IDA 安装目录 |
| `--host` | `127.0.0.1` | HTTP 绑定地址 |
| `--port` | `8745` | HTTP 端口 |
| `--max-workers` | 无限制 | 同时打开的数据库数量上限 |
| `--debug` | `false` | 在 stderr 输出 MCP 工具调用参数、worker/op 层级、结果摘要及耗时 |
| `--stateless` | `false` | 无 session 的 HTTP 模式 |
| `--allowed-hosts` | *(空)* | 远程访问 Host 白名单，如 `172.29.64.1:*` |

## 远程访问（WSL / LAN）

如果采用“方式一”安装服务，请重新运行安装器更新监听地址：

```bash
python3 setup.py --user --ida-dir /path/to/ida --host 0.0.0.0 --port 8745
```

如果采用“方式二”手动安装，则在启动命令中指定监听地址：

```bash
python server.py --ida-dir /path/to/ida --host 0.0.0.0 --port 8745
```

## 多数据库并行分析

**支持。** 每个数据库在独立的 worker 进程中运行（各自加载一份 idalib），互不冲突。

```text
MCP Client
    ├── worker-1  →  /path/to/a.bin
    ├── worker-2  →  /path/to/b.bin
    └── worker-3  →  /path/to/c.bin
```

### 用法

```python
# 打开第一个（自动成为默认数据库）
ida_open_database("/path/to/a.bin")

# 打开第二个，第一个仍保留
ida_open_database("/path/to/b.bin")

# 查看已打开的数据库及当前默认项
ida_list_databases()

# 切换默认数据库
ida_select_database("/path/to/a.bin")

# 后续分析工具均针对默认数据库，无需指定 database
ida_list_functions(limit=10)
ida_decompile_function("main")

# 关闭默认数据库
ida_close_database()
```

规则：

- 每次 `ida_open_database` 成功后，新打开的数据库自动成为**默认数据库**
- 已打开的其他数据库会保留在独立 worker 中
- 多库并行时，用 `ida_select_database` 切换默认数据库
- 所有分析类工具始终针对**默认数据库**，无需传递 `database` 参数
- `ida_close_database` 省略参数时关闭当前默认数据库；关闭默认库后自动切换到剩余第一个

## 提供的 MCP 工具

### 数据库管理

| 工具 | 说明 |
|------|------|
| `ida_open_database` | 打开二进制文件并自动分析 |
| `ida_analyze_database` | 对当前默认数据库执行完整自动分析（适用于列表仅返回导入表等分析不完整的情况） |
| `ida_close_database` | 关闭数据库（默认关闭当前默认库） |
| `ida_list_databases` | 列出已打开的数据库（含 `is_default` 字段） |
| `ida_select_database` | 选择默认数据库 |
| `ida_get_database_info` | 获取数据库元信息 |
| `ida_list_segments` | 列出内存段 |

### 函数分析

| 工具 | 说明 |
|------|------|
| `ida_list_functions` | 列出 IDA 分析后的函数（默认排除导入/PLT） |
| `ida_get_function` | 查询单个函数 |
| `ida_decompile_function` | 反编译（需 Hex-Rays） |
| `ida_disassemble` | 反汇编（`size` 为字节数，支持 `64` 或 `"0x14"`） |
| `ida_get_function_callers` | 查询谁调用了该函数 |
| `ida_get_function_callees` | 查询该函数调用了谁 |
| `ida_get_function_cfg` | 获取函数控制流基本块 |
| `ida_rename_function` | 重命名函数 |

### 交叉引用与搜索

| 工具 | 说明 |
|------|------|
| `ida_get_xrefs_to` | 查询指向某地址的引用 |
| `ida_get_xrefs_from` | 查询从某地址发出的引用 |
| `ida_get_global_variable_xrefs` | 查询全局符号引用（含所在函数） |
| `ida_search_strings` | 搜索字符串 |
| `ida_search_bytes` | 搜索字节序列（支持 `??` 通配） |
| `ida_search_immediate` | 搜索立即数 |
| `ida_list_global_names` | 列出全局符号名 |

### 导入/导出

| 工具 | 说明 |
|------|------|
| `ida_list_imports` | 列出导入表 |
| `ida_list_exports` | 列出导出/入口点 |
| `ida_demangle` | C++ 符号 demangle |

### 类型与结构

| 工具 | 说明 |
|------|------|
| `ida_list_structs` | 列出本地结构体类型 |
| `ida_get_struct_members` | 查看结构体成员 |
| `ida_get_type_at_address` | 读取地址上的类型 |
| `ida_set_type_at_address` | 给数据/全局设置 C 类型 |
| `ida_apply_function_type` | 设置函数原型 |
| `ida_create_struct` | 用 C 声明创建/更新结构体 |
| `ida_add_struct_member` | 向结构体添加成员 |
| `ida_apply_struct_at_address` | 把结构体类型应用到地址 |
| `ida_rename_local_variable` | 重命名反编译局部变量（需 Hex-Rays） |
| `ida_set_local_variable_type` | 设置反编译局部变量类型（需 Hex-Rays） |

### 变量分析

| 工具 | 说明 |
|------|------|
| `ida_list_local_variables` | 列出函数反编译局部变量（需 Hex-Rays） |
| `ida_get_local_variable_xrefs` | 查找局部变量在伪代码中的使用点（需 Hex-Rays） |

### 高阶程序分析

| 工具 | 说明 |
|------|------|
| `ida_find_call_path` | 在调用图中搜索从起点函数到终点函数的路径（BFS 最短路径 + 备选路径，`max_depth` / `max_paths` 可调） |
| `ida_get_backward_slice` | 从 sink 地址对局部变量做 backward slice，返回影响该变量的伪代码语句（需 Hex-Rays） |
| `ida_resolve_indirect_calls` | 解析函数内间接调用（如 AArch64 `BLR`），推断可能 callee 并可 `add_cref` 补全控制流 |
| `ida_get_microcode` | 提取 Hex-Rays 微码（`mblock`/`minsn`、SSA IR、块后继边；需 Hex-Rays，适合 OLLVM 去混淆） |
| `ida_find_crypto_constants` | 扫描 AES/MD5/SHA/ChaCha20/CRC32 等密码学魔术常量，可选自动打 `[Crypto]` 注释 |

### 脚本执行

| 工具 | 说明 |
|------|------|
| `ida_exec_script` | 在当前 worker 中执行 IDAPython 脚本；可赋值 `result` 返回结果 |

### 标注与原始数据

| 工具 | 说明 |
|------|------|
| `ida_get_bytes` | 读取原始字节 |
| `ida_get_comment` | 读取注释 |
| `ida_set_comment` | 设置注释 |

## 典型工作流

1. 调用 `ida_open_database` 打开第一个二进制（自动成为默认库）
2. 继续 `ida_open_database` 打开更多二进制（之前的库仍保留）
3. 用 `ida_select_database` 切换当前工作库
4. 直接调用分析工具（针对默认库）
5. 用 `ida_find_call_path` / `ida_get_backward_slice` / `ida_resolve_indirect_calls` 做跨函数路径与切片分析
6. 完成后用 `ida_close_database` 关闭

## 架构

```
MCP Client (HTTP)
       │
       ▼
  idat-mcp (FastMCP + uvicorn)
       │  tools/          ← MCP 工具注册（按类别分文件）
       │  ops/            ← IDA 操作实现（按类别分文件）
       │
       ├── worker-1 (idapro)  ←→  数据库 A
       ├── worker-2 (idapro)  ←→  数据库 B
       └── worker-N ...
```

源码布局：

| 目录 | 说明 |
|------|------|
| `src/idat_mcp/tools/` | MCP 工具定义（`database.py`、`functions.py`、`analysis.py`、`types.py` 等） |
| `src/idat_mcp/ops/` | IDA 底层操作（与 tools 一一对应） |

## 许可证

MIT
