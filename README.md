# idat-mcp

基于 [IDA Pro](https://hex-rays.com/ida-pro/) 的无头 MCP 服务器，通过 **HTTP (Streamable HTTP)** 暴露二进制分析能力，供 Cursor、Claude 等 MCP 客户端调用。

底层使用 IDA 9+ 的 **idalib**（与 `idat` 文本模式相同的分析引擎）。

## 要求

- IDA Pro 9+（含有效许可证；反编译需要 Hex-Rays）
- Python 3.11+
- Linux / macOS / Windows

## 安装（只需一次）

```bash
cd idat-mcp
python3 -m venv .venv
source .venv/bin/activate

# 1. 升级 pip
pip install -U pip

# 2. 以可编辑模式安装当前项目（这会自动安装依赖，并注册 idat-mcp 命令行工具）
pip install -e .

# 3. 安装 idalib 的 Python 绑定包（路径换成你的 IDA 安装路径中相应的 whl 文件）
pip install /path/to/ida/idalib/python/idapro-*.whl

# 4. 激活 idalib（只需一次，路径换成你的 IDA 安装目录）
python /path/to/ida/idalib/python/py-activate-idalib.py -d /path/to/ida
```

或使用安装脚本（一键自动创建虚拟环境、安装依赖与 idalib，并激活）：

```bash
# 直接指定 IDA 路径作为参数
bash scripts/setup.sh /path/to/ida

# 或者通过环境变量指定 IDA 路径
IDADIR=/path/to/ida bash scripts/setup.sh
```

## 启动 HTTP 服务

```bash
python server.py --ida-dir /path/to/ida
```

常用参数：

```bash
python server.py --ida-dir /path/to/ida --host 0.0.0.0 --port 8745
python server.py -d /path/to/ida --stateless
```

也可使用已安装的入口（同样必须传 `--ida-dir`）：

```bash
idat-mcp --ida-dir /path/to/ida --host 127.0.0.1 --port 8745
```

服务地址：`http://127.0.0.1:8745/mcp`

## Cursor / MCP 客户端配置

在 Cursor 的 MCP 设置中添加：

```json
{
  "mcpServers": {
    "idat-mcp": {
      "url": "http://127.0.0.1:8745/mcp"
    }
  }
}
```

或使用 CLI：

```bash
claude mcp add --transport http idat-mcp http://127.0.0.1:8745/mcp
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ida-dir` / `-d` | *(必填)* | IDA 安装目录 |
| `--host` | `127.0.0.1` | HTTP 绑定地址 |
| `--port` | `8745` | HTTP 端口 |
| `--max-workers` | 无限制 | 同时打开的数据库数量上限 |
| `--stateless` | `false` | 无 session 的 HTTP 模式 |
| `--allowed-hosts` | *(空)* | 远程访问 Host 白名单，如 `172.29.64.1:*` |

## 远程访问（WSL / LAN）

```bash
python server.py --ida-dir /path/to/ida --host 0.0.0.0 --port 8745
```

Cursor 配置（Windows 访问 WSL 内服务）：

```json
{
  "mcpServers": {
    "idat-mcp": {
      "url": "http://172.29.64.1:8745/mcp"
    }
  }
}
```

将 `172.29.64.1` 替换为你的 WSL IP（`hostname -I`）。

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
