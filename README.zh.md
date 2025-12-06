
# Hyper_rw

本文档介绍基于 [noahware/hyper-reV](https://github.com/noahware/hyper-reV)
 的虚拟内存访问类 **GuestMemory**，以及用于定位目标进程 CR3、EPROCESS、PEB、模块基址的四个内核工具函数。

 ### 此项目依赖特定的Windows版本(Windows11 25H2,如果版本不匹配会造成此项目无法运行，请修改GetM中的Offsets &PsActiveProcessHead offset:0xF05790 in Hyper_rw.cpp ) 。

---

## 1. 核心工具函数

这些函数依赖 `PsActiveProcessHead`，用于从内核侧定位进程的关键结构。

### GetProcessCr3
**参数**：`target_pid`, `ps_active_process_head`  
**返回**：CR3（DirectoryTableBase）  
遍历 ActiveProcessLinks，根据 PID 返回该进程的页表基址。

### FindProcessEProcessBase
**参数**：同上  
**返回**：EPROCESS 内核虚址  
适合需要访问 Token、HandleTable 等字段时使用。

### FindPebByCr3_Raw
**参数**：`target_cr3`, `ps_active_process_head`  
**返回**：PEB 用户层虚址  
通过 CR3 反查 EPROCESS，再读取 Peb 字段；不依赖 PID。

### GetModuleBase_Raw
**参数**：`target_cr3`, `peb_address`, `module_name`  
**返回**：DllBase  
遍历 PEB 的 Ldr 模块链表，查目标 DLL。

---

## 2. GuestMemory

GuestMemory 封装 VA→PA 转换、跨页处理，是用户态访问目标进程虚拟内存的主要接口。

### 构造方式
```cpp
GuestMemory mem( target_cr3);  // 绑定页表
```

### 2. ReadValue / WriteValue
```cpp
int hp = 0;
mem.ReadValue<int>(0x7FF70010, hp);
```

### 3. 调用流程概述

1. 获取 PsActiveProcessHead

2. 获取目标 CR3

3. 初始化 GuestMemory

4. 查找 PEB

5. 查找目标 DLL

6. 使用 GuestMemory 读写目标地址


# BSD 2-Clause License (Clear Attribution Required)

Copyright (c) [2025], [wz5200]  
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, **are permitted provided that the following conditions are met**:

1. **Source code redistributions must retain the above copyright notice, this list of conditions, and the following disclaimer.**
2. **Binary redistributions must reproduce the above copyright notice, this list of conditions, and the following disclaimer in the documentation and/or other materials provided with the distribution.**
3. **All redistributions must clearly attribute the original author ([wz5200]) in any public or private use of this software.**
