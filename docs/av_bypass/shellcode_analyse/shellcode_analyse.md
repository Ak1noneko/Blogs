##### 翻译自 [这里](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html)，转发请标注原作者和译者

### 介绍

本教程适用于 x86 32 位 shellcode。 Windows shellcode 比 Linux 的 shellcode 更难编写，你马上就会知道为什么。首先，我们需要对 Windows 架构有一个基本的了解，如下图所示，请好好了解。分割线上方的所有内容都处于用户模式，下方的所有内容都处于内核模式。
![windows架构图](https://idafchev.github.io/images/windows_shellcode/windows_architecture.png)

与 Linux 不同的是，在 Windows 中，应用程序不能直接访问系统调用。相反，它们使用来自 Windows API (WinAPI) 的函数，这些函数在内部调用来自 Native API (NtAPI) 的函数，而后者又使用系统调用。Native API 函数未文档化，并且在<font color="#dd0000">ntdll</font>中实现，从上图可以看出，它是用户模式代码的最低抽象级别。

Windows API 的文档化函数在 kernel32.dll、advapi32.dll、gdi32.dll 等dll中。基本服务（如文件系统、进程、设备等）由<font color="#dd0000">kernel32.dll</font>提供。

因此，要为 Windows 编写 shellcode，我们需要使用 WinAPI 或 NtAPI 中的函数。但是我们应该怎么做？

<font color="#dd0000">ntdll.dll 和 kernel32.dll 非常重要，每个进程都会导入它们。
</font>

### 发现DLL基地址
### 发现函数地址
### 调用函数
### 写shellcode
### 测试shellcode

