### cookie /GS 保护机制和绕过

所有这些漏洞利用的成功（无论是基于直接 ret 覆盖还是异常处理程序结构覆盖）都基于必须找到可靠的返回地址或 pop/pop/ret 地址，使应用程序跳转到您的 shellcode ，在所有这些情况下，我们都能在操作系统 dll 或应用程序 dll 中找到或多或少可靠的地址。即使在重新启动后，此地址也保持不变，从而使漏洞利用程序可靠地工作。

幸运的是，对于数以亿计的 Windows 最终用户来说，Windows 操作系统中内置了许多保护机制。

- Stack cookies (/GS Switch cookie)
-  Safeseh (/Safeseh 编译器选项)
- Data Execution Prevention (DEP) (基于软硬件)
- Address Space Layout Randomization (ASLR)

#### 堆栈 cookie /GS 保护

/GS 是一个编译器选项，它将向函数的开始和结尾代码添加一些代码，以防止典型的基于堆栈的（字符串缓冲区）溢出。

当应用程序启动时，会计算程序范围的 master cookie（4 字节（dword），无符号整数）（伪随机数）并保存在加载模块的 .data 部分中。在函数开始处，这个程序范围的 master cookie 被复制到堆栈中，就在保存的 EBP 和 EIP 之前。 （在局部变量和返回地址之间）

```
[buffer][cookie][saved EBP][saved EIP]
```

在结尾处，此 cookie 再次与程序范围的 master cookie 进行比较。如果不同，则断定发生了损坏，并终止程序。

为了最小化额外代码行对性能的影响，编译器只在函数包含 string buffers 或者使用 _alloca 在栈上分配内存的时候才会启用 stack cookie。而且，保护只在 buffer 包含 5 个或更多 bytes 的时候才会启动。

在一个典型的栈溢出中，攻击尝试使用你的数据覆盖 EIP，但是在你覆盖 EIP 之前，cookie 也会被覆盖，是漏洞变得无效（但是它可能导致 DOS），结尾的函数会发现 cookie 已经被改变了，然后程序退出。

```
[buffer][cookie][saved EBP][saved EIP]
[AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
         ^
         |
```

/GS 的第二个重要保护机制是变量重排。为了避免攻击者覆写函数的局部变量或者参数，编译器将重新排列栈帧的布局，会将字符串缓冲区放在比所有其他变量更高的地址。所以当字符串缓冲区溢出时，它不能覆盖任何其他局部变量。

#### cookie /GS 绕过方法

避免基于堆栈的溢出保护机制的最简单方法，需要您检索/猜测/计算 cookie 的值（这样你就可以在缓冲区中用的相同的 cookie 值覆盖原来的cookie）。此 cookie 有时（很少）是静态值，但即使是静态值，它也可能包含错误字符，你可能无法使用该值。

David Litchfield 在 2003 年写了一篇关于如何使用其他技术绕过栈保护的论文，并不需要猜测 cookie。

David 说，如果覆盖的 cookie 与原始 cookie 不匹配，代码会检查是否有开发人员定义的异常处理程序（如果没有，操作系统异常处理程序将启动）。如果攻击者可以覆盖异常处理程序结构（下一个 SEH + 指向 SE 处理程序的指针），并在检查 cookie 之前触发异常，则可以执行基于栈的溢出（基于 SEH 的利用），尽管确实有栈 cookie。

毕竟，GS 最重要的限制之一是它不保护异常处理记录。那时，程序将需要完全依赖 SEH 保护机制（例如 SafeSEH 等）来处理这些场景，有一些方法可以克服这个 safeseh 问题。

在 2003 服务器（以及更高版本的 XP/Vista/7/... 版本）中，结构化异常已被修改，使得在较新的操作系统版本中更加难以利用。异常处理程序在加载配置目录中注册，并且在执行异常处理程序之前，会根据已注册处理程序列表检查其地址。我们将在本文后面讨论如何绕过它。

#### 使用异常处理程序绕过

因此，我们可以通过在检查 cookie 之前触发一个异常来破坏堆栈保护（或者我们可以尝试覆盖其他数据或那些易受攻击的函数的栈中参数，使它们在 cookie 检查之前引用），然后处理可能存在的 SEH 保护机制，如果有的话，当然，第二种技术只有在编写代码以实际引用此数据时才有效。您可以尝试通过在栈末尾之外写入来利用这一点。

```
[buffer][cookie][EH record][saved ebp][saved eip][arguments ]

overwrite - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - >
```

这种情况下的关键是你需要覆盖足够远，并且注册了一个用于程序的异常处理程序（然后覆盖它），如果你可以控制异常处理程序地址（在 Exception_Registration 结构中），那么你可以尝试使用位于已加载模块地址范围之外的地址覆盖指针（但无论如何都应该在内存中可用，例如属于 OS 的模块等）。较新版本的 Windows 操作系统中的大多数模块都已使用 /safeseh 编译，因此这将不再起作用。但是你仍然可以在一个 DLL 中找到没有 safeseh 的处理器。毕竟，栈上的 SEH 记录不受 GS 保护，您只需绕过 SafeSEH。

这个指针需要用 pop/pop/ret 指令覆盖，所以代码将跳到 next seh，在那里你可以做一个短跳转到shellcode。或者，如果你找不到属于程序的已加载模块的地址范围内的 pop/pop/ret 指令，你可以查看 ESP/EBP，找到从这些寄存器到 next seh 位置的偏移量，并寻找以下可以使用的地址。

- call dword ptr [esp+nn]
- call dword ptr [ebp+nn]
- jmp dword ptr [esp+nn]
- jmp dword ptr[ebp+nn]

其中 nn 是从寄存器到 next seh 位置的偏移量。寻找 pop/pop/ret 组合可能更容易，但它应该也能工作。

#### 代替栈和 .data 段的 cookie 绕过

绕过堆栈 cookie 保护的另一种技术是在模块的 .data 部分中替换原来的 cookie 值（这是可写的，否则应用程序将无法计算新的 cookie 并在运行时存储它）并将栈中的 cookie 替换为相同的值。只有当你有能力在任何位置写任何东西时，这种技术才有可能。 (4 byte 的任意写入）

```assembly
mov dword ptr[reg1], reg2
```

为了使这项技术生效，你显然需要能够控制 reg1 和 reg2 的内容。然后 reg1 应该包含要写入的内存位置，而 reg2 应该包含要在该地址写入的值。

#### 并不是所有缓冲区都被保护

当易受攻击的代码不包含字符串缓冲区（所以不会有栈 cookie）时，会出现另一个利用机会。这也适用于整数或指针数组。

```
[buffer][cookie][EH record][saved ebp][saved eip][arguments ]

```

示例：如果“参数”不包含指针或字符串缓冲区，那么您可以覆盖这些参数并利用函数不受 GS 保护的事实。

