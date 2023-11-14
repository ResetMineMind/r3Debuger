#pragma once
#ifndef __DEBUGGER__
#define __DEBUGGER__
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "capstone/capstone.h"
// 在C/C++，分别填写包含目录 和 库目录
#pragma comment(lib, "capstone.lib") // 库目录下目前只有32位的反编译


// 格式化用户输入的命令结构体
typedef enum _CommandType {
	WRONG = 0,
	WRITE = 1, // 写内存  w
	READ = 2,   // 读内存  r
	SET = 3,   // 设置断点  set
	CLEAR = 4, // 清理断点  cls
	STEPIN = 5, // 单步  si
	STEPINM = 16, // 内存断点使用
	STEPOVER = 6,    // 步过  so
	LISTPROCESS = 7,  // 列出进程列表 lp
	RUN = 8,     // 一直运行知道遇到断点  run
	RMBREAKPOINT = 9,  // 移除指定断点 rm
	LISTSFOTBREAKPOINT = 10, // 显示软件断点  lsb
	PRINTFREGS = 11,  // 打印寄存器的值  pr
	DISASMCODE = 12,  // 反汇编  disasm 

	SETHARD = 13,    // 硬件断点  setd 
	DEATTACH = 14,  // 退出调试   da
	SETMEM   = 15,  // 内存断点   setm
	EXIT     = 100,   // 结束调试  exit
} CommandType;

typedef struct user_command {
	// 命令类型
	CommandType type = WRONG;
	// 32位操作地址
	union u1 {
		DWORD addr;
		PCHAR name;
	} u1;
	// 读写
	union u2 {
		// 读数据的长度
		DWORD len;
		// 写数据的内容,一次仅允许写4字节
		DWORD wdata;
		// 哪个硬件寄存器
		DWORD drx;
		// 什么类型的内存断点
		DWORD mtype;
	} u2;
} UserCommand, *PUserCommand;

// EFLAGS结构体
typedef union _EFLAGS {
	DWORD eflags;
	struct {
		DWORD CF : 1;
		DWORD reverse1 : 1;
		DWORD PF : 1;
		DWORD reverse2 : 1;
		DWORD AF : 1;
		DWORD reverse3 : 1;
		DWORD ZF : 1;
		DWORD SF : 1;
		DWORD TF : 1;
		DWORD IF : 1;
		DWORD DF : 1;
		DWORD OF : 1;
		DWORD IOPL : 2;
		DWORD NT : 1;
		DWORD reverse4 : 1;
		DWORD RF : 1;
		DWORD VM : 1;
		DWORD AC : 1;
		DWORD VIF : 1;
		DWORD VIP : 1;
		DWORD ID : 1;
		DWORD reverse5 : 10;
	}u;
}EFLAGS, * PEFLAGS;

typedef struct _DBG_REG7
{
	/*
	// 局部断点(L0~3)与全局断点(G0~3)的标记位
	*/
	unsigned L0 : 1;  // 对Dr0保存的地址启用 局部断点
	unsigned G0 : 1;  // 对Dr0保存的地址启用 全局断点
	unsigned L1 : 1;  // 对Dr1保存的地址启用 局部断点
	unsigned G1 : 1;  // 对Dr1保存的地址启用 全局断点
	unsigned L2 : 1;  // 对Dr2保存的地址启用 局部断点
	unsigned G2 : 1;  // 对Dr2保存的地址启用 全局断点
	unsigned L3 : 1;  // 对Dr3保存的地址启用 局部断点
	unsigned G3 : 1;  // 对Dr3保存的地址启用 全局断点
	/*
	// 【以弃用】用于降低CPU频率，以方便准确检测断点异常
	*/
	unsigned LE : 1;
	unsigned GE : 1;
	/*
	// 保留字段
	*/
	unsigned Reserve1 : 3;
	/*
	// 保护调试寄存器标志位，如果此位为1，则有指令修改条是寄存器时会触发异常
	*/
	unsigned GD : 1;
	/*
	// 保留字段
	*/
	unsigned Reserve2 : 2;

	unsigned RW0 : 2;  // 设定Dr0指向地址的断点类型 
	unsigned LEN0 : 2;  // 设定Dr0指向地址的断点长度
	unsigned RW1 : 2;  // 设定Dr1指向地址的断点类型
	unsigned LEN1 : 2;  // 设定Dr1指向地址的断点长度
	unsigned RW2 : 2;  // 设定Dr2指向地址的断点类型
	unsigned LEN2 : 2;  // 设定Dr2指向地址的断点长度
	unsigned RW3 : 2;  // 设定Dr3指向地址的断点类型
	unsigned LEN3 : 2;  // 设定Dr3指向地址的断点长度
}DBG_REG7, * PDBG_REG7;

typedef enum _BreakPointType {
	SOFTWAREBP,
	HARDBP,
	MEMORYBP
}BreakPointType;

// 断点信息
typedef struct _BreakPointInfo {
	DWORD breakAddr;
	// int 3断点使用
	BYTE origin;
	LIST_ENTRY pointer;
	// 内存断点使用
	DWORD originalProtect;
	DWORD mtype;
	// 指定类型值
	BreakPointType bptype;
}BreakPointInfo, *PBreakPointInfo;
typedef struct _HardBreakPointInfo {
	DWORD drx;
	DWORD addr;
	// 多线程时需要考虑
	DWORD threadId;
}HardBreakPointInfo, *PHardBreakPointInfo;


// 创建进程，进行调试
int CreateForDebug(char* imagePath);
// 附加进程，进行调试

// 调试主循环
void EnterDebugLoop(PUserCommand command, const LPDEBUG_EVENT DebugEv);

// 设置软件断点
int SetSoftwareBreakPoint(PVOID addr, DWORD pid);

// 插入头节点
void insertFirstNode(LIST_ENTRY* node);

// 头插法
void insertListHeader(LIST_ENTRY* node, BreakPointType bptype);

// haven in
int inTheLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype);

// 查看断点
void ListSoftwareBreakPoint();

// 删除指定断点
void deleteBreakpoint(PVOID addr, DWORD pid);

// 清理所有软件断点
void CleanAllSoftwareBreakPoint(DWORD pid);

// 用户处理异常
int UserHandleException(PUserCommand command, const LPDEBUG_EVENT DebugEv);

// 设置硬件断点
int SetHardBreakPoint(PVOID addr, DWORD drx, PCONTEXT context, DWORD len, DWORD type, BOOL local);

// 查看所有的硬件断点
void ListHardBreakPoint(CONTEXT context);

// 删除指定的硬件断点
void RmHardBreakPoint(PCONTEXT pContext, DWORD num);

// 设置内存断点
void SetMemoryBreakPoint(PVOID addr, DWORD pid, DWORD type);

// 处理内存断点异常
int AutoHandleMemoryException(LPDEBUG_EVENT DebugEv, HANDLE hProcess, DWORD autoHandle);

// 此页面已有内存断点？
// haven in
int inThePageLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype);


#elif
#endif
