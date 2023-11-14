#include "debugger.h"
#include <psapi.h>

extern int FormatInput(PUserCommand command, char processArgs[256]);
extern void PrintMem(PULONG32 ptr, LONG32 len, LONG32 printColums, PULONG32 realptr);
extern DWORD ListProcess(const char* name);

extern void DisasmInput(csh handle, PUCHAR startBuffer, DWORD allSize, DWORD realptr);
extern DWORD DisasmJudge(csh handle, PUCHAR startBuffer);
extern void PrintRegs(DWORD dwThreadId);


// 调试指令处理
int DoCommand(PUserCommand command, const LPDEBUG_EVENT DebugEv);
// 反汇编用户指令对应操作，复用
void DisasmByUserCommand(HANDLE hProcess, PUserCommand command);
// 单步步入，复用
void StepInReuse(HANDLE hProcess, HANDLE hThread, CONTEXT context);
// 打印临时信息
void printTmpCodeInfo(HANDLE hProcess, CONTEXT context, const char* sign, int stepLen);
// 重新设置好断点
void recoverSoftBreakAgain(HANDLE hProcess, int startIndex);
// 临时恢复断点
void tmpRecoverSoftwareBreakPoint(PUserCommand command, HANDLE hProcess, DWORD startIndex);


// 全局断点数组
static LIST_ENTRY breakArray = { 0 };
// 初始化反汇编引擎
static csh cshHandle = NULL;
// 初始化是否继续调试的标志 
static int debugFlag = 1;

// 一次最多恢复512个软件断点；供于临时恢复断点之用
#define MAX_TMP_SOFT_BREAK 512
#define MAX_TMP_HARD_BREAK 4
#define MAX_TMP_MEME_BREAK 512
static PBreakPointInfo globalTmpSoftwareBreakpoint;
static int count = 0;

static PBreakPointInfo globalTmpMemoryBreakpoint;
static int mcount = 0;

// 临时下断点，永远之后临时下一个断点
static BreakPointInfo tmpUseSoftBreak;
// 临时恢复的局部硬件断点
static PHardBreakPointInfo globalTmpHardBreakPoint;
static int hardCount = 0;

// 当前是附加进程进行调试还是创建进程调试
static int attchOrCreate = 0;
// deattach
static int deAttachNow = 0;

// 内存断点，上一条命令是啥
static int lastCommand = 0;


int main() {
	// 创建调试进程
	int ret = CreateForDebug((char*)"D:\\tools\\Visual Studio\\projects\\easyDebugger\\Debug\\vim.exe");
	// int ret = DebugActiveProcess(ListProcess("vim2.exe"));
	attchOrCreate = 0;
	if (!ret) {
		printf("调试器退出, errorCode: %d\n", GetLastError());
		return 0;
	}
	// 初始化反汇编引擎
	cs_err errNo;
	if ((errNo = cs_open(CS_ARCH_X86, CS_MODE_32, &cshHandle)) != CS_ERR_OK) {
		printf("反汇编引擎加载失败, errorCode: 0x%x\n", errNo);
		return 0;
	}
	// 初始化断点临时存储空间
	globalTmpSoftwareBreakpoint = (PBreakPointInfo)malloc(sizeof(BreakPointInfo) * MAX_TMP_SOFT_BREAK);
	if (!globalTmpSoftwareBreakpoint) {
		printf("软件断点临时存储空间初始化失败\n");
		return 0;
	}
	memset(globalTmpSoftwareBreakpoint, 0, sizeof(BreakPointInfo) * MAX_TMP_SOFT_BREAK);
	// 初始化内存断点临时存储空间
	globalTmpMemoryBreakpoint = (PBreakPointInfo)malloc(sizeof(BreakPointInfo) * MAX_TMP_MEME_BREAK);
	if (!globalTmpMemoryBreakpoint) {
		printf("内存断点临时存储空间初始化失败\n");
		return 0;
	}
	memset(globalTmpMemoryBreakpoint, 0, sizeof(BreakPointInfo) * MAX_TMP_MEME_BREAK);

	globalTmpHardBreakPoint = (PHardBreakPointInfo)malloc(sizeof(HardBreakPointInfo) * MAX_TMP_HARD_BREAK);
	if (!globalTmpHardBreakPoint) {
		printf("硬件断点临时存储空间初始化失败\n");
		return 0;
	}
	memset(globalTmpHardBreakPoint, 0, sizeof(HardBreakPointInfo) * MAX_TMP_HARD_BREAK);
	// 初始化临时断点的空间
	memset(&tmpUseSoftBreak, 0, sizeof(BreakPointInfo));
	// 初始化用户命令空间
	PUserCommand command = (PUserCommand)malloc(sizeof(UserCommand));
	if (!command) {
		printf("用户命令空间初始化失败\n");
		return 0;
	}
	memset(command, 0, sizeof(UserCommand));	
	// 创建调试事件对象
	DEBUG_EVENT DebugEvent = { 0 };
	EnterDebugLoop(command, &DebugEvent);

	// 回收用户命令空间句柄
	free(command);
	// 回收反汇编引擎句柄
	cs_close(&cshHandle);
}

// 调试指令处理
int DoCommand(PUserCommand command, const LPDEBUG_EVENT DebugEv) {
	int retFlag = 1;
	DWORD pid = DebugEv->dwProcessId;
	DWORD tid = DebugEv->dwThreadId;
	// 临时恢复断点
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) printf("获取进程句柄失败，临时恢复断点、读写内存操作将失效\n\n");
	// 处理基本的线程上下文
	HANDLE hThread = NULL;
	hThread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
	CONTEXT context = { 0 };
	int stepLen = 0;
	// 内存断点与否
	DWORD memFlag = 0;
	if (!hThread) printf("获取线程上下文失败，设置线程上下文操作将失效\n\n");
	else {
		context.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hThread, &context);
		// 如果是软件断点，那么将会导致eip前进1位，继续执行前需要变回去。
		if (DebugEv->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			if (DebugEv->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
				stepLen = 1;
			else if (DebugEv->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
				memFlag = 1;
			// 打印下一条指令信息
			if (command->type == STEPIN || command->type == STEPOVER || command->type == RUN)
				printTmpCodeInfo(hProcess, context, "setp", stepLen);
		}
		// 恢复临时取消的硬件断点
		for (int i = 0; i < MAX_TMP_HARD_BREAK; i++) {
			DWORD dr7 = context.Dr7;
			// 暂时不考虑多线程
			if(globalTmpHardBreakPoint[i].addr)
				dr7 |= (DWORD)(1 << globalTmpHardBreakPoint[i].drx);
			memset(&globalTmpHardBreakPoint[i], 0, sizeof(HardBreakPointInfo));
			context.Dr7 = dr7;
		}
		SetThreadContext(hThread, &context);
	}
	
	// 根据命令分类处理
	switch (command->type) {
	case WRITE:
	{
		// 写内存应该是等长更改
		break;
	}
	case DEATTACH:
	{
		if (!hThread) break;
		// 修复eip   记得按情况设置好setpLen的值
		context.Eip -= stepLen;
		// 设置Trap位
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		// 清除所有硬件断点
		PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
		pDr7->L0 = 0;
		pDr7->L1 = 0;
		pDr7->L2 = 0;
		pDr7->L3 = 0;
		SetThreadContext(hThread, &context);
		// 清除所有软件断点
		CleanAllSoftwareBreakPoint(pid);
		// 退出用户命令循环
		retFlag = 0;
		// 退出调试事件等待、监控
		debugFlag = 0;
		// 退出附加的进程
		deAttachNow = 1;
		break;
	}
	case READ:
	{
		PBYTE data = (PBYTE)malloc(command->u2.len);
		if (!data) {
			printf("申请临时空间失败 读内存\n\n");
			break;
		}
		if (!hProcess) break;
		ReadProcessMemory(hProcess, (LPCVOID)command->u1.addr, data, command->u2.len, 0);
		PrintMem((PULONG32)data, command->u2.len, 4, (PULONG32)command->u1.addr);
		free(data);
		break; 
	}
	case SET:
	{
		SetSoftwareBreakPoint((PVOID)command->u1.addr, pid);
		break;
	}
	case SETHARD:
	{
		SetHardBreakPoint((PVOID)command->u1.addr, command->u2.drx, &context, 0, 0, 1);
		if(hThread) SetThreadContext(hThread, &context);
		break;
	}
	case SETMEM:
	{
		SetMemoryBreakPoint((PVOID)command->u1.addr, DebugEv->dwProcessId, 0);
		// retFlag = 0;
		break;
	}
	case STEPINM:
	{
	}
	case STEPIN:
	{
		if (!hThread) break;
		// 修复eip
		context.Eip -= stepLen;
		// 设置Trap位
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 1;
		context.EFlags = tmpEflags.eflags;
		// 如果当前是硬件断点导致的异常，那么也应该暂时修复硬件断点
		DWORD drx = context.Dr6 & 0xf;
		PDBG_REG7 dbgR7 = (PDBG_REG7)&context.Dr7;
		if (drx == 1) {
			dbgR7->L0 = 0;
			globalTmpHardBreakPoint[0].addr = context.Dr0;
			globalTmpHardBreakPoint[0].drx = 0;
		}
		else if (drx == 2) {
			dbgR7->L1 = 0;
			globalTmpHardBreakPoint[1].addr = context.Dr1;
			globalTmpHardBreakPoint[1].drx = 2;
		}
		else if (drx == 4) {
			dbgR7->L2 = 0;
			globalTmpHardBreakPoint[2].addr = context.Dr2;
			globalTmpHardBreakPoint[2].drx = 4;
		}
		else if (drx == 8) {
			dbgR7->L3 = 0;
			globalTmpHardBreakPoint[3].addr = context.Dr3;
			globalTmpHardBreakPoint[3].drx = 6;
		}// 修改后，记得把断点重新设置上！！！
		// 重设上下文
		SetThreadContext(hThread, &context);
		// 判断并可能临时清除断点
		StepInReuse(hProcess, hThread, context);
		if (command->u1.addr != 1) {
			lastCommand = 0;
		}
		// 临时恢复内存断点   accessFlag标志是内存断点导致的异常，当前需要临时恢复
		if (command->u1.addr != 1 && memFlag) {
			AutoHandleMemoryException(DebugEv, hProcess, 0);
		}
		retFlag = 0;
		break;
	}
	case CLEAR:
	{
		CleanAllSoftwareBreakPoint(pid);
		break;
	}
	case RMBREAKPOINT:
	{
		if(command->u1.addr >= 4)
			deleteBreakpoint((PVOID)command->u1.addr, pid);
		// 此时的值只会是 0 1 2 3
		else if(command->u1.addr >= 0 && command->u1.addr < 4)
			RmHardBreakPoint(&context, command->u1.addr);
		if(hThread) SetThreadContext(hThread, &context);
		break;
	}
	case LISTSFOTBREAKPOINT:
	{
		ListSoftwareBreakPoint();
		ListHardBreakPoint(context);
		break;
	}
	case PRINTFREGS:
	{
		// 处理前的线程上下文
		PrintRegs(tid);
		break;
	}
	case DISASMCODE:
	{
		DisasmByUserCommand(hProcess, command);
		break; 
	}
	case STEPOVER:
	{
		if (!hThread || !hProcess) break;
		// 软件断点实现步过
		// 通过判断是否为call指令、重复性指令来确定下一个断点的位置
		// 如果考虑使用 临时断点数组 ，那么得考虑step in的 设置临时断点
		int step = 0;
		// 读取已经处理的数据
		PBYTE data = (PBYTE)malloc(16);
		if (!data) {
			printf("申请临时空间失败 步过\n\n");
			break;
		}
		memset(data, 0, 16);
		// 修复eip
		context.Eip -= stepLen;
		// 设置Trap位
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		if(context.Eip) ReadProcessMemory(hProcess, (LPCVOID)context.Eip, data, 16, 0);
		if ((step = DisasmJudge(cshHandle, data))) {
			tmpEflags.u.TF = 0;
			context.EFlags = tmpEflags.eflags;
			// 设置一个临时的断点
			tmpUseSoftBreak.breakAddr = context.Eip + step;
			// 一定记得原值需要重新读一下，因为临时断点在下一条指令！
			ReadProcessMemory(hProcess, (LPCVOID)tmpUseSoftBreak.breakAddr, data, 16, 0);
			tmpUseSoftBreak.origin = data[0];
			// 设置临时的cc断点
			WriteProcessMemory(hProcess, (LPVOID)tmpUseSoftBreak.breakAddr, "\xCC", 1, 0);
		}
		else {
			// 不是call以及重复命令，因此走单步步入的步骤即可
			tmpEflags.u.TF = 1;
			context.EFlags = tmpEflags.eflags;
		}
		// 如果当前是硬件断点导致的异常，那么也应该暂时修复硬件断点
		DWORD drx = context.Dr6 & 0xf;
		PDBG_REG7 dbgR7 = (PDBG_REG7)&context.Dr7;
		if (drx == 1) {
			dbgR7->L0 = 0;
			globalTmpHardBreakPoint[0].addr = context.Dr0;
			globalTmpHardBreakPoint[0].drx = 0;
		}
		else if (drx == 2) {
			dbgR7->L1 = 0;
			globalTmpHardBreakPoint[1].addr = context.Dr1;
			globalTmpHardBreakPoint[1].drx = 2;
		}
		else if (drx == 4) {
			dbgR7->L2 = 0;
			globalTmpHardBreakPoint[2].addr = context.Dr2;
			globalTmpHardBreakPoint[2].drx = 4;
		}
		else if (drx == 8) {
			dbgR7->L3 = 0;
			globalTmpHardBreakPoint[3].addr = context.Dr3;
			globalTmpHardBreakPoint[3].drx = 6;
		}// 修改后，记得把断点重新设置上！！！
		SetThreadContext(hThread, &context);
		// 单步步入，复用；如果是int 3 软件断点的话，将会临时恢复断点。直至下一次异常处理恢复临时断点
		// 如果不是int 3软件断点，将会不处理。
		StepInReuse(hProcess, hThread, context);
		lastCommand = 0;
		// 临时恢复内存断点   accessFlag标志是内存断点导致的异常，当前需要临时恢复
		if (command->u1.addr != 1 && memFlag) {
			AutoHandleMemoryException(DebugEv, hProcess, 0);
		}
		retFlag = 0;
		break;
	}
	case RUN:
	{
		// 如果软件断点和硬件断点断在一起的话，应该会死锁
		if (!hThread) break;
		// 修复eip
		context.Eip -= stepLen;
		// 清0 tp位
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		if (stepLen == 1) {
			UserCommand command;
			command.u1.addr = context.Eip;
			command.u2.len = 1;
			// 当前是软件断点
			// 临时恢复软件断点   理论上每次异常处理，临时断点数量为0
			tmpRecoverSoftwareBreakPoint(&command, hProcess, 0);
		}// 还要处理硬件断点和内存断点
		// 如果当前是硬件断点导致的异常，那么也应该暂时修复硬件断点   存在要run两次的情况？？？应该不是这里的问题 找一找
		DWORD drx = context.Dr6 & 0xf;
		PDBG_REG7 dbgR7 = (PDBG_REG7)&context.Dr7;
		if (drx & 1) {
			dbgR7->L0 = 0;
			globalTmpHardBreakPoint[0].addr = context.Dr0;
			globalTmpHardBreakPoint[0].drx = 0;
		}
		if (drx & 2) {
			dbgR7->L1 = 0;
			globalTmpHardBreakPoint[1].addr = context.Dr1;
			globalTmpHardBreakPoint[1].drx = 2;
		}
		if (drx & 4) {
			dbgR7->L2 = 0;
			globalTmpHardBreakPoint[2].addr = context.Dr2;
			globalTmpHardBreakPoint[2].drx = 4;
		}
		if (drx & 8) {
			dbgR7->L3 = 0;
			globalTmpHardBreakPoint[3].addr = context.Dr3;
			globalTmpHardBreakPoint[3].drx = 6;
		}// 修改后，记得把断点重新设置上！！！

		// 恢复线程上下文
		SetThreadContext(hThread, &context);
		// printf("count: %d\n\n", count);
		// run指令，指示处理内存断点到异常发生！
		lastCommand = 1;
		// 临时恢复内存断点   accessFlag标志是内存断点导致的异常，当前需要临时恢复
		if (command->u1.addr != 1 && memFlag) {
			AutoHandleMemoryException(DebugEv, hProcess, 0);
		}
		// 结束当前用户指令会话
		retFlag = 0;
		break;
	}
	case EXIT: 
	{
		if (!hThread) break;
		// 修复eip   记得按情况设置好setpLen的值
		context.Eip -= stepLen;
		// 设置Trap位
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		// 清除所有硬件断点
		PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
		pDr7->L0 = 0;
		pDr7->L1 = 0;
		pDr7->L2 = 0;
		pDr7->L3 = 0;
		SetThreadContext(hThread, &context);
		// 清除所有软件断点
		CleanAllSoftwareBreakPoint(pid);
		retFlag = 0;
		break;
	}
	case LISTPROCESS:
	{
		// 因为command->u1.name只是一个PCHAR变量，
		// 其指向的内容是main从formatInput空间中复制过来的，在main函数帧中是局部变量, 在使用时会发现值不正确了。
		// 操作字符串变量传参时，一定要注意 字符数据 有没有真正拿到返回、有没有真正传入。
		ListProcess(command->u1.name);
		break; 
	}
	default:
		printf("Wrong ommand. \n w => write, r => READ, set => SET Breakpoint\n \
cls => CLEAR, si => STEPIN, so => STEPOVER, lp => LIST Process\n \
run => RUN, exit => EXIT\n");
	}

	// 释放句柄
	if(hProcess) CloseHandle(hProcess);
	if(hThread) CloseHandle(hThread);
	return retFlag;
}

// 创建进程，进行调试
int CreateForDebug(char* imagePath) {
	STARTUPINFOA startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	// 进调试当前进程，不调试其子进程; 这样当前进程将会在DebugPort中存放目标进程的调试对象句柄。
	BOOL ret = CreateProcessA(NULL, imagePath, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, \
		&startupInfo, &processInformation);
	if (!ret) {
		printf("创建调试进程%s失败，errorCode: 0x%x\n", imagePath, GetLastError());
		return 0;
	}
	if (processInformation.hProcess) CloseHandle(processInformation.hProcess);
	if (processInformation.hThread) CloseHandle(processInformation.hThread);
	return 1;
}

// 调试主循环
void EnterDebugLoop(PUserCommand command, const LPDEBUG_EVENT DebugEv)
{
	// 模块名
	TCHAR name[1024] = { 0 };
	// 是否为系统断点
	int flag = 0;
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

	for (;debugFlag;)
	{
		WaitForDebugEvent(DebugEv, INFINITE);
		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// 如果有设置临时的断点，那么需要将其恢复为断点  之所以放在此处恢复，
			// 是保证在下一次用户操作前，临时断点一定全部得到恢复
			if (count) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("因为打开进程句柄失败，导致恢复临时断点cc的操作失败\n\n");
					break;
				}
				// 变回断点   与用户 run 命令处的recoverSoftBreakAgain函数配对
				// 如果严格成对出现的话，此处一定只存在一个临时断点的 临时恢复断点。
				recoverSoftBreakAgain(hProcess, 0);
				CloseHandle(hProcess);
			}
			// 恢复临时断点原值
			if (tmpUseSoftBreak.breakAddr) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("因为打开进程句柄失败，导致恢复临时断点原值的操作失败\n\n");
					break;
				}
				WriteProcessMemory(hProcess, (LPVOID)tmpUseSoftBreak.breakAddr, \
					(LPCVOID)&tmpUseSoftBreak.origin, 1, 0);
				CloseHandle(hProcess);
			}
			// 恢复临时软件断点原值
			// 如果当前是访问异常，应该判断当前是否是下断点的地方，如果不是那么应该跳过当前指令
			if (mcount) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("因为打开进程句柄失败，导致恢复内存断点的操作失败\n\n");
					break;
				}
				// 先仅仅做内存执行断点的修复
				for (int i = 0; i < mcount; i++) {
					BreakPointInfo bpInfo = globalTmpMemoryBreakpoint[i];
					if (bpInfo.mtype == 0) {
						DWORD t;
						VirtualProtectEx(hProcess, (LPVOID)((DWORD)bpInfo.breakAddr & 0x0fffff000), 0x1000, bpInfo.originalProtect, &t);
					}
					memset(&globalTmpMemoryBreakpoint[i], 0, sizeof(BreakPointInfo));
				}
				mcount = 0;
				CloseHandle(hProcess);
			}
			switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
			{
				// printf("ACCESS_VIOLATION\n");
				// 异常发生地址
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("因为打开进程句柄失败，导致恢复内存断点的操作失败\n\n");
					break;
				}
				// 非断点地址，导致修复内存页属性
				int ret = AutoHandleMemoryException(DebugEv, hProcess, 1);
				CloseHandle(hProcess);
				if (ret) {
					// 内存断点处到了，用户接管异常
					printf("\n内存断点触发:0x%x\n", DebugEv->u.Exception.ExceptionRecord.ExceptionInformation[1]);
					UserHandleException(command, DebugEv);
					lastCommand = 0;
				}
				else {
					// 主动触发单步执行，进入异常自动修复断点，保证下次再次触发内存断点
					command->type = STEPINM;
					command->u1.addr = 1;
					DoCommand(command, DebugEv);
					memset(command, 0, sizeof(UserCommand));
				}
				break;
			}
			case EXCEPTION_BREAKPOINT: 
			{
				printf("EXCEPTION_BREAKPOINT\n\n");
				// 系统断点
				if (!flag) {
					// 系统断点不可由用户处理，否则将会在此处停滞不前。
					printf("系统断点触发，in 0x%x\n\n", (DWORD)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
					flag++;
					if (attchOrCreate) {
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, DebugEv->dwThreadId);
						if (!hThread) {
							printf("因为打开线程句柄失败，导致attch进程的第一个设置断点操作失败\n\n");
							break;
						}
						CONTEXT context;
						context.ContextFlags = CONTEXT_ALL;
						GetThreadContext(hThread, &context);
						// 设置第一个断点
						SetSoftwareBreakPoint((PVOID)context.Eip, DebugEv->dwProcessId);
						CloseHandle(hThread);
					}
					break;
				}
				// 后续的软件断点了
				printf("软件断点触发，in 0x%x\n\n", (DWORD)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
				// 调试器将异常交予用户
				UserHandleException(command, DebugEv);
				break; 
			}
			case EXCEPTION_DATATYPE_MISALIGNMENT: 
				printf("DATATYPE_MISALIGNMENT\n");
				break;
			case EXCEPTION_SINGLE_STEP:
			{
				// 不是run指令，就走一步停一下！
				if (lastCommand) {
					// 当前是不是硬件中断
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, DebugEv->dwThreadId);
					if (!hThread) {
						printf("未能正常打开线程，无法判断硬件中的触发与否\n\n");
						break;
					}
					CONTEXT t;
					t.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &t);
					DWORD dr6 = t.Dr6;
					if (dr6 & 0x0f) {
						printf("\n硬件断点触发,DR0:0x%x,DR1:0x%x,DR2:0x%x,DR3:0x%x\n", t.Dr0,t.Dr1,t.Dr2,t.Dr3);
						UserHandleException(command, DebugEv);
					}
					CloseHandle(hThread);
					break;
				}
				UserHandleException(command, DebugEv);
				break;
			}
			case DBG_CONTROL_C:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				printf("被调试进程获取 Ctrl + c 信号\n");
				break;
			default:
				break;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			// dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
			// printf("线程创建\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			// dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
		{
			printf("进程%s创建, 于%p处设置断点。\n",\
				(char *)DebugEv->u.CreateProcessInfo.lpImageName, DebugEv->u.CreateProcessInfo.lpStartAddress);
			// 设置第一个断点
			SetSoftwareBreakPoint(DebugEv->u.CreateProcessInfo.lpStartAddress, DebugEv->dwProcessId);
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code. 
			// dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
			printf("线程退出\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code. 
			// dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
			// 脱离调试
			DebugActiveProcessStop(DebugEv->dwProcessId);
			printf("进程调试对象退出\n");
			debugFlag = 0;
			break;
		case LOAD_DLL_DEBUG_EVENT:
		{
			// 模块名
			// 调试进程中的地址
			HANDLE hmap = CreateFileMapping(DebugEv->u.LoadDll.hFile, 0, PAGE_READONLY, 0, 1, 0);
			if (!hmap) break;
			LPVOID pmem = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 1);
			if (!pmem) break;
			int ret = GetMappedFileName(GetCurrentProcess(), pmem, name, 1024);
				
			printf("[%d:%d] %ws is loaded, locate at %x\n", ret, GetLastError(), \
			name, (DWORD)DebugEv->u.LoadDll.lpBaseOfDll);
			UnmapViewOfFile(pmem);

			memset(name, 0, 1024 * sizeof(TCHAR));
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
			// dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);
			printf("dll卸载\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			// dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
			// 被调试进程可以向调试器发消息，调试器在此处接收
			// printf("输出调试字符串事件\n");
			break;
		case RIP_EVENT:
			// dwContinueStatus = OnRipEvent(DebugEv);
			printf("RIP事件\n");
			break;
		}
		// Resume executing the thread that reported the debugging event. 
		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dwContinueStatus);
		if (deAttachNow) {
			// 如果退出了调试器
			DebugActiveProcessStop(DebugEv->dwProcessId);
		}
	}
}

// 用户处理异常
int UserHandleException(PUserCommand command, const LPDEBUG_EVENT DebugEv) {
	// 字符串操作专用临时存储空间
	char processArgs[256] = { 0 };
	int flag = 1;
	while (flag) {
		int ret = FormatInput(command, processArgs);
		if (ret == 0) {
			printf("code: 0\n");
			memset(command, 0, sizeof(UserCommand));
			continue;
		}
		flag = DoCommand(command, DebugEv);
		memset(command, 0, sizeof(UserCommand));
	}
	return 0;
}

// 设置软件断点
int SetSoftwareBreakPoint(PVOID addr, DWORD pid) {
	// 打开被调试进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("打开被调试进程失败\n\n");
		return 0;
	}
	// 读一个字节，保存起来，然后写0xcc。
	BreakPointInfo* bp = (BreakPointInfo*)malloc(sizeof(BreakPointInfo));
	if (!bp) {
		printf("初始化断点信息失败\n\n");
		return 0;
	}
	memset(bp, 0, sizeof(BreakPointInfo));
	bp->breakAddr = (DWORD)addr;
	bp->bptype = SOFTWAREBP;

	ReadProcessMemory(hProcess, addr, &bp->origin, 1, 0);
	// PrintMem((PULONG32)p, 100, 4, ((PULONG32)addr));
	WriteProcessMemory(hProcess, addr, "\xCC", 1, 0);  // "\xCC" 传入的是字符串常量的指针，然后获取到值0xcc

	CloseHandle(hProcess);

	// 将断点插入链表
	if (!breakArray.Flink) insertFirstNode(&bp->pointer);
	else insertListHeader(&bp->pointer, SOFTWAREBP);

	return 1;
}

// 设置硬件断点
int SetHardBreakPoint(PVOID addr, DWORD drx, PCONTEXT context, DWORD len, DWORD type, BOOL local) {
/**
	保存DR0-DR3地址所指向位置的断点类型(RW0-RW3)与断点长度(LEN0-LEN3)，状态描述如下：
		00：执行         01：写入        11：读写
		00：1字节        01：2字节       11：4字节
	设置硬件执行断点时，长度只能为1(LEN0-LEN3设置为0时表示长度为1)
	设置读写断点时，如果长度为1，地址不需要对齐，如果长度为2，则地址必须是2的整数倍，如果长度为4，则地址必须是4的整数倍。
*/
	int offset = local ? 0 : 1;
	if (context->Dr7 & 1 << ((2 * drx) + offset)) {
		printf("DR%d寄存器正在使用中\n\n", drx);
		return 0;
	}
	if (len != 0 && type == 0) {
		printf("设置硬件执行断点时，长度只能为1!(即 len == 0)\n\n");
		return 0;
	}
	// 这个也是一种赋值位的办法
	PDBG_REG7 pDr7 = (PDBG_REG7)&context->Dr7;
	// 其实还需要分 局部硬件断点还是全局硬件断点;  分是断点是 1bit 2bit 4bit
	// 当断点是全局时，无法获取调试事件；
	// 局部硬件断点用来实现stepover简直绝配

	// 不同长度的硬件断点需要修复下断点的地址
	//  00 1bit    01 2bit    11 4bit
	if (len == 1) {
		addr = (PVOID)((DWORD)addr - (DWORD)addr % 2);
	}
	else if (len == 3) {
		addr = (PVOID)((DWORD)addr - (DWORD)addr % 4);
	}

	// 目前全部实现全局硬件断点
	switch (drx) {
	case 0:
	{
		context->Dr0 = (DWORD)addr;
		// 00 执行， 01 写， 11读写  =>  type == 0 / 1 / 3
		pDr7->RW0 = type;
		pDr7->LEN0 = len;
		// 全局断点还是局部断点
		if (local) pDr7->L0 = 1;
		else pDr7->G0 = 1;
		break;
	}
	case 1:
	{
		context->Dr1 = (DWORD)addr;
		// 00 执行， 01 写， 11读写  =>  type == 0 / 1 / 3
		pDr7->RW1 = type;
		pDr7->LEN1 = len;
		// 全局断点还是局部断点
		if (local) pDr7->L1 = 1;
		else pDr7->G1 = 1;
		break;
	}
	case 2:
	{
		context->Dr2 = (DWORD)addr;
		// 00 执行， 01 写， 11读写  =>  type == 0 / 1 / 3
		pDr7->RW2 = type;
		pDr7->LEN2 = len;
		// 全局断点还是局部断点
		if (local) pDr7->L2 = 1;
		else pDr7->G2 = 1;
		break;
	}
	case 3:
	{
		context->Dr3 = (DWORD)addr;
		// 00 执行， 01 写， 11读写  =>  type == 0 / 1 / 3
		pDr7->RW3 = type;
		pDr7->LEN3 = len;
		// 全局断点还是局部断点
		if (local) pDr7->L3 = 1;
		else pDr7->G3 = 1;
		break;
	}
	}
	return 1;
}

// 设置内存断点
void SetMemoryBreakPoint(PVOID addr, DWORD pid, DWORD type) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("获取进程句柄失败，无法正常设置内存访问断点\n\n");
		return;
	}
	// 读一个字节，保存起来，然后写0xcc。
	BreakPointInfo* bp = (BreakPointInfo*)malloc(sizeof(BreakPointInfo));
	if (!bp) {
		printf("初始化断点信息失败\n\n");
		return;
	}
	memset(bp, 0, sizeof(BreakPointInfo));
	bp->breakAddr = (DWORD)addr;
	bp->bptype = MEMORYBP;
	DWORD originalProtect;
	if (type == 0) {
		// 执行断点
		bp->mtype = 0;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_READWRITE, &bp->originalProtect);
	}
	else if (type == 1) {
		// 写断点
		bp->mtype = 1;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_EXECUTE_READ, &bp->originalProtect);
	}
	else if (type == 2) {
		// 读断点、访问断点
		bp->mtype = 2;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_NOACCESS, &bp->originalProtect);
	}

	CloseHandle(hProcess);
	// 查一下这个页面有没有节点已经插过了
	BreakPointInfo t;
	if (inThePageLinkList((DWORD)addr, &t, MEMORYBP)) {
		printf("该页面已有内存断点，现在查询页面属性:0x%x,最原始页面属性:0x%x, 已经更新插入断点\n\n", bp->originalProtect, t.originalProtect);
		bp->originalProtect = t.originalProtect;
	}
	// 将断点插入链表
	if (!breakArray.Flink) insertFirstNode(&bp->pointer);
	else insertListHeader(&bp->pointer, MEMORYBP);
}

// 插入首节点
void insertFirstNode(LIST_ENTRY* node) {
	breakArray.Flink = node;
	breakArray.Blink = node;
	node->Flink = node;
	node->Blink = node;
}

// 头插法
void insertListHeader(LIST_ENTRY* node, BreakPointType bptype) {
	DWORD offset = (DWORD) & (((BreakPointInfo*)0)->pointer) - 0;
	BreakPointInfo* nowNode = (BreakPointInfo*)((DWORD)node - offset);
	if (inTheLinkList(nowNode->breakAddr, 0, bptype)) {
		if(nowNode->bptype == SOFTWAREBP)
			printf("不可重复在软件断点0x%x处下断点, 断点现值: 0x%x\n\n", nowNode->breakAddr, nowNode->origin);
		else if(nowNode->bptype == MEMORYBP)
			printf("不可重复在内存断点0x%x处下断点, 页面原属性: 0x%x\n\n", nowNode->breakAddr, nowNode->originalProtect);
		free(nowNode);
		return;
	}

	LIST_ENTRY* tmp = breakArray.Flink;
	breakArray.Flink = node;

	node->Flink = tmp;
	node->Blink = breakArray.Blink;

	tmp->Blink = node;

	breakArray.Blink->Flink = breakArray.Flink;
}

// haven in
int inTheLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype) {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	do {
		DWORD offset = (DWORD) & (((BreakPointInfo*)0)->pointer) - 0;
		BreakPointInfo* tmp = (BreakPointInfo*)((DWORD)start - offset);

		if (tmp->breakAddr == addr && tmp->bptype == bptype) {
			if (retV) RtlCopyMemory(retV, tmp, sizeof(BreakPointInfo));
			return 1;
		}
		start = start->Flink;
	} while (start != end->Flink);
	return 0;
}

// 删除指定断点
void deleteBreakpoint(PVOID addr, DWORD pid) {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	// 打开被调试进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("打开被调试进程失败 释放\n\n");
		return;
	}

	DWORD offset = (DWORD) & ((PBreakPointInfo)0)->pointer - 0;
	PBreakPointInfo tmp = (PBreakPointInfo)(DWORD(start) - offset);

	if (start == NULL || end == NULL) {
		printf("暂无软件断点\n\n");
		return;
	}

	if (start == end && tmp->breakAddr == (DWORD)addr) {
		breakArray.Flink = 0;
		breakArray.Blink = 0;
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// 释放节点
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[软件断点] 释放断点final: 0x%x, 断点原值: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			if (!inThePageLinkList(tmp->breakAddr, 0, MEMORYBP)) {
				// 该页面内没有内存断点了，可以永久恢复
				DWORD t = 0;
				VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			}
			printf("[内存断点] 释放断点final: 0x%x, 页面原属性: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		free(tmp);
		return;
	}

	do {
		tmp = (PBreakPointInfo)(DWORD(start) - offset);

		if (tmp->breakAddr == (DWORD)addr) {
			// 摘掉此节点
			PLIST_ENTRY ltmp = start;
			ltmp->Blink->Flink = ltmp->Flink;
			ltmp->Flink->Blink = ltmp->Blink;
			if (breakArray.Flink == ltmp) breakArray.Flink = ltmp->Flink;
			if (breakArray.Blink == ltmp)  breakArray.Blink = ltmp->Blink;
			// 释放节点
			if (tmp->bptype == SOFTWAREBP) {
				WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
				printf("[软件断点] 释放断点final: 0x%x, 断点原值: 0x%x\n\n", tmp->breakAddr, tmp->origin);
			}
			else if (tmp->bptype == MEMORYBP) {
				if (!inThePageLinkList(tmp->breakAddr, 0, MEMORYBP)) {
					// 该页面内没有内存断点了，可以永久恢复
					DWORD t = 0;
					VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
				}
				printf("[内存断点] 释放断点final: 0x%x, 页面原属性: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
			}
			free(tmp);
			break;
		}
		start = start->Flink;
	} while (start != end->Flink);
	CloseHandle(hProcess);
}

// 查看断点
void ListSoftwareBreakPoint() {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	if (!start || !end) {
		printf("暂无断点\n\n");
		return;
	}
	do {
		DWORD offset = (DWORD)&(((BreakPointInfo*)0)->pointer) - 0;
		BreakPointInfo *tmp = (BreakPointInfo*)((DWORD)start - offset);
		
		if(tmp->bptype == SOFTWAREBP)
			printf("[软件断点] 断点地址: 0x%x, 断点原值: 0x%x\n", tmp->breakAddr, tmp->origin);
		else if(tmp->bptype == MEMORYBP)
			printf("[内存断点] 断点地址: 0x%x, 内存原属性: 0x%x\n", tmp->breakAddr, tmp->originalProtect);
		start = start->Flink;
	} while (start != end->Flink);
	printf("\n");
}

// 清理所有软件断点\内存断点
void CleanAllSoftwareBreakPoint(DWORD pid) {
	// 打开被调试进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("打开被调试进程失败\n");
		return;
	}
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	DWORD offset = (DWORD) & ((PBreakPointInfo)0)->pointer - 0;
	PBreakPointInfo tmp = (PBreakPointInfo)(DWORD(start) - offset);

	if (start == NULL || end == NULL) {
		printf("已清理所有软件断点\n\n");
		return;
	}

	// 只有一个节点
	if (start == end) {
		breakArray.Flink = 0;
		breakArray.Blink = 0;
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// 释放节点
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[软件断点] 释放断点final: 0x%x, 断点原值: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			DWORD t = 0;
			VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			printf("[内存断点] 释放断点final: 0x%x, 页面原属性: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		free(tmp);
		return;
	}

	do {
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// 删掉的永远是头节点，因此只需要修改breakArray的向前指针
		breakArray.Flink = tmp->pointer.Flink;
		tmp->pointer.Flink->Blink = tmp->pointer.Blink;
		tmp->pointer.Blink->Flink = tmp->pointer.Flink;

		// 释放节点
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[软件断点] 释放断点: 0x%x, 断点原值: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			DWORD t = 0;
			VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			printf("[内存断点] 释放断点: 0x%x, 页面原属性: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		start = start->Flink;
		free(tmp);
	} while (start != end);

	breakArray.Flink = 0;
	breakArray.Blink = 0;
	tmp = (PBreakPointInfo)(DWORD(start) - offset);
	// 释放节点
	if (tmp->bptype == SOFTWAREBP) {
		WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
		printf("[软件断点] 释放断点final2: 0x%x, 断点原值: 0x%x\n\n", tmp->breakAddr, tmp->origin);
	}
	else if (tmp->bptype == MEMORYBP) {
		DWORD t = 0;
		VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
		printf("[内存断点] 释放断点final2: 0x%x, 页面原属性: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
	}
	free(tmp);
	CloseHandle(hProcess);
}

// 临时恢复断点
void tmpRecoverSoftwareBreakPoint(PUserCommand command, HANDLE hProcess, DWORD startIndex) {
	// 记得反汇编之前恢复断点值
	DWORD startAddr = command->u1.addr;
	BYTE p = 0;
	for (DWORD i = 0; i < command->u2.len; i++, startAddr++) {
		int ret = 0;
		ReadProcessMemory(hProcess, (LPCVOID)startAddr, &p, 1, 0);
		if (p == 0xcc) {
			ret = inTheLinkList(startAddr, &globalTmpSoftwareBreakpoint[count], SOFTWAREBP);
			if (ret) count++;
		}
	}
	// 恢复代码
	for (int i = startIndex; i < count; i++) {
		BreakPointInfo tmp = globalTmpSoftwareBreakpoint[i];
		if (tmp.breakAddr)
			WriteProcessMemory(hProcess, (LPVOID)tmp.breakAddr, &(tmp.origin), 1, 0);
	}
}

// 重新设置好断点
void recoverSoftBreakAgain(HANDLE hProcess, int startIndex) {
	int i = startIndex;
	// 恢复断点
	for (startIndex; startIndex < count; startIndex++) {
		BreakPointInfo tmp = globalTmpSoftwareBreakpoint[startIndex];
		memset(&globalTmpSoftwareBreakpoint[startIndex], 0, sizeof(BreakPointInfo));
		if (tmp.breakAddr)
			WriteProcessMemory(hProcess, (LPVOID)tmp.breakAddr, "\xCC", 1, 0);
	}
	count = i;
}

// 反汇编用户指令对应操作，复用
void DisasmByUserCommand(HANDLE hProcess, PUserCommand command) {
	if (!hProcess) return;
	// 临时恢复   ==>  必须与成对出现
	int startIndex = count;
	printf("startIndex start: %d\n", startIndex);
	tmpRecoverSoftwareBreakPoint(command, hProcess, startIndex);

	// 读取已经处理的数据
	PBYTE data = (PBYTE)malloc(command->u2.len);
	if (!data) {
		printf("申请临时空间失败 反汇编\n\n");
		return;
	}
	memset(data, 0, command->u2.len);
	ReadProcessMemory(hProcess, (LPCVOID)command->u1.addr, data, command->u2.len, 0);
	// 变回断点
	recoverSoftBreakAgain(hProcess, startIndex);
	printf("startIndex end: %d\n\n", startIndex);

	DisasmInput(cshHandle, data, command->u2.len, command->u1.addr);
	free(data);
}

// 单步步入，复用
void StepInReuse(HANDLE hProcess, HANDLE hThread, CONTEXT context) {
	// 有可能是trap ， 也有可能是硬件断点
	UserCommand tmp;
	// SetThreadContext(hThread, &context);
	tmp.u1.addr = context.Eip;
	tmp.u2.len = 1;
	// 临时恢复了断点，但是还没有设置回去断点
	tmpRecoverSoftwareBreakPoint(&tmp, hProcess, 0);
}

// 打印临时信息
void printTmpCodeInfo(HANDLE hProcess, CONTEXT context, const char* sign, int stepLen) {
	// 换了输出的位置，导致此参数无用了
	// stepLen = 0;
	// 打印提示信息
	printf("%s , current eip : 0x%x\n", sign, context.Eip - stepLen);
	// 显示几行汇编
	if (hProcess && context.Eip) {
		PBYTE data = (PBYTE)malloc(16);
		if (!data) {
			printf("申请临时空间失败 反汇编\n\n");
			return;
		}
		UserCommand command;
		command.u1.addr = context.Eip - stepLen;
		command.u2.len = 16;
		DisasmByUserCommand(hProcess, &command);
	}
}

// 查看所有的硬件断点
void ListHardBreakPoint(CONTEXT context) {
	PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
	
	if (pDr7->L0) 
		printf("硬件断点DR0: 0x%x, 断点长度: %d, 断点类型: %x\n", context.Dr0, pDr7->LEN0, pDr7->RW0);
	if (pDr7->L1)
		printf("硬件断点DR1: 0x%x, 断点长度: %d, 断点类型: %x\n", context.Dr1, pDr7->LEN1, pDr7->RW1);
	if (pDr7->L2)
		printf("硬件断点DR2: 0x%x, 断点长度: %d, 断点类型: %x\n", context.Dr2, pDr7->LEN2, pDr7->RW2);
	if (pDr7->L3)
		printf("硬件断点DR3: 0x%x, 断点长度: %d, 断点类型: %x\n\n", context.Dr3, pDr7->LEN3, pDr7->RW3);
}

// 删除指定的硬件断点
void RmHardBreakPoint(PCONTEXT pContext, DWORD num) {

	PDBG_REG7 pDr7 = (PDBG_REG7)&pContext->Dr7;
	if (num == 0) {
		pContext->Dr0 = 0;
		pDr7->L0 = 0;
	}
	else if (num == 1) {
		pContext->Dr1 = 0;
		pDr7->L1 = 0;
	}
	else if (num == 2) {
		pContext->Dr2 = 0;
		pDr7->L2 = 0;
	}
	else if (num == 3) {
		pContext->Dr3 = 0;
		pDr7->L3 = 0;
	}
}

// 处理内存断点异常
int AutoHandleMemoryException(LPDEBUG_EVENT DebugEv, HANDLE hProcess, DWORD autoHandle) {
	// 判断异常类型
	EXCEPTION_DEBUG_INFO procInfo = DebugEv->u.Exception;
	// 0读  1写   8执行
	DWORD accessFlag = procInfo.ExceptionRecord.ExceptionInformation[0]; 
	DWORD accessAddr = procInfo.ExceptionRecord.ExceptionInformation[1];

	// 遍历所有断点，找到页面内的内存断点，记录入全局表 // 此程序中，只考虑内存执行断点
	BreakPointInfo bpInfo;
	int ret = inTheLinkList(accessAddr, 0, MEMORYBP);
	if (ret && autoHandle) {
		return 1;
	}

	bpInfo.breakAddr = (DWORD)accessAddr & 0x0fffff000;
	if (accessFlag == 0) {
		// 内存读、访问异常
	}
	else if (accessFlag == 1) {
		// 内存写异常
	}
	else if (accessFlag == 8) {
		// 内存执行异常
		// 自动修复，临时修复异常页面, 内存执行异常不需要修复eip。
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)accessAddr & 0x0fffff000), 0x1000, PAGE_EXECUTE, &bpInfo.originalProtect);
		bpInfo.mtype = 0;
		globalTmpMemoryBreakpoint[mcount++] = bpInfo;
	}
	return 0;
}

// 此页面已有内存断点？
// haven in
int inThePageLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype) {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	do {
		DWORD offset = (DWORD) & (((BreakPointInfo*)0)->pointer) - 0;
		BreakPointInfo* tmp = (BreakPointInfo*)((DWORD)start - offset);

		if ((tmp->breakAddr & 0x0fffff000) == (addr & 0x0fffff000) && tmp->bptype == bptype) {
			if (retV) RtlCopyMemory(retV, tmp, sizeof(BreakPointInfo));
			return 1;
		}
		start = start->Flink;
	} while (start != end->Flink);
	return 0;
}