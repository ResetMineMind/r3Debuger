#ifndef __HELPER__
#define __HELPER__
#include <string.h>
#include <ctype.h>
#include "debugger.h"
#include <TlHelp32.h>  // 必须在windows.h文件之后加载

#define COMMANDLEN 4
typedef struct _AnalysisInt {
	ULONG32 low1   : 4;
	ULONG32 low2 : 4;
	ULONG32 high1  : 4;
	ULONG32 high2 : 4;
	ULONG32 Rlow1  : 4;
	ULONG32 Rlow2 : 4;
	ULONG32 Rhigh1 : 4;
	ULONG32 Rhigh2 : 4;
}AnalysisInt;

// 字符串转16进制
int HexStrToInt(const char* hexStr) {
	LONG32 res = 0;
	LONG32 len = strlen(hexStr);
	if (len > 10) return -2;
	if (len <= 2 || !(hexStr[0] == '0' && toupper(hexStr[1]) == 'X')) return -1;
	for (LONG32 i = 2; i < len; i++) {
		LONG32 now = toupper(hexStr[i]);
		if (now >= 65) {
			res += (now - 65 + 10) << (4 * (len - i - 1));
		}
		else {
			res += (now - 48) << (4 * (len - i - 1));
		}
	}
	return res;
}

// 用于格式化接收用户输入的命令。   写得太丑陋了
int FormatInput(PUserCommand command, char processArgs[256]) {
	char tmpBuffer[1024] = { 0 };
	// 读取命令
	printf("调试命令: ");
	scanf_s("%[^\n]%*c", tmpBuffer, 1024); // %[^\n]遇到\n结束输入，%*c跳过一个字符（即跳过\n）
	// 解析命令  s 0x0     r 0x0 12
	int commandLen = strnlen_s(tmpBuffer, 1024);
	char* token = NULL; 
	char* nextToken = NULL;
	char seps[] = " ,\t\n";
	// 存放命令数组
	char* arrCommand[COMMANDLEN] = { 0 };
	int index = 0;

	token = strtok_s(tmpBuffer, seps, &nextToken);
	while (token != NULL) {
		if (index >= COMMANDLEN) break;
		arrCommand[index++] = token;
		// printf("'%s'\t", token);
		token = strtok_s(NULL, seps, &nextToken);
	}
	// printf("\n");
	// 构造数据
	if (index == COMMANDLEN) return 0;
	if (!arrCommand[0]) return 0;
	if (!_stricmp("w", arrCommand[0])) command->type = WRITE;
	if (!_stricmp("r", arrCommand[0])) command->type = READ;
	if (!_stricmp("set", arrCommand[0])) command->type = SET;
	if (!_stricmp("cls", arrCommand[0])) command->type = CLEAR;
	if (!_stricmp("si", arrCommand[0])) command->type = STEPIN;
	if (!_stricmp("so", arrCommand[0])) command->type = STEPOVER;
	if (!_stricmp("lp", arrCommand[0])) command->type = LISTPROCESS;
	if (!_stricmp("run", arrCommand[0])) command->type = RUN;
	if (!_stricmp("rm", arrCommand[0])) command->type = RMBREAKPOINT;
	if (!_stricmp("lsb", arrCommand[0])) command->type = LISTSFOTBREAKPOINT;
	if (!_stricmp("pr", arrCommand[0])) command->type = PRINTFREGS;
	if (!_stricmp("disasm", arrCommand[0])) command->type = DISASMCODE;
	if (!_stricmp("exit", arrCommand[0])) command->type = EXIT;
	if (!_stricmp("setd", arrCommand[0])) command->type = SETHARD;
	if (!_stricmp("da", arrCommand[0])) command->type = DEATTACH;
	if (!_stricmp("setm", arrCommand[0])) command->type = SETMEM;
		
	if (!command->type) return 0;

	// cls  si  so
	if (!arrCommand[1] && (command->type == CLEAR || command->type == STEPIN \
		|| command->type == STEPOVER || command->type == RUN || command->type == EXIT || \
		command->type == LISTSFOTBREAKPOINT || command->type == PRINTFREGS || \
		command->type == DEATTACH)) return 1;
	// error
	if (!arrCommand[1]) return 0;
	// error
	if ((command->type == CLEAR || command->type == STEPIN || \
		command->type == STEPOVER || command->type == RUN || command->type == EXIT || \
		command->type == LISTSFOTBREAKPOINT || command->type == PRINTFREGS || \
		command->type == DEATTACH) && arrCommand[1]) return 0;

	// address   set  w  r rm  lp
	command->u1.addr = HexStrToInt(arrCommand[1]);
	if (command->u1.addr == -2) return 0;
	if (command->u1.addr == -1) command->u1.addr = atoi(arrCommand[1]);
	// w  r lp
	if (!arrCommand[2] && (command->type == SET || command->type == LISTPROCESS || command->type == RMBREAKPOINT)) {
		if (command->type == LISTPROCESS) {
			sprintf_s(processArgs, 256, "%s", arrCommand[1]);
			command->u1.name = processArgs;
		}
		return 1;
	}
	if (!arrCommand[2] && !(command->type == SET || command->type == LISTPROCESS || command->type == RMBREAKPOINT)) return 0;
	if (arrCommand[2] && (command->type == SET || command->type == LISTPROCESS || command->type == RMBREAKPOINT)) return 0;


	if (command->type == READ || command->type == DISASMCODE) {
		command->u2.len = HexStrToInt(arrCommand[2]);
		if (command->u2.len == -2) return 0;
		if(command->u2.len == -1) command->u2.len = atoi(arrCommand[2]);
	}
	else if (command->type == WRITE) {
		command->u2.wdata = HexStrToInt(arrCommand[2]);
		if (command->u2.wdata == -2) return 0;
		if (command->u2.wdata == -1) command->u2.wdata = atoi(arrCommand[2]);
	}
	else if (command->type == SETHARD){
		command->u2.drx = HexStrToInt(arrCommand[2]);
		if (command->u2.drx == -2) return 0;
		if (command->u2.drx == -1) command->u2.drx = atoi(arrCommand[2]);
		if (command->u2.drx < 0 || command->u2.drx > 3) {
			return 0;
		}
	}
	else if (command->type == SETMEM) {
		command->u2.mtype = HexStrToInt(arrCommand[2]);
		if (command->u2.mtype == -2) return 0;
		if (command->u2.mtype == -1) command->u2.mtype = atoi(arrCommand[2]);
	}
	else {
		return 0;
	}
	return 1;
}

// 格式化打印输出,len是字节数
void PrintMem(PULONG32 ptr, LONG32 len, LONG32 printColums, PULONG32 realptr) {
	DWORD countByte = len / 4;
	ULONG32 nowV = 0;
	// 解析4个字节
	AnalysisInt val = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int flag = 0;
	for (LONG32 i = 0; i < countByte; i++, flag++) {
		if (flag % printColums == 0) printf("\n0x%p:\t", realptr);
		nowV = *ptr;
		// 解析4个字节,做复杂了，看自定义的ELFAGS结构体（debugger.h中）
		val = { nowV >> 4, nowV, nowV >> 0xc, nowV >> 8, nowV >> 0x14 ,nowV >> 0x10, nowV >> 0x1c, nowV >> 0x18 };
		printf("%X%X %X%X %X%X %X%X\t", val.low1, val.low2, val.high1, val.high2, val.Rlow1, val.Rlow2, val.Rhigh1, val.Rhigh2);
		ptr++;
		realptr++;
	}
	if (flag % printColums == 0) printf("\n0x%p:\t", realptr);
	int gapByte = len - countByte * 4;
	if (gapByte > 0) {
		nowV = *ptr;
		val = { nowV >> 4, nowV, nowV >> 0xc, nowV >> 8, nowV >> 0x14 ,nowV >> 0x10, nowV >> 0x1c, nowV >> 0x18 };
		for (int i = 0; i < 4; i++) {
			val = { nowV >> 4, nowV};
			if (i < gapByte) printf("%X%X ", val.low1, val.low2);
			else printf("%c%c ", '*', '*');
			nowV = nowV >> 8;
		}
	}
	printf("\n\n");
}

// 通过快照遍历当前进程,并输出进程列表
DWORD ListProcess(const char* name) {
	int flag = _stricmp(name, "all");
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) printf("快照句柄开启失败, errorCode: 0x%x\n", GetLastError());
	PROCESSENTRY32 pEntry = { 0 };
	pEntry.dwSize = sizeof(pEntry);
	Process32First(hSnapShot, &pEntry);
	char nowName[1024] = { 0 };
	do{
		sprintf_s(nowName, "%ws", pEntry.szExeFile);
		if (!flag || !_stricmp(name, nowName))
		{
			printf("父进程id: %d, 进程id: %d, 进程名: %ws\n", pEntry.th32ParentProcessID, pEntry.th32ProcessID, pEntry.szExeFile);
			return pEntry.th32ProcessID;
		}
		memset(nowName, 0, 1024);
	}while (Process32Next(hSnapShot, &pEntry));

	if(hSnapShot) CloseHandle(hSnapShot);
}

// 利用反汇编引擎，反汇编指令
void DisasmInput(csh handle, PUCHAR startBuffer, DWORD allSize, DWORD realptr) {
	cs_insn* insn; // 存储反汇编指令的信息
	// 成功反编译的指令数量
	size_t count = cs_disasm(handle, startBuffer, allSize, (DWORD)realptr, 0, &insn);
	if (!count) printf("disasm code failed, errorCode: 0x%x, maybe the length of disasm is too short\n", cs_errno(handle));
	printf("disasm from 0x%x, size: 0x%x, instructions's count that disasmed successfully : %d\n", (DWORD)realptr, allSize, count);
	for (int i = 0; i < count; i++) {
		int indexOrigin = 0;
		if (i == 0) printf("0x%I64x: === now  ==>\t\t", insn[i].address);
		else if (i == 1) printf("0x%I64x: === next ==>\t\t", insn[i].address);
		else printf("0x%I64x:\t\t\t", insn[i].address);
		for (indexOrigin; indexOrigin < insn[i].size; indexOrigin++) {
			printf("%02x ", insn[i].bytes[indexOrigin]);
		}
		printf("%8s%s %s\t\n", "\t\t", insn[i].mnemonic, insn[i].op_str);
	}

	// 释放cs_disasm在堆中申请的cs_insn空间
	cs_free(insn, count);
}

// 利用反汇编引擎，判断当前命令是否为call、重复命令
DWORD DisasmJudge(csh handle, PUCHAR startBuffer) {
	cs_insn* insn;
	// 反编译当前指令
	size_t count = cs_disasm(handle, startBuffer, 16, 0, 1, &insn);
	if (!_memicmp(insn[0].mnemonic, "call", 4) || \
		!_memicmp(insn[0].mnemonic, "rep", 3)) {
		// 如果非单行的指令，返回1
		return insn[0].size;
	}
	return 0;
}

// 打印寄存器的值
void PrintRegs(DWORD dwThreadId) {
	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, dwThreadId);
	CONTEXT context = { 0 };
	if (!hThread) {
		printf("打开线程句柄失败，无法获取寄存器信息\n");
		return;
	}
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	CloseHandle(hThread);

	EFLAGS eflag;
	eflag.eflags = context.EFlags;
	// 打印EFLAGS寄存器
	printf("EFLAGS:\tCF: %d, PF: %d, AF: %d, ZF: %d, SF: %d, TF: %d, IF: %d\n\
EFLAGS:\tDF: %d, OF: %d, IOPL: %d, NT: %d, RF: %d, VM: %d\n\
EFLAGS:\tAC: %d, VIF: %d, VIP: %d, ID: %d\n\n", \
eflag.u.CF, eflag.u.PF, eflag.u.AF, eflag.u.ZF, eflag.u.SF, eflag.u.TF, eflag.u.IF, \
eflag.u.DF, eflag.u.OF, eflag.u.IOPL, eflag.u.NT, eflag.u.RF, eflag.u.VM, \
eflag.u.AC, eflag.u.VIF, eflag.u.VIP, eflag.u.ID);
	// 打印通用寄存器
	printf("EAX: 0x%x, EBX: 0x%x, ECX: 0x%x, EDX: 0x%x\n\n", context.Eax, context.Ebx, context.Ecx, context.Edx);
	// 打印基址寄存器
	printf("EBP: 0x%x, EDI: 0x%x, ESI: 0x%x\n\n", context.Ebp, context.Edi, context.Esi);
	// 打印指针寄存器
	printf("ESP: 0x%x, EIP: 0x%x\n\n", context.Esp, context.Eip);
	// 打印段寄存器
	printf("SS: 0x%x, FS: 0x%x, GS: 0x%x, CS: 0x%x, DS: 0x%x, ES: 0x%x\n\n", \
		context.SegSs, context.SegFs, context.SegGs, context.SegCs, context.SegDs, context.SegEs);
	// 打印调试寄存器
	printf("DR0: 0x%x, DR1: 0x%x, DR2: 0x%x, DR3: 0x%x, DR6: 0x%x, DR7: 0x%x\n\n", \
		context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr6, context.Dr7);
}




#else

#endif
