#include "debugger.h"
#include <psapi.h>

extern int FormatInput(PUserCommand command, char processArgs[256]);
extern void PrintMem(PULONG32 ptr, LONG32 len, LONG32 printColums, PULONG32 realptr);
extern DWORD ListProcess(const char* name);

extern void DisasmInput(csh handle, PUCHAR startBuffer, DWORD allSize, DWORD realptr);
extern DWORD DisasmJudge(csh handle, PUCHAR startBuffer);
extern void PrintRegs(DWORD dwThreadId);


// ����ָ���
int DoCommand(PUserCommand command, const LPDEBUG_EVENT DebugEv);
// ������û�ָ���Ӧ����������
void DisasmByUserCommand(HANDLE hProcess, PUserCommand command);
// �������룬����
void StepInReuse(HANDLE hProcess, HANDLE hThread, CONTEXT context);
// ��ӡ��ʱ��Ϣ
void printTmpCodeInfo(HANDLE hProcess, CONTEXT context, const char* sign, int stepLen);
// �������úöϵ�
void recoverSoftBreakAgain(HANDLE hProcess, int startIndex);
// ��ʱ�ָ��ϵ�
void tmpRecoverSoftwareBreakPoint(PUserCommand command, HANDLE hProcess, DWORD startIndex);


// ȫ�ֶϵ�����
static LIST_ENTRY breakArray = { 0 };
// ��ʼ�����������
static csh cshHandle = NULL;
// ��ʼ���Ƿ�������Եı�־ 
static int debugFlag = 1;

// һ�����ָ�512������ϵ㣻������ʱ�ָ��ϵ�֮��
#define MAX_TMP_SOFT_BREAK 512
#define MAX_TMP_HARD_BREAK 4
#define MAX_TMP_MEME_BREAK 512
static PBreakPointInfo globalTmpSoftwareBreakpoint;
static int count = 0;

static PBreakPointInfo globalTmpMemoryBreakpoint;
static int mcount = 0;

// ��ʱ�¶ϵ㣬��Զ֮����ʱ��һ���ϵ�
static BreakPointInfo tmpUseSoftBreak;
// ��ʱ�ָ��ľֲ�Ӳ���ϵ�
static PHardBreakPointInfo globalTmpHardBreakPoint;
static int hardCount = 0;

// ��ǰ�Ǹ��ӽ��̽��е��Ի��Ǵ������̵���
static int attchOrCreate = 0;
// deattach
static int deAttachNow = 0;

// �ڴ�ϵ㣬��һ��������ɶ
static int lastCommand = 0;


int main() {
	// �������Խ���
	int ret = CreateForDebug((char*)"D:\\tools\\Visual Studio\\projects\\easyDebugger\\Debug\\vim.exe");
	// int ret = DebugActiveProcess(ListProcess("vim2.exe"));
	attchOrCreate = 0;
	if (!ret) {
		printf("�������˳�, errorCode: %d\n", GetLastError());
		return 0;
	}
	// ��ʼ�����������
	cs_err errNo;
	if ((errNo = cs_open(CS_ARCH_X86, CS_MODE_32, &cshHandle)) != CS_ERR_OK) {
		printf("������������ʧ��, errorCode: 0x%x\n", errNo);
		return 0;
	}
	// ��ʼ���ϵ���ʱ�洢�ռ�
	globalTmpSoftwareBreakpoint = (PBreakPointInfo)malloc(sizeof(BreakPointInfo) * MAX_TMP_SOFT_BREAK);
	if (!globalTmpSoftwareBreakpoint) {
		printf("����ϵ���ʱ�洢�ռ��ʼ��ʧ��\n");
		return 0;
	}
	memset(globalTmpSoftwareBreakpoint, 0, sizeof(BreakPointInfo) * MAX_TMP_SOFT_BREAK);
	// ��ʼ���ڴ�ϵ���ʱ�洢�ռ�
	globalTmpMemoryBreakpoint = (PBreakPointInfo)malloc(sizeof(BreakPointInfo) * MAX_TMP_MEME_BREAK);
	if (!globalTmpMemoryBreakpoint) {
		printf("�ڴ�ϵ���ʱ�洢�ռ��ʼ��ʧ��\n");
		return 0;
	}
	memset(globalTmpMemoryBreakpoint, 0, sizeof(BreakPointInfo) * MAX_TMP_MEME_BREAK);

	globalTmpHardBreakPoint = (PHardBreakPointInfo)malloc(sizeof(HardBreakPointInfo) * MAX_TMP_HARD_BREAK);
	if (!globalTmpHardBreakPoint) {
		printf("Ӳ���ϵ���ʱ�洢�ռ��ʼ��ʧ��\n");
		return 0;
	}
	memset(globalTmpHardBreakPoint, 0, sizeof(HardBreakPointInfo) * MAX_TMP_HARD_BREAK);
	// ��ʼ����ʱ�ϵ�Ŀռ�
	memset(&tmpUseSoftBreak, 0, sizeof(BreakPointInfo));
	// ��ʼ���û�����ռ�
	PUserCommand command = (PUserCommand)malloc(sizeof(UserCommand));
	if (!command) {
		printf("�û�����ռ��ʼ��ʧ��\n");
		return 0;
	}
	memset(command, 0, sizeof(UserCommand));	
	// ���������¼�����
	DEBUG_EVENT DebugEvent = { 0 };
	EnterDebugLoop(command, &DebugEvent);

	// �����û�����ռ���
	free(command);
	// ���շ����������
	cs_close(&cshHandle);
}

// ����ָ���
int DoCommand(PUserCommand command, const LPDEBUG_EVENT DebugEv) {
	int retFlag = 1;
	DWORD pid = DebugEv->dwProcessId;
	DWORD tid = DebugEv->dwThreadId;
	// ��ʱ�ָ��ϵ�
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) printf("��ȡ���̾��ʧ�ܣ���ʱ�ָ��ϵ㡢��д�ڴ������ʧЧ\n\n");
	// ����������߳�������
	HANDLE hThread = NULL;
	hThread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
	CONTEXT context = { 0 };
	int stepLen = 0;
	// �ڴ�ϵ����
	DWORD memFlag = 0;
	if (!hThread) printf("��ȡ�߳�������ʧ�ܣ������߳������Ĳ�����ʧЧ\n\n");
	else {
		context.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hThread, &context);
		// ���������ϵ㣬��ô���ᵼ��eipǰ��1λ������ִ��ǰ��Ҫ���ȥ��
		if (DebugEv->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
			if (DebugEv->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
				stepLen = 1;
			else if (DebugEv->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
				memFlag = 1;
			// ��ӡ��һ��ָ����Ϣ
			if (command->type == STEPIN || command->type == STEPOVER || command->type == RUN)
				printTmpCodeInfo(hProcess, context, "setp", stepLen);
		}
		// �ָ���ʱȡ����Ӳ���ϵ�
		for (int i = 0; i < MAX_TMP_HARD_BREAK; i++) {
			DWORD dr7 = context.Dr7;
			// ��ʱ�����Ƕ��߳�
			if(globalTmpHardBreakPoint[i].addr)
				dr7 |= (DWORD)(1 << globalTmpHardBreakPoint[i].drx);
			memset(&globalTmpHardBreakPoint[i], 0, sizeof(HardBreakPointInfo));
			context.Dr7 = dr7;
		}
		SetThreadContext(hThread, &context);
	}
	
	// ����������ദ��
	switch (command->type) {
	case WRITE:
	{
		// д�ڴ�Ӧ���ǵȳ�����
		break;
	}
	case DEATTACH:
	{
		if (!hThread) break;
		// �޸�eip   �ǵð�������ú�setpLen��ֵ
		context.Eip -= stepLen;
		// ����Trapλ
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		// �������Ӳ���ϵ�
		PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
		pDr7->L0 = 0;
		pDr7->L1 = 0;
		pDr7->L2 = 0;
		pDr7->L3 = 0;
		SetThreadContext(hThread, &context);
		// �����������ϵ�
		CleanAllSoftwareBreakPoint(pid);
		// �˳��û�����ѭ��
		retFlag = 0;
		// �˳������¼��ȴ������
		debugFlag = 0;
		// �˳����ӵĽ���
		deAttachNow = 1;
		break;
	}
	case READ:
	{
		PBYTE data = (PBYTE)malloc(command->u2.len);
		if (!data) {
			printf("������ʱ�ռ�ʧ�� ���ڴ�\n\n");
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
		// �޸�eip
		context.Eip -= stepLen;
		// ����Trapλ
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 1;
		context.EFlags = tmpEflags.eflags;
		// �����ǰ��Ӳ���ϵ㵼�µ��쳣����ôҲӦ����ʱ�޸�Ӳ���ϵ�
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
		}// �޸ĺ󣬼ǵðѶϵ����������ϣ�����
		// ����������
		SetThreadContext(hThread, &context);
		// �жϲ�������ʱ����ϵ�
		StepInReuse(hProcess, hThread, context);
		if (command->u1.addr != 1) {
			lastCommand = 0;
		}
		// ��ʱ�ָ��ڴ�ϵ�   accessFlag��־���ڴ�ϵ㵼�µ��쳣����ǰ��Ҫ��ʱ�ָ�
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
		// ��ʱ��ֵֻ���� 0 1 2 3
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
		// ����ǰ���߳�������
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
		// ����ϵ�ʵ�ֲ���
		// ͨ���ж��Ƿ�Ϊcallָ��ظ���ָ����ȷ����һ���ϵ��λ��
		// �������ʹ�� ��ʱ�ϵ����� ����ô�ÿ���step in�� ������ʱ�ϵ�
		int step = 0;
		// ��ȡ�Ѿ����������
		PBYTE data = (PBYTE)malloc(16);
		if (!data) {
			printf("������ʱ�ռ�ʧ�� ����\n\n");
			break;
		}
		memset(data, 0, 16);
		// �޸�eip
		context.Eip -= stepLen;
		// ����Trapλ
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		if(context.Eip) ReadProcessMemory(hProcess, (LPCVOID)context.Eip, data, 16, 0);
		if ((step = DisasmJudge(cshHandle, data))) {
			tmpEflags.u.TF = 0;
			context.EFlags = tmpEflags.eflags;
			// ����һ����ʱ�Ķϵ�
			tmpUseSoftBreak.breakAddr = context.Eip + step;
			// һ���ǵ�ԭֵ��Ҫ���¶�һ�£���Ϊ��ʱ�ϵ�����һ��ָ�
			ReadProcessMemory(hProcess, (LPCVOID)tmpUseSoftBreak.breakAddr, data, 16, 0);
			tmpUseSoftBreak.origin = data[0];
			// ������ʱ��cc�ϵ�
			WriteProcessMemory(hProcess, (LPVOID)tmpUseSoftBreak.breakAddr, "\xCC", 1, 0);
		}
		else {
			// ����call�Լ��ظ��������ߵ�������Ĳ��輴��
			tmpEflags.u.TF = 1;
			context.EFlags = tmpEflags.eflags;
		}
		// �����ǰ��Ӳ���ϵ㵼�µ��쳣����ôҲӦ����ʱ�޸�Ӳ���ϵ�
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
		}// �޸ĺ󣬼ǵðѶϵ����������ϣ�����
		SetThreadContext(hThread, &context);
		// �������룬���ã������int 3 ����ϵ�Ļ���������ʱ�ָ��ϵ㡣ֱ����һ���쳣����ָ���ʱ�ϵ�
		// �������int 3����ϵ㣬���᲻����
		StepInReuse(hProcess, hThread, context);
		lastCommand = 0;
		// ��ʱ�ָ��ڴ�ϵ�   accessFlag��־���ڴ�ϵ㵼�µ��쳣����ǰ��Ҫ��ʱ�ָ�
		if (command->u1.addr != 1 && memFlag) {
			AutoHandleMemoryException(DebugEv, hProcess, 0);
		}
		retFlag = 0;
		break;
	}
	case RUN:
	{
		// �������ϵ��Ӳ���ϵ����һ��Ļ���Ӧ�û�����
		if (!hThread) break;
		// �޸�eip
		context.Eip -= stepLen;
		// ��0 tpλ
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		if (stepLen == 1) {
			UserCommand command;
			command.u1.addr = context.Eip;
			command.u2.len = 1;
			// ��ǰ������ϵ�
			// ��ʱ�ָ�����ϵ�   ������ÿ���쳣������ʱ�ϵ�����Ϊ0
			tmpRecoverSoftwareBreakPoint(&command, hProcess, 0);
		}// ��Ҫ����Ӳ���ϵ���ڴ�ϵ�
		// �����ǰ��Ӳ���ϵ㵼�µ��쳣����ôҲӦ����ʱ�޸�Ӳ���ϵ�   ����Ҫrun���ε����������Ӧ�ò������������ ��һ��
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
		}// �޸ĺ󣬼ǵðѶϵ����������ϣ�����

		// �ָ��߳�������
		SetThreadContext(hThread, &context);
		// printf("count: %d\n\n", count);
		// runָ�ָʾ�����ڴ�ϵ㵽�쳣������
		lastCommand = 1;
		// ��ʱ�ָ��ڴ�ϵ�   accessFlag��־���ڴ�ϵ㵼�µ��쳣����ǰ��Ҫ��ʱ�ָ�
		if (command->u1.addr != 1 && memFlag) {
			AutoHandleMemoryException(DebugEv, hProcess, 0);
		}
		// ������ǰ�û�ָ��Ự
		retFlag = 0;
		break;
	}
	case EXIT: 
	{
		if (!hThread) break;
		// �޸�eip   �ǵð�������ú�setpLen��ֵ
		context.Eip -= stepLen;
		// ����Trapλ
		EFLAGS tmpEflags;
		tmpEflags.eflags = context.EFlags;
		tmpEflags.u.TF = 0;
		context.EFlags = tmpEflags.eflags;
		// �������Ӳ���ϵ�
		PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
		pDr7->L0 = 0;
		pDr7->L1 = 0;
		pDr7->L2 = 0;
		pDr7->L3 = 0;
		SetThreadContext(hThread, &context);
		// �����������ϵ�
		CleanAllSoftwareBreakPoint(pid);
		retFlag = 0;
		break;
	}
	case LISTPROCESS:
	{
		// ��Ϊcommand->u1.nameֻ��һ��PCHAR������
		// ��ָ���������main��formatInput�ռ��и��ƹ����ģ���main����֡���Ǿֲ�����, ��ʹ��ʱ�ᷢ��ֵ����ȷ�ˡ�
		// �����ַ�����������ʱ��һ��Ҫע�� �ַ����� ��û�������õ����ء���û���������롣
		ListProcess(command->u1.name);
		break; 
	}
	default:
		printf("Wrong ommand. \n w => write, r => READ, set => SET Breakpoint\n \
cls => CLEAR, si => STEPIN, so => STEPOVER, lp => LIST Process\n \
run => RUN, exit => EXIT\n");
	}

	// �ͷž��
	if(hProcess) CloseHandle(hProcess);
	if(hThread) CloseHandle(hThread);
	return retFlag;
}

// �������̣����е���
int CreateForDebug(char* imagePath) {
	STARTUPINFOA startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	// �����Ե�ǰ���̣����������ӽ���; ������ǰ���̽�����DebugPort�д��Ŀ����̵ĵ��Զ�������
	BOOL ret = CreateProcessA(NULL, imagePath, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, \
		&startupInfo, &processInformation);
	if (!ret) {
		printf("�������Խ���%sʧ�ܣ�errorCode: 0x%x\n", imagePath, GetLastError());
		return 0;
	}
	if (processInformation.hProcess) CloseHandle(processInformation.hProcess);
	if (processInformation.hThread) CloseHandle(processInformation.hThread);
	return 1;
}

// ������ѭ��
void EnterDebugLoop(PUserCommand command, const LPDEBUG_EVENT DebugEv)
{
	// ģ����
	TCHAR name[1024] = { 0 };
	// �Ƿ�Ϊϵͳ�ϵ�
	int flag = 0;
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

	for (;debugFlag;)
	{
		WaitForDebugEvent(DebugEv, INFINITE);
		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// �����������ʱ�Ķϵ㣬��ô��Ҫ����ָ�Ϊ�ϵ�  ֮���Է��ڴ˴��ָ���
			// �Ǳ�֤����һ���û�����ǰ����ʱ�ϵ�һ��ȫ���õ��ָ�
			if (count) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("��Ϊ�򿪽��̾��ʧ�ܣ����»ָ���ʱ�ϵ�cc�Ĳ���ʧ��\n\n");
					break;
				}
				// ��ضϵ�   ���û� run �����recoverSoftBreakAgain�������
				// ����ϸ�ɶԳ��ֵĻ����˴�һ��ֻ����һ����ʱ�ϵ�� ��ʱ�ָ��ϵ㡣
				recoverSoftBreakAgain(hProcess, 0);
				CloseHandle(hProcess);
			}
			// �ָ���ʱ�ϵ�ԭֵ
			if (tmpUseSoftBreak.breakAddr) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("��Ϊ�򿪽��̾��ʧ�ܣ����»ָ���ʱ�ϵ�ԭֵ�Ĳ���ʧ��\n\n");
					break;
				}
				WriteProcessMemory(hProcess, (LPVOID)tmpUseSoftBreak.breakAddr, \
					(LPCVOID)&tmpUseSoftBreak.origin, 1, 0);
				CloseHandle(hProcess);
			}
			// �ָ���ʱ����ϵ�ԭֵ
			// �����ǰ�Ƿ����쳣��Ӧ���жϵ�ǰ�Ƿ����¶ϵ�ĵط������������ôӦ��������ǰָ��
			if (mcount) {
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("��Ϊ�򿪽��̾��ʧ�ܣ����»ָ��ڴ�ϵ�Ĳ���ʧ��\n\n");
					break;
				}
				// �Ƚ������ڴ�ִ�жϵ���޸�
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
				// �쳣������ַ
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, DebugEv->dwProcessId);
				if (!hProcess) {
					printf("��Ϊ�򿪽��̾��ʧ�ܣ����»ָ��ڴ�ϵ�Ĳ���ʧ��\n\n");
					break;
				}
				// �Ƕϵ��ַ�������޸��ڴ�ҳ����
				int ret = AutoHandleMemoryException(DebugEv, hProcess, 1);
				CloseHandle(hProcess);
				if (ret) {
					// �ڴ�ϵ㴦���ˣ��û��ӹ��쳣
					printf("\n�ڴ�ϵ㴥��:0x%x\n", DebugEv->u.Exception.ExceptionRecord.ExceptionInformation[1]);
					UserHandleException(command, DebugEv);
					lastCommand = 0;
				}
				else {
					// ������������ִ�У������쳣�Զ��޸��ϵ㣬��֤�´��ٴδ����ڴ�ϵ�
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
				// ϵͳ�ϵ�
				if (!flag) {
					// ϵͳ�ϵ㲻�����û��������򽫻��ڴ˴�ͣ�Ͳ�ǰ��
					printf("ϵͳ�ϵ㴥����in 0x%x\n\n", (DWORD)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
					flag++;
					if (attchOrCreate) {
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, DebugEv->dwThreadId);
						if (!hThread) {
							printf("��Ϊ���߳̾��ʧ�ܣ�����attch���̵ĵ�һ�����öϵ����ʧ��\n\n");
							break;
						}
						CONTEXT context;
						context.ContextFlags = CONTEXT_ALL;
						GetThreadContext(hThread, &context);
						// ���õ�һ���ϵ�
						SetSoftwareBreakPoint((PVOID)context.Eip, DebugEv->dwProcessId);
						CloseHandle(hThread);
					}
					break;
				}
				// ����������ϵ���
				printf("����ϵ㴥����in 0x%x\n\n", (DWORD)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
				// ���������쳣�����û�
				UserHandleException(command, DebugEv);
				break; 
			}
			case EXCEPTION_DATATYPE_MISALIGNMENT: 
				printf("DATATYPE_MISALIGNMENT\n");
				break;
			case EXCEPTION_SINGLE_STEP:
			{
				// ����runָ�����һ��ͣһ�£�
				if (lastCommand) {
					// ��ǰ�ǲ���Ӳ���ж�
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, DebugEv->dwThreadId);
					if (!hThread) {
						printf("δ���������̣߳��޷��ж�Ӳ���еĴ������\n\n");
						break;
					}
					CONTEXT t;
					t.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &t);
					DWORD dr6 = t.Dr6;
					if (dr6 & 0x0f) {
						printf("\nӲ���ϵ㴥��,DR0:0x%x,DR1:0x%x,DR2:0x%x,DR3:0x%x\n", t.Dr0,t.Dr1,t.Dr2,t.Dr3);
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
				printf("�����Խ��̻�ȡ Ctrl + c �ź�\n");
				break;
			default:
				break;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			// dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
			// printf("�̴߳���\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			// dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
		{
			printf("����%s����, ��%p�����öϵ㡣\n",\
				(char *)DebugEv->u.CreateProcessInfo.lpImageName, DebugEv->u.CreateProcessInfo.lpStartAddress);
			// ���õ�һ���ϵ�
			SetSoftwareBreakPoint(DebugEv->u.CreateProcessInfo.lpStartAddress, DebugEv->dwProcessId);
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code. 
			// dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
			printf("�߳��˳�\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code. 
			// dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
			// �������
			DebugActiveProcessStop(DebugEv->dwProcessId);
			printf("���̵��Զ����˳�\n");
			debugFlag = 0;
			break;
		case LOAD_DLL_DEBUG_EVENT:
		{
			// ģ����
			// ���Խ����еĵ�ַ
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
			printf("dllж��\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			// dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
			// �����Խ��̿��������������Ϣ���������ڴ˴�����
			// printf("��������ַ����¼�\n");
			break;
		case RIP_EVENT:
			// dwContinueStatus = OnRipEvent(DebugEv);
			printf("RIP�¼�\n");
			break;
		}
		// Resume executing the thread that reported the debugging event. 
		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dwContinueStatus);
		if (deAttachNow) {
			// ����˳��˵�����
			DebugActiveProcessStop(DebugEv->dwProcessId);
		}
	}
}

// �û������쳣
int UserHandleException(PUserCommand command, const LPDEBUG_EVENT DebugEv) {
	// �ַ�������ר����ʱ�洢�ռ�
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

// ��������ϵ�
int SetSoftwareBreakPoint(PVOID addr, DWORD pid) {
	// �򿪱����Խ���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("�򿪱����Խ���ʧ��\n\n");
		return 0;
	}
	// ��һ���ֽڣ�����������Ȼ��д0xcc��
	BreakPointInfo* bp = (BreakPointInfo*)malloc(sizeof(BreakPointInfo));
	if (!bp) {
		printf("��ʼ���ϵ���Ϣʧ��\n\n");
		return 0;
	}
	memset(bp, 0, sizeof(BreakPointInfo));
	bp->breakAddr = (DWORD)addr;
	bp->bptype = SOFTWAREBP;

	ReadProcessMemory(hProcess, addr, &bp->origin, 1, 0);
	// PrintMem((PULONG32)p, 100, 4, ((PULONG32)addr));
	WriteProcessMemory(hProcess, addr, "\xCC", 1, 0);  // "\xCC" ��������ַ���������ָ�룬Ȼ���ȡ��ֵ0xcc

	CloseHandle(hProcess);

	// ���ϵ��������
	if (!breakArray.Flink) insertFirstNode(&bp->pointer);
	else insertListHeader(&bp->pointer, SOFTWAREBP);

	return 1;
}

// ����Ӳ���ϵ�
int SetHardBreakPoint(PVOID addr, DWORD drx, PCONTEXT context, DWORD len, DWORD type, BOOL local) {
/**
	����DR0-DR3��ַ��ָ��λ�õĶϵ�����(RW0-RW3)��ϵ㳤��(LEN0-LEN3)��״̬�������£�
		00��ִ��         01��д��        11����д
		00��1�ֽ�        01��2�ֽ�       11��4�ֽ�
	����Ӳ��ִ�жϵ�ʱ������ֻ��Ϊ1(LEN0-LEN3����Ϊ0ʱ��ʾ����Ϊ1)
	���ö�д�ϵ�ʱ���������Ϊ1����ַ����Ҫ���룬�������Ϊ2�����ַ������2�����������������Ϊ4�����ַ������4����������
*/
	int offset = local ? 0 : 1;
	if (context->Dr7 & 1 << ((2 * drx) + offset)) {
		printf("DR%d�Ĵ�������ʹ����\n\n", drx);
		return 0;
	}
	if (len != 0 && type == 0) {
		printf("����Ӳ��ִ�жϵ�ʱ������ֻ��Ϊ1!(�� len == 0)\n\n");
		return 0;
	}
	// ���Ҳ��һ�ָ�ֵλ�İ취
	PDBG_REG7 pDr7 = (PDBG_REG7)&context->Dr7;
	// ��ʵ����Ҫ�� �ֲ�Ӳ���ϵ㻹��ȫ��Ӳ���ϵ�;  ���Ƕϵ��� 1bit 2bit 4bit
	// ���ϵ���ȫ��ʱ���޷���ȡ�����¼���
	// �ֲ�Ӳ���ϵ�����ʵ��stepover��ֱ����

	// ��ͬ���ȵ�Ӳ���ϵ���Ҫ�޸��¶ϵ�ĵ�ַ
	//  00 1bit    01 2bit    11 4bit
	if (len == 1) {
		addr = (PVOID)((DWORD)addr - (DWORD)addr % 2);
	}
	else if (len == 3) {
		addr = (PVOID)((DWORD)addr - (DWORD)addr % 4);
	}

	// Ŀǰȫ��ʵ��ȫ��Ӳ���ϵ�
	switch (drx) {
	case 0:
	{
		context->Dr0 = (DWORD)addr;
		// 00 ִ�У� 01 д�� 11��д  =>  type == 0 / 1 / 3
		pDr7->RW0 = type;
		pDr7->LEN0 = len;
		// ȫ�ֶϵ㻹�Ǿֲ��ϵ�
		if (local) pDr7->L0 = 1;
		else pDr7->G0 = 1;
		break;
	}
	case 1:
	{
		context->Dr1 = (DWORD)addr;
		// 00 ִ�У� 01 д�� 11��д  =>  type == 0 / 1 / 3
		pDr7->RW1 = type;
		pDr7->LEN1 = len;
		// ȫ�ֶϵ㻹�Ǿֲ��ϵ�
		if (local) pDr7->L1 = 1;
		else pDr7->G1 = 1;
		break;
	}
	case 2:
	{
		context->Dr2 = (DWORD)addr;
		// 00 ִ�У� 01 д�� 11��д  =>  type == 0 / 1 / 3
		pDr7->RW2 = type;
		pDr7->LEN2 = len;
		// ȫ�ֶϵ㻹�Ǿֲ��ϵ�
		if (local) pDr7->L2 = 1;
		else pDr7->G2 = 1;
		break;
	}
	case 3:
	{
		context->Dr3 = (DWORD)addr;
		// 00 ִ�У� 01 д�� 11��д  =>  type == 0 / 1 / 3
		pDr7->RW3 = type;
		pDr7->LEN3 = len;
		// ȫ�ֶϵ㻹�Ǿֲ��ϵ�
		if (local) pDr7->L3 = 1;
		else pDr7->G3 = 1;
		break;
	}
	}
	return 1;
}

// �����ڴ�ϵ�
void SetMemoryBreakPoint(PVOID addr, DWORD pid, DWORD type) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("��ȡ���̾��ʧ�ܣ��޷����������ڴ���ʶϵ�\n\n");
		return;
	}
	// ��һ���ֽڣ�����������Ȼ��д0xcc��
	BreakPointInfo* bp = (BreakPointInfo*)malloc(sizeof(BreakPointInfo));
	if (!bp) {
		printf("��ʼ���ϵ���Ϣʧ��\n\n");
		return;
	}
	memset(bp, 0, sizeof(BreakPointInfo));
	bp->breakAddr = (DWORD)addr;
	bp->bptype = MEMORYBP;
	DWORD originalProtect;
	if (type == 0) {
		// ִ�жϵ�
		bp->mtype = 0;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_READWRITE, &bp->originalProtect);
	}
	else if (type == 1) {
		// д�ϵ�
		bp->mtype = 1;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_EXECUTE_READ, &bp->originalProtect);
	}
	else if (type == 2) {
		// ���ϵ㡢���ʶϵ�
		bp->mtype = 2;
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)addr & 0x0fffff000), 0x1000, PAGE_NOACCESS, &bp->originalProtect);
	}

	CloseHandle(hProcess);
	// ��һ�����ҳ����û�нڵ��Ѿ������
	BreakPointInfo t;
	if (inThePageLinkList((DWORD)addr, &t, MEMORYBP)) {
		printf("��ҳ�������ڴ�ϵ㣬���ڲ�ѯҳ������:0x%x,��ԭʼҳ������:0x%x, �Ѿ����²���ϵ�\n\n", bp->originalProtect, t.originalProtect);
		bp->originalProtect = t.originalProtect;
	}
	// ���ϵ��������
	if (!breakArray.Flink) insertFirstNode(&bp->pointer);
	else insertListHeader(&bp->pointer, MEMORYBP);
}

// �����׽ڵ�
void insertFirstNode(LIST_ENTRY* node) {
	breakArray.Flink = node;
	breakArray.Blink = node;
	node->Flink = node;
	node->Blink = node;
}

// ͷ�巨
void insertListHeader(LIST_ENTRY* node, BreakPointType bptype) {
	DWORD offset = (DWORD) & (((BreakPointInfo*)0)->pointer) - 0;
	BreakPointInfo* nowNode = (BreakPointInfo*)((DWORD)node - offset);
	if (inTheLinkList(nowNode->breakAddr, 0, bptype)) {
		if(nowNode->bptype == SOFTWAREBP)
			printf("�����ظ�������ϵ�0x%x���¶ϵ�, �ϵ���ֵ: 0x%x\n\n", nowNode->breakAddr, nowNode->origin);
		else if(nowNode->bptype == MEMORYBP)
			printf("�����ظ����ڴ�ϵ�0x%x���¶ϵ�, ҳ��ԭ����: 0x%x\n\n", nowNode->breakAddr, nowNode->originalProtect);
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

// ɾ��ָ���ϵ�
void deleteBreakpoint(PVOID addr, DWORD pid) {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	// �򿪱����Խ���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("�򿪱����Խ���ʧ�� �ͷ�\n\n");
		return;
	}

	DWORD offset = (DWORD) & ((PBreakPointInfo)0)->pointer - 0;
	PBreakPointInfo tmp = (PBreakPointInfo)(DWORD(start) - offset);

	if (start == NULL || end == NULL) {
		printf("��������ϵ�\n\n");
		return;
	}

	if (start == end && tmp->breakAddr == (DWORD)addr) {
		breakArray.Flink = 0;
		breakArray.Blink = 0;
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// �ͷŽڵ�
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[����ϵ�] �ͷŶϵ�final: 0x%x, �ϵ�ԭֵ: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			if (!inThePageLinkList(tmp->breakAddr, 0, MEMORYBP)) {
				// ��ҳ����û���ڴ�ϵ��ˣ��������ûָ�
				DWORD t = 0;
				VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			}
			printf("[�ڴ�ϵ�] �ͷŶϵ�final: 0x%x, ҳ��ԭ����: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		free(tmp);
		return;
	}

	do {
		tmp = (PBreakPointInfo)(DWORD(start) - offset);

		if (tmp->breakAddr == (DWORD)addr) {
			// ժ���˽ڵ�
			PLIST_ENTRY ltmp = start;
			ltmp->Blink->Flink = ltmp->Flink;
			ltmp->Flink->Blink = ltmp->Blink;
			if (breakArray.Flink == ltmp) breakArray.Flink = ltmp->Flink;
			if (breakArray.Blink == ltmp)  breakArray.Blink = ltmp->Blink;
			// �ͷŽڵ�
			if (tmp->bptype == SOFTWAREBP) {
				WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
				printf("[����ϵ�] �ͷŶϵ�final: 0x%x, �ϵ�ԭֵ: 0x%x\n\n", tmp->breakAddr, tmp->origin);
			}
			else if (tmp->bptype == MEMORYBP) {
				if (!inThePageLinkList(tmp->breakAddr, 0, MEMORYBP)) {
					// ��ҳ����û���ڴ�ϵ��ˣ��������ûָ�
					DWORD t = 0;
					VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
				}
				printf("[�ڴ�ϵ�] �ͷŶϵ�final: 0x%x, ҳ��ԭ����: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
			}
			free(tmp);
			break;
		}
		start = start->Flink;
	} while (start != end->Flink);
	CloseHandle(hProcess);
}

// �鿴�ϵ�
void ListSoftwareBreakPoint() {
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	if (!start || !end) {
		printf("���޶ϵ�\n\n");
		return;
	}
	do {
		DWORD offset = (DWORD)&(((BreakPointInfo*)0)->pointer) - 0;
		BreakPointInfo *tmp = (BreakPointInfo*)((DWORD)start - offset);
		
		if(tmp->bptype == SOFTWAREBP)
			printf("[����ϵ�] �ϵ��ַ: 0x%x, �ϵ�ԭֵ: 0x%x\n", tmp->breakAddr, tmp->origin);
		else if(tmp->bptype == MEMORYBP)
			printf("[�ڴ�ϵ�] �ϵ��ַ: 0x%x, �ڴ�ԭ����: 0x%x\n", tmp->breakAddr, tmp->originalProtect);
		start = start->Flink;
	} while (start != end->Flink);
	printf("\n");
}

// ������������ϵ�\�ڴ�ϵ�
void CleanAllSoftwareBreakPoint(DWORD pid) {
	// �򿪱����Խ���
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess) {
		printf("�򿪱����Խ���ʧ��\n");
		return;
	}
	LIST_ENTRY* start = breakArray.Flink;
	LIST_ENTRY* end = breakArray.Blink;

	DWORD offset = (DWORD) & ((PBreakPointInfo)0)->pointer - 0;
	PBreakPointInfo tmp = (PBreakPointInfo)(DWORD(start) - offset);

	if (start == NULL || end == NULL) {
		printf("��������������ϵ�\n\n");
		return;
	}

	// ֻ��һ���ڵ�
	if (start == end) {
		breakArray.Flink = 0;
		breakArray.Blink = 0;
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// �ͷŽڵ�
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[����ϵ�] �ͷŶϵ�final: 0x%x, �ϵ�ԭֵ: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			DWORD t = 0;
			VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			printf("[�ڴ�ϵ�] �ͷŶϵ�final: 0x%x, ҳ��ԭ����: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		free(tmp);
		return;
	}

	do {
		tmp = (PBreakPointInfo)(DWORD(start) - offset);
		// ɾ������Զ��ͷ�ڵ㣬���ֻ��Ҫ�޸�breakArray����ǰָ��
		breakArray.Flink = tmp->pointer.Flink;
		tmp->pointer.Flink->Blink = tmp->pointer.Blink;
		tmp->pointer.Blink->Flink = tmp->pointer.Flink;

		// �ͷŽڵ�
		if (tmp->bptype == SOFTWAREBP) {
			WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
			printf("[����ϵ�] �ͷŶϵ�: 0x%x, �ϵ�ԭֵ: 0x%x\n\n", tmp->breakAddr, tmp->origin);
		}
		else if (tmp->bptype == MEMORYBP) {
			DWORD t = 0;
			VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
			printf("[�ڴ�ϵ�] �ͷŶϵ�: 0x%x, ҳ��ԭ����: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
		}
		start = start->Flink;
		free(tmp);
	} while (start != end);

	breakArray.Flink = 0;
	breakArray.Blink = 0;
	tmp = (PBreakPointInfo)(DWORD(start) - offset);
	// �ͷŽڵ�
	if (tmp->bptype == SOFTWAREBP) {
		WriteProcessMemory(hProcess, (LPVOID)tmp->breakAddr, (LPCVOID)&tmp->origin, 1, 0);
		printf("[����ϵ�] �ͷŶϵ�final2: 0x%x, �ϵ�ԭֵ: 0x%x\n\n", tmp->breakAddr, tmp->origin);
	}
	else if (tmp->bptype == MEMORYBP) {
		DWORD t = 0;
		VirtualProtectEx(hProcess, (LPVOID)(tmp->breakAddr & 0xfffff000), 0x1000, tmp->originalProtect, &t);
		printf("[�ڴ�ϵ�] �ͷŶϵ�final2: 0x%x, ҳ��ԭ����: 0x%x\n\n", tmp->breakAddr, tmp->originalProtect);
	}
	free(tmp);
	CloseHandle(hProcess);
}

// ��ʱ�ָ��ϵ�
void tmpRecoverSoftwareBreakPoint(PUserCommand command, HANDLE hProcess, DWORD startIndex) {
	// �ǵ÷����֮ǰ�ָ��ϵ�ֵ
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
	// �ָ�����
	for (int i = startIndex; i < count; i++) {
		BreakPointInfo tmp = globalTmpSoftwareBreakpoint[i];
		if (tmp.breakAddr)
			WriteProcessMemory(hProcess, (LPVOID)tmp.breakAddr, &(tmp.origin), 1, 0);
	}
}

// �������úöϵ�
void recoverSoftBreakAgain(HANDLE hProcess, int startIndex) {
	int i = startIndex;
	// �ָ��ϵ�
	for (startIndex; startIndex < count; startIndex++) {
		BreakPointInfo tmp = globalTmpSoftwareBreakpoint[startIndex];
		memset(&globalTmpSoftwareBreakpoint[startIndex], 0, sizeof(BreakPointInfo));
		if (tmp.breakAddr)
			WriteProcessMemory(hProcess, (LPVOID)tmp.breakAddr, "\xCC", 1, 0);
	}
	count = i;
}

// ������û�ָ���Ӧ����������
void DisasmByUserCommand(HANDLE hProcess, PUserCommand command) {
	if (!hProcess) return;
	// ��ʱ�ָ�   ==>  ������ɶԳ���
	int startIndex = count;
	printf("startIndex start: %d\n", startIndex);
	tmpRecoverSoftwareBreakPoint(command, hProcess, startIndex);

	// ��ȡ�Ѿ����������
	PBYTE data = (PBYTE)malloc(command->u2.len);
	if (!data) {
		printf("������ʱ�ռ�ʧ�� �����\n\n");
		return;
	}
	memset(data, 0, command->u2.len);
	ReadProcessMemory(hProcess, (LPCVOID)command->u1.addr, data, command->u2.len, 0);
	// ��ضϵ�
	recoverSoftBreakAgain(hProcess, startIndex);
	printf("startIndex end: %d\n\n", startIndex);

	DisasmInput(cshHandle, data, command->u2.len, command->u1.addr);
	free(data);
}

// �������룬����
void StepInReuse(HANDLE hProcess, HANDLE hThread, CONTEXT context) {
	// �п�����trap �� Ҳ�п�����Ӳ���ϵ�
	UserCommand tmp;
	// SetThreadContext(hThread, &context);
	tmp.u1.addr = context.Eip;
	tmp.u2.len = 1;
	// ��ʱ�ָ��˶ϵ㣬���ǻ�û�����û�ȥ�ϵ�
	tmpRecoverSoftwareBreakPoint(&tmp, hProcess, 0);
}

// ��ӡ��ʱ��Ϣ
void printTmpCodeInfo(HANDLE hProcess, CONTEXT context, const char* sign, int stepLen) {
	// ���������λ�ã����´˲���������
	// stepLen = 0;
	// ��ӡ��ʾ��Ϣ
	printf("%s , current eip : 0x%x\n", sign, context.Eip - stepLen);
	// ��ʾ���л��
	if (hProcess && context.Eip) {
		PBYTE data = (PBYTE)malloc(16);
		if (!data) {
			printf("������ʱ�ռ�ʧ�� �����\n\n");
			return;
		}
		UserCommand command;
		command.u1.addr = context.Eip - stepLen;
		command.u2.len = 16;
		DisasmByUserCommand(hProcess, &command);
	}
}

// �鿴���е�Ӳ���ϵ�
void ListHardBreakPoint(CONTEXT context) {
	PDBG_REG7 pDr7 = (PDBG_REG7)&context.Dr7;
	
	if (pDr7->L0) 
		printf("Ӳ���ϵ�DR0: 0x%x, �ϵ㳤��: %d, �ϵ�����: %x\n", context.Dr0, pDr7->LEN0, pDr7->RW0);
	if (pDr7->L1)
		printf("Ӳ���ϵ�DR1: 0x%x, �ϵ㳤��: %d, �ϵ�����: %x\n", context.Dr1, pDr7->LEN1, pDr7->RW1);
	if (pDr7->L2)
		printf("Ӳ���ϵ�DR2: 0x%x, �ϵ㳤��: %d, �ϵ�����: %x\n", context.Dr2, pDr7->LEN2, pDr7->RW2);
	if (pDr7->L3)
		printf("Ӳ���ϵ�DR3: 0x%x, �ϵ㳤��: %d, �ϵ�����: %x\n\n", context.Dr3, pDr7->LEN3, pDr7->RW3);
}

// ɾ��ָ����Ӳ���ϵ�
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

// �����ڴ�ϵ��쳣
int AutoHandleMemoryException(LPDEBUG_EVENT DebugEv, HANDLE hProcess, DWORD autoHandle) {
	// �ж��쳣����
	EXCEPTION_DEBUG_INFO procInfo = DebugEv->u.Exception;
	// 0��  1д   8ִ��
	DWORD accessFlag = procInfo.ExceptionRecord.ExceptionInformation[0]; 
	DWORD accessAddr = procInfo.ExceptionRecord.ExceptionInformation[1];

	// �������жϵ㣬�ҵ�ҳ���ڵ��ڴ�ϵ㣬��¼��ȫ�ֱ� // �˳����У�ֻ�����ڴ�ִ�жϵ�
	BreakPointInfo bpInfo;
	int ret = inTheLinkList(accessAddr, 0, MEMORYBP);
	if (ret && autoHandle) {
		return 1;
	}

	bpInfo.breakAddr = (DWORD)accessAddr & 0x0fffff000;
	if (accessFlag == 0) {
		// �ڴ���������쳣
	}
	else if (accessFlag == 1) {
		// �ڴ�д�쳣
	}
	else if (accessFlag == 8) {
		// �ڴ�ִ���쳣
		// �Զ��޸�����ʱ�޸��쳣ҳ��, �ڴ�ִ���쳣����Ҫ�޸�eip��
		VirtualProtectEx(hProcess, (LPVOID)((DWORD)accessAddr & 0x0fffff000), 0x1000, PAGE_EXECUTE, &bpInfo.originalProtect);
		bpInfo.mtype = 0;
		globalTmpMemoryBreakpoint[mcount++] = bpInfo;
	}
	return 0;
}

// ��ҳ�������ڴ�ϵ㣿
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