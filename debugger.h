#pragma once
#ifndef __DEBUGGER__
#define __DEBUGGER__
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "capstone/capstone.h"
// ��C/C++���ֱ���д����Ŀ¼ �� ��Ŀ¼
#pragma comment(lib, "capstone.lib") // ��Ŀ¼��Ŀǰֻ��32λ�ķ�����


// ��ʽ���û����������ṹ��
typedef enum _CommandType {
	WRONG = 0,
	WRITE = 1, // д�ڴ�  w
	READ = 2,   // ���ڴ�  r
	SET = 3,   // ���öϵ�  set
	CLEAR = 4, // ����ϵ�  cls
	STEPIN = 5, // ����  si
	STEPINM = 16, // �ڴ�ϵ�ʹ��
	STEPOVER = 6,    // ����  so
	LISTPROCESS = 7,  // �г������б� lp
	RUN = 8,     // һֱ����֪�������ϵ�  run
	RMBREAKPOINT = 9,  // �Ƴ�ָ���ϵ� rm
	LISTSFOTBREAKPOINT = 10, // ��ʾ����ϵ�  lsb
	PRINTFREGS = 11,  // ��ӡ�Ĵ�����ֵ  pr
	DISASMCODE = 12,  // �����  disasm 

	SETHARD = 13,    // Ӳ���ϵ�  setd 
	DEATTACH = 14,  // �˳�����   da
	SETMEM   = 15,  // �ڴ�ϵ�   setm
	EXIT     = 100,   // ��������  exit
} CommandType;

typedef struct user_command {
	// ��������
	CommandType type = WRONG;
	// 32λ������ַ
	union u1 {
		DWORD addr;
		PCHAR name;
	} u1;
	// ��д
	union u2 {
		// �����ݵĳ���
		DWORD len;
		// д���ݵ�����,һ�ν�����д4�ֽ�
		DWORD wdata;
		// �ĸ�Ӳ���Ĵ���
		DWORD drx;
		// ʲô���͵��ڴ�ϵ�
		DWORD mtype;
	} u2;
} UserCommand, *PUserCommand;

// EFLAGS�ṹ��
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
	// �ֲ��ϵ�(L0~3)��ȫ�ֶϵ�(G0~3)�ı��λ
	*/
	unsigned L0 : 1;  // ��Dr0����ĵ�ַ���� �ֲ��ϵ�
	unsigned G0 : 1;  // ��Dr0����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L1 : 1;  // ��Dr1����ĵ�ַ���� �ֲ��ϵ�
	unsigned G1 : 1;  // ��Dr1����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L2 : 1;  // ��Dr2����ĵ�ַ���� �ֲ��ϵ�
	unsigned G2 : 1;  // ��Dr2����ĵ�ַ���� ȫ�ֶϵ�
	unsigned L3 : 1;  // ��Dr3����ĵ�ַ���� �ֲ��ϵ�
	unsigned G3 : 1;  // ��Dr3����ĵ�ַ���� ȫ�ֶϵ�
	/*
	// �������á����ڽ���CPUƵ�ʣ��Է���׼ȷ���ϵ��쳣
	*/
	unsigned LE : 1;
	unsigned GE : 1;
	/*
	// �����ֶ�
	*/
	unsigned Reserve1 : 3;
	/*
	// �������ԼĴ�����־λ�������λΪ1������ָ���޸����ǼĴ���ʱ�ᴥ���쳣
	*/
	unsigned GD : 1;
	/*
	// �����ֶ�
	*/
	unsigned Reserve2 : 2;

	unsigned RW0 : 2;  // �趨Dr0ָ���ַ�Ķϵ����� 
	unsigned LEN0 : 2;  // �趨Dr0ָ���ַ�Ķϵ㳤��
	unsigned RW1 : 2;  // �趨Dr1ָ���ַ�Ķϵ�����
	unsigned LEN1 : 2;  // �趨Dr1ָ���ַ�Ķϵ㳤��
	unsigned RW2 : 2;  // �趨Dr2ָ���ַ�Ķϵ�����
	unsigned LEN2 : 2;  // �趨Dr2ָ���ַ�Ķϵ㳤��
	unsigned RW3 : 2;  // �趨Dr3ָ���ַ�Ķϵ�����
	unsigned LEN3 : 2;  // �趨Dr3ָ���ַ�Ķϵ㳤��
}DBG_REG7, * PDBG_REG7;

typedef enum _BreakPointType {
	SOFTWAREBP,
	HARDBP,
	MEMORYBP
}BreakPointType;

// �ϵ���Ϣ
typedef struct _BreakPointInfo {
	DWORD breakAddr;
	// int 3�ϵ�ʹ��
	BYTE origin;
	LIST_ENTRY pointer;
	// �ڴ�ϵ�ʹ��
	DWORD originalProtect;
	DWORD mtype;
	// ָ������ֵ
	BreakPointType bptype;
}BreakPointInfo, *PBreakPointInfo;
typedef struct _HardBreakPointInfo {
	DWORD drx;
	DWORD addr;
	// ���߳�ʱ��Ҫ����
	DWORD threadId;
}HardBreakPointInfo, *PHardBreakPointInfo;


// �������̣����е���
int CreateForDebug(char* imagePath);
// ���ӽ��̣����е���

// ������ѭ��
void EnterDebugLoop(PUserCommand command, const LPDEBUG_EVENT DebugEv);

// ��������ϵ�
int SetSoftwareBreakPoint(PVOID addr, DWORD pid);

// ����ͷ�ڵ�
void insertFirstNode(LIST_ENTRY* node);

// ͷ�巨
void insertListHeader(LIST_ENTRY* node, BreakPointType bptype);

// haven in
int inTheLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype);

// �鿴�ϵ�
void ListSoftwareBreakPoint();

// ɾ��ָ���ϵ�
void deleteBreakpoint(PVOID addr, DWORD pid);

// ������������ϵ�
void CleanAllSoftwareBreakPoint(DWORD pid);

// �û������쳣
int UserHandleException(PUserCommand command, const LPDEBUG_EVENT DebugEv);

// ����Ӳ���ϵ�
int SetHardBreakPoint(PVOID addr, DWORD drx, PCONTEXT context, DWORD len, DWORD type, BOOL local);

// �鿴���е�Ӳ���ϵ�
void ListHardBreakPoint(CONTEXT context);

// ɾ��ָ����Ӳ���ϵ�
void RmHardBreakPoint(PCONTEXT pContext, DWORD num);

// �����ڴ�ϵ�
void SetMemoryBreakPoint(PVOID addr, DWORD pid, DWORD type);

// �����ڴ�ϵ��쳣
int AutoHandleMemoryException(LPDEBUG_EVENT DebugEv, HANDLE hProcess, DWORD autoHandle);

// ��ҳ�������ڴ�ϵ㣿
// haven in
int inThePageLinkList(DWORD addr, BreakPointInfo* retV, BreakPointType bptype);


#elif
#endif
