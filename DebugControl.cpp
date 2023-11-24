#include "DebugControl.h"
#include <stdio.h>
#include <inttypes.h>

//����
DebugControl::DebugControl()
{
	//��ʼ��
	si = { 0 };
	pi = { 0 };
	DebugEvent = { 0 };
	BreakPointCount = 0;
	MBP = { 0 };
}
//����
DebugControl::~DebugControl()
{
}

VOID DebugControl::DebugStartExecute(const char* szFilePath)
{
	//�ж��ǲ���64λ����
	FILE* pFile;
	BOOL bFileRet = fopen_s(&pFile, szFilePath, "r");
	if (bFileRet)
	{
		printf_s("[-]Open File Fileds! ErrorCode:%d\r\n", bFileRet);
		return;
	}
	fseek(pFile, 0, SEEK_SET);
	IMAGE_DOS_HEADER ImageDos = { 0 };
	fread(&ImageDos, 1, sizeof(IMAGE_DOS_HEADER), pFile);
	fseek(pFile, ImageDos.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS ImageNtUnknown = { 0 };
	fread(&ImageNtUnknown, 1, sizeof(IMAGE_NT_HEADERS), pFile);
	if (ImageNtUnknown.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		MessageBox(NULL, "ERROR : This application is not 64-bit", "Open Failed", MB_OK);
		return ;
	}
	fclose(pFile);
	//ϵͳ�����쳣 -> �����������쳣 -> ɸѡ�������쳣
	//�Ե���ģʽ��������
	//���ӽ���
	si.cb = sizeof(STARTUPINFO);
	BOOL bRet = CreateProcess(
		szFilePath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi
	);
	if (!bRet)
	{
		printf_s("[-]Create Debug Process Failed! ErrorCode:%d\r\n", GetLastError());
		system("pause");
		ExitProcess(1);
	}
	printf("[+]Create Debug Process Success!\r\n");
	
	//--------------------------------------------
	//DBG_EXCEPTION_NOT_HANDLED �������������쳣
	//DBG_CONTINUE �����������쳣
	DWORD dwContinueStatus = DBG_CONTINUE;
	//--------------------------------------------

	//�ַ��¼�
	while (true)
	{
		//ֻ�д������ڵ��ԵĽ��̵��̲߳��ܵ��� WaitForDebugEvent��
		WaitForDebugEvent(&DebugEvent, INFINITE);//���޵ȴ������¼� 
		switch (DebugEvent.dwDebugEventCode)//�ַ��¼�����
		{
		case EXCEPTION_DEBUG_EVENT://�����¼�
		{
			dwContinueStatus = UtilDebugEventManage();
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT://�����߳��¼�
		{
			dwContinueStatus = UtilCreateThreadEventManage();
			break;
		}
		case CREATE_PROCESS_DEBUG_EVENT://���������¼�
		{
			dwContinueStatus = UtilCreateProcessEventManage();
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT://�˳��߳��¼�
		{
			dwContinueStatus = UtilExitThreadEventManage();
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT://�˳������¼�
		{
			dwContinueStatus = UtilExitProcessEventManage();
			break;
		}
		case LOAD_DLL_DEBUG_EVENT: //����ģ���¼�
		{
			dwContinueStatus = UtilLoadDllEventManage();
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT: //ж��ģ���¼�
		{
			dwContinueStatus = UtilUnLoadDllEventManage();
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT: //��������ַ����¼�
		{
			dwContinueStatus = UtilOutputDebugStringEventManage();
			break;
		}
		case RIP_EVENT: //�����¼�
		{
			printf_s("RIP_EVENT\r\n");
			break;
		}
		}
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, dwContinueStatus);
	}
	
	//std::thread ThreadLDE(std::bind(&DebugControl::LoopDistributeEvent,this));
	//ThreadLDE.detach();

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

DWORD DebugControl::UtilCreateThreadEventManage()
{
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilCreateProcessEventManage()
{
	LPCREATE_PROCESS_DEBUG_INFO lpCreateProcessInfo = &DebugEvent.u.CreateProcessInfo;
	printf_s("[+]CreateProcess:[BaseOfImage:%p][StartAddress:%p]\r\n", lpCreateProcessInfo->lpBaseOfImage, lpCreateProcessInfo->lpStartAddress);
	//����ڵ��¶ϵ�
	UtilSetInt3BreakPoint(lpCreateProcessInfo->lpStartAddress);
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilExitThreadEventManage()
{
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilExitProcessEventManage()
{
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilLoadDllEventManage()
{
	LPLOAD_DLL_DEBUG_INFO lpLoadDllInfo = &DebugEvent.u.LoadDll;
	LPVOID lpModuleName = nullptr;
	SIZE_T stReadLength = 0;
	WCHAR szModuleName[MAX_PATH] = { 0 };
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	BOOL bRet = ReadProcessMemory(
		hProcess, lpLoadDllInfo->lpImageName, &lpModuleName, sizeof(LPVOID), &stReadLength
	);
	if (bRet)
	{
		if (ReadProcessMemory(hProcess,lpModuleName,&szModuleName,sizeof(szModuleName),&stReadLength))
		{
			if (lpLoadDllInfo->fUnicode)
			{
				wprintf(L"OnLoadDll:[Base:%p][DllName:%s]\r\n", lpLoadDllInfo->lpBaseOfDll, szModuleName);
			}
			else
			{
				printf("OnLoadDll:[Base:%p]", lpLoadDllInfo->lpBaseOfDll);
			}
		}
	}
	CloseHandle(hProcess);

	return DBG_CONTINUE;
}

DWORD DebugControl::UtilUnLoadDllEventManage()
{
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilOutputDebugStringEventManage()
{
	LPOUTPUT_DEBUG_STRING_INFO lpOutDBGStrInfo = &DebugEvent.u.DebugString;
	SIZE_T stReadLength = 0;
	WCHAR szDebugString[MAX_PATH] = { 0 };
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	if (ReadProcessMemory(hProcess, 
		lpOutDBGStrInfo->lpDebugStringData, 
		&szDebugString, 
		sizeof(szDebugString), 
		&stReadLength))
	{
		if (lpOutDBGStrInfo->fUnicode)
		{
			wprintf(L"OnOutputDebugString:[String:%s]\r\n", szDebugString);
		}
		else
		{
			printf_s("OnOutputDebugString:[String:%s]\r\n", szDebugString);
		}
	}
	CloseHandle(hProcess);

	return DBG_CONTINUE;
}

DWORD DebugControl::UtilDebugEventManage()
{
	LPEXCEPTION_DEBUG_INFO lpExceptionDebugInfo = &DebugEvent.u.Exception;
	LPEXCEPTION_RECORD lpExceptionRecord = &lpExceptionDebugInfo->ExceptionRecord;
	DWORD dwStatus = DBG_EXCEPTION_NOT_HANDLED;
	switch (lpExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION: //�ڴ�����쳣
	{
		dwStatus = UtilExceptionMemoryAccess();
		break;
	}
	case EXCEPTION_BREAKPOINT: //�ϵ��쳣
	{

		dwStatus = UtilExceptionBreakPoint();
		break;
	}
	//case EXCEPTION_DATATYPE_MISALIGNMENT: //int 3�쳣
	//{
	//	//dwStatus = 
	//	break;
	//}
	case EXCEPTION_SINGLE_STEP: //�����쳣
	{
		dwStatus = UtilExceptionSingelStep();
		break;
	}
	case DBG_CONTROL_C: //����̨�˳�����
	{
		break;
	}
	}
	return dwStatus;
}

DWORD DebugControl::UtilExceptionMemoryAccess()
{
	//printf_s("OnDebugEvent:[ExceptionCode:%p][ExceptionAddress:0x%08X]\r\n",  &lpExceptionInfo->ExceptionCode, &lpExceptionInfo->ExceptionAddress);
	LPEXCEPTION_RECORD lpExceptionInfo = &DebugEvent.u.Exception.ExceptionRecord;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	DWORD dwOldProtect = 0;
	VirtualProtectEx(hProcess, MBP.BreakAddress, MBP.dwLength, MBP.OldProtect, &dwOldProtect);
	CloseHandle(hProcess);

	UtilDisassemblyRipContext(20);
	UtilGetCommandLine();
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilExceptionSingelStep()
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		goto Routine;
	}
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	if (ctx.Dr6 & 0xF)
	{
		Dr7* DR7 = nullptr;
		DR7 = (Dr7*) & ctx.Dr7;
		DR7->fields.l0 = 0;
		SetThreadContext(hThread, &ctx);
	}
	CloseHandle(hThread);

Routine:
	UtilDisassemblyRipContext(20);
	UtilGetCommandLine();
	return DBG_CONTINUE;
}


DWORD DebugControl::UtilExceptionBreakPoint()
{
	LPEXCEPTION_RECORD lpExceptionRecord = &DebugEvent.u.Exception.ExceptionRecord;



	for (size_t Index = 0; Index < BreakPointCount; Index++)
	{
		if (BPGroup[Index].BreakAddress != lpExceptionRecord->ExceptionAddress)
		{
			continue;
		}
		//��ԭ����ϵ�λ��
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
		if (hProcess == NULL)
		{
			return DBG_CONTINUE;
		}
		SIZE_T stWriteLength = 0;
		WriteProcessMemory(hProcess, BPGroup[Index].BreakAddress, &BPGroup[Index].szOldCode, sizeof(BPGroup[Index].szOldCode), &stWriteLength);
		CloseHandle(hProcess);
		//RIPָ��Ĵ���������1��ԭ�ϵ�ǰ��λ��
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
		if (hThread == NULL)
		{
			return DBG_CONTINUE;
		}
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hThread, &ctx);
		ctx.Rip -= 1;
		SetThreadContext(hThread, &ctx);
		CloseHandle(hThread);

		UtilDisassemblyRipContext(20);
		UtilGetCommandLine();
		return DBG_CONTINUE;
	}
	UtilDisassemblyRipContext(20);
	UtilGetCommandLine();
	return DBG_CONTINUE;
}

DWORD DebugControl::UtilGetCommandLine()
{
	char szCMD[MAXBYTE];
	while (true)
	{
		printf_s(">>>");
		scanf_s("%s", szCMD, MAXBYTE);
		if (_stricmp(szCMD,"g") == 0)
		{
			break;
		}
		else if (_stricmp(szCMD,"u") == 0)//����൱ǰ��ַ ��ʾ20��
		{
			UtilDisassemblyRipContext(20);
		}
		else if (_stricmp(szCMD,"t") == 0)//����
		{
			UtilSetSingelStep();
			break;
		}
		else if (_stricmp(szCMD,"p") == 0)//����
		{
			UtilSetSingelStepOver();
			break;
		}
		else if ((_stricmp(szCMD,"b" ) == 0) || (_stricmp(szCMD, "bp") == 0))//����ϵ�
		{
			printf_s("[Address]>>>");
			DWORD64 dwTempValue = 0;
			scanf_s("%llx", &dwTempValue);
			UtilSetInt3BreakPoint((VOID*)dwTempValue);
			continue;
		}
		else if(_stricmp(szCMD,"r") == 0)//��ȡ�Ĵ���
		{
			UtilShowReg();
			continue;
		}
		else if (_stricmp(szCMD, "mbp") == 0)//�ڴ�ϵ�
		{
			printf_s("[Address]>>>");
			DWORD64 dwTempValue = 0;
			scanf_s("%llx", &dwTempValue);
			UtilSetMemoryBreakPoint((VOID*)dwTempValue,8, PAGE_NOACCESS);
			continue;
		}
		else if (_stricmp(szCMD, "hbp") == 0)//�ڴ�ϵ�
		{
			printf_s("[Address]>>>");
			DWORD64 dwTempValue = 0;
			scanf_s("%llx", &dwTempValue);
			UtilSetHardBreakPoint((VOID*)dwTempValue);
			continue;
		}
	}
	return 0;
}

DWORD DebugControl::UtilDisassemblyRipContext(DWORD dwLine)
{
	CHAR CodeData[0x1000] = { 0 };
	ZeroMemory(&CodeData, 0x1000);
	//��ȡRIP
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	CONTEXT Ctx;
	Ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &Ctx);
	//��ȡRIPָ��Ĵ���鳤��0x1000
	SIZE_T stReadLength = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	if (hProcess == NULL)
	{
		return 0;
	}
	ReadProcessMemory(hProcess, (LPVOID)Ctx.Rip, &CodeData, sizeof(CodeData), &stReadLength);


	INT Index = 0;
	// Loop over the instructions in our buffer.
	ZyanU64 runtime_address = Ctx.Rip;
	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
		/* runtime_address: */ runtime_address,
		/* buffer:          */ CodeData + offset,
		/* length:          */ sizeof(CodeData) - offset,
		/* instruction:     */ &instruction
	))) {
		if (Index == dwLine)
		{
			break;
		}
		printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
		offset += instruction.info.length;
		runtime_address += instruction.info.length;
		Index++;
	}
	return 0;
}

DWORD DebugControl::UtilSetSingelStep()
{
	//���������ʵ�������ڵ����쳣
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	//��ȡ�����ṹ��Ϣ
	CONTEXT Ctx;
	Ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &Ctx);
	//TF�������־��Trap flag���Ǳ�־�Ĵ����ĵ�8λ�����䱻����ʱ��������������ģʽ��
	//���䱻���õ�����£�ÿ��ָ�ִ�к󶼽�����һ�������쳣���Ա��ڹ۲�ָ��ִ�к�������
	Ctx.EFlags |= 0x100;
	SetThreadContext(hThread, &Ctx);
	CloseHandle(hThread);
	return 0;
}

DWORD DebugControl::UtilSetInt3BreakPoint(VOID* pAddress)
{
	//д��ϵ㲢�����滻���ֽ� 
	BreakPointInfo BP = { 0 };
	UCHAR szInt3 = 0xCC;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	SIZE_T stWriteLength = 0;
	//BP.activate = true;
	BP.BreakAddress = pAddress;
	ReadProcessMemory(hProcess, pAddress, &BP.szOldCode, sizeof(BP.szOldCode),NULL);
	BPGroup.push_back(BP);
	BreakPointCount++;

	WriteProcessMemory(hProcess, pAddress, &szInt3, sizeof(szInt3), &stWriteLength);
	CloseHandle(hProcess);
	
	return 0;
}

DWORD DebugControl::UtilSetSingelStepOver()
{
	//�жϵ�ǰָ���Ƿ�ΪCALLָ��
	//������CALLָ�����TFΪ1���������쳣
	//����CALLָ��ж�OPCODE��E8����FF15
	//��OPCODE��E8���ڵ�ǰ��ַ֮��ĵ�5���ֽ���������ϵ㣨E8ָ��ռ5���ֽ� ���λ�ã�
	//��OPCODE��FF15���ڵ�ǰ��ַ֮��ĵ�6���ֽ���������ϵ㣨FF15ָ��ռ6���ֽ� ����λ�ã�

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	if (hProcess == NULL)
	{
		return 0;
	}
	DWORD64 OPCODE = 0;
	SIZE_T dwReadLength = 0;
	ReadProcessMemory(hProcess, (LPVOID)ctx.Rip, &OPCODE, sizeof(DWORD64), &dwReadLength);
	
	//�ж�OPCODE
	if ((OPCODE & 0xFF) == 0xE8)
	{
		UtilSetInt3BreakPoint((LPVOID)(ctx.Rip + 5));
	}
	if ((OPCODE & 0xFFFF) == 0x15FF)
	{
		UtilSetInt3BreakPoint((LPVOID)(ctx.Rip + 6));
	}

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}

DWORD DebugControl::UtilShowReg()
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	printf_s("[RAX:0x%016llX][RBX:0x%016llX][RCX:0x%016llX][RDX:0x%016llX][RSI:0x%016llX][RDI:0x%016llX][RSP:0x%016llX][RBP:0x%016llX]\r\n",
		ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rsp, ctx.Rbp);
	printf_s("[DR0:0x%016llX][DR1:0x%016llX][DR2:0x%016llX][DR3:0x%016llX][DR6:0x%016llX][DR7:0x%016llX]\r\n", ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
	printf_s("[CS:0x%04X][DS:0x%04X][SS:0x%04X][ES:0x%04X][FS:0x%04X][GS:0x%04X]\r\n", ctx.SegCs, ctx.SegDs, ctx.SegSs, ctx.SegEs, ctx.SegFs, ctx.SegGs);
	FlagRegister EFlags = { 0 };
	EFlags.all = ctx.EFlags;
	printf_s("[ZF:%ld][PF:%ld][AF:%ld][OF:%ld][SF:%ld][DF:%ld][CF:%ld][TF:%ld][IF:%ld]\r\n", EFlags.fields.zf, EFlags.fields.pf, EFlags.fields.af, EFlags.fields.of, EFlags.fields.sf, EFlags.fields.df, EFlags.fields.cf, EFlags.fields.tf, EFlags.fields.intf);
	printf_s("[RFLAGS:0x%08lX]\r\n", EFlags.all);
	CloseHandle(hThread);
	return 0;
}

DWORD DebugControl::UtilSetMemoryBreakPoint(VOID* pAddress, DWORD SegmentLength, DWORD flNewProtect)
{
	//C0000005 �ڴ�����쳣
	//���쳣 д�쳣 �����쳣 ִ���쳣
	//PAGE_EXECUTE_WRITECOPY 
	//PAGE_EXECUTE_READ
	//PAGE_NOACCESS
	//PAGE_READWRITE
	//MemoryBreakPointInfo MBP = { 0 };
	MBP.BreakAddress = pAddress;
	MBP.dwLength = SegmentLength;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
	if (hProcess == NULL)
	{
		return 0;
	}
	VirtualProtectEx(hProcess, pAddress, SegmentLength, flNewProtect, &MBP.OldProtect);
	CloseHandle(hProcess);
	return 0;
}

DWORD DebugControl::UtilSetHardBreakPoint(VOID* pAddress)
{
	//������ϵ����ڴ�ϵ㲻ͬ��Ӳ���ϵ㲻���������Գ��򣬶���������CPU�еĵ��ԼĴ�����
	//���ԼĴ�����8�����ֱ�ΪDr0~Dr7��
	//�û�����ܹ�����4��Ӳ���ϵ㣬��������ֻ��Dr0~Dr3���ڴ洢���Ե�ַ��
	//���У�Dr4��Dr5�Ǳ����ġ�
	// Ӳ�����Զϵ�������쳣�� STATUS_SINGLE_STEP�������쳣��
	// --------------------------------------
	//Dr7:
	//���� L0/G0 ~ L3/G3������Dr0~Dr3�Ƿ���Ч���ֲ�����ȫ�֣�ÿ���쳣��Lx��������,Gx������
	
	//�ϵ�����(R / Wx)��00(ִ�жϵ�)��01(д��ϵ�)��11(���ʶϵ�)
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	Dr7* DR7 = nullptr;
	DR7 = (Dr7*) & ctx.Dr7;
	//�ϵ㳤��(LENx)��00(1�ֽ�)��01(2�ֽ�)��11(4�ֽ�)��10��δ���������8�ֽڣ���cpu��ϵ���й�ϵ��
	DR7->fields.len0 = 0b00;
	//L0-L3���ɵ�0��2��4��6λ���ƣ�:��ӦDR0-DR3�����öϵ����÷�Χ��
	//�������λ����ô��ֻ�Ե�ǰ������Ч��ÿ���쳣��Lx�������㡣
	DR7->fields.l0 = 0b01;
	//R/W0-R/W3�����ɵ�16��17��20��21��24��25��28��29λ���ƣ�����������Ĵ��������������
	//���CR4��DE����λ����ô�����ǰ�������Ĺ��������⣺
	//00��ִ�жϵ�
	//01������д��ϵ�
	//10��I / 0��д�ϵ�
	//11����д�ϵ㣬��ȡָ���
	//���DE��0����ô�������������
	//00��ִ�жϵ�
	//01������д��ϵ�
	//10��δ����
	//11�����ݶ�д�ϵ㣬��ȡָ���
	DR7->fields.rw0 = 0b00;
	ctx.Dr0 = (DWORD64)pAddress;
	SetThreadContext(hThread, &ctx);
	CloseHandle(hThread);
	return 0;
}
