#include "DebugControl.h"
#include <stdio.h>
#include <inttypes.h>

//构造
DebugControl::DebugControl()
{
	//初始化
	si = { 0 };
	pi = { 0 };
	DebugEvent = { 0 };
	BreakPointCount = 0;
	MBP = { 0 };
}
//析构
DebugControl::~DebugControl()
{
}

VOID DebugControl::DebugStartExecute(const char* szFilePath)
{
	//判断是不是64位程序
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
	//系统接收异常 -> 调试器接收异常 -> 筛选器接收异常
	//以调试模式启动进程
	//附加进程
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
	//DBG_EXCEPTION_NOT_HANDLED 调试器不处理异常
	//DBG_CONTINUE 调试器处理异常
	DWORD dwContinueStatus = DBG_CONTINUE;
	//--------------------------------------------

	//分发事件
	while (true)
	{
		//只有创建正在调试的进程的线程才能调用 WaitForDebugEvent。
		WaitForDebugEvent(&DebugEvent, INFINITE);//无限等待调试事件 
		switch (DebugEvent.dwDebugEventCode)//分发事件代码
		{
		case EXCEPTION_DEBUG_EVENT://调试事件
		{
			dwContinueStatus = UtilDebugEventManage();
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT://创建线程事件
		{
			dwContinueStatus = UtilCreateThreadEventManage();
			break;
		}
		case CREATE_PROCESS_DEBUG_EVENT://创建进程事件
		{
			dwContinueStatus = UtilCreateProcessEventManage();
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT://退出线程事件
		{
			dwContinueStatus = UtilExitThreadEventManage();
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT://退出进程事件
		{
			dwContinueStatus = UtilExitProcessEventManage();
			break;
		}
		case LOAD_DLL_DEBUG_EVENT: //加载模块事件
		{
			dwContinueStatus = UtilLoadDllEventManage();
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT: //卸载模块事件
		{
			dwContinueStatus = UtilUnLoadDllEventManage();
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT: //输出调试字符串事件
		{
			dwContinueStatus = UtilOutputDebugStringEventManage();
			break;
		}
		case RIP_EVENT: //控制事件
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
	//在入口点下断点
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
	case EXCEPTION_ACCESS_VIOLATION: //内存访问异常
	{
		dwStatus = UtilExceptionMemoryAccess();
		break;
	}
	case EXCEPTION_BREAKPOINT: //断点异常
	{

		dwStatus = UtilExceptionBreakPoint();
		break;
	}
	//case EXCEPTION_DATATYPE_MISALIGNMENT: //int 3异常
	//{
	//	//dwStatus = 
	//	break;
	//}
	case EXCEPTION_SINGLE_STEP: //单步异常
	{
		dwStatus = UtilExceptionSingelStep();
		break;
	}
	case DBG_CONTROL_C: //控制台退出进程
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
		//还原软件断点位置
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
		if (hProcess == NULL)
		{
			return DBG_CONTINUE;
		}
		SIZE_T stWriteLength = 0;
		WriteProcessMemory(hProcess, BPGroup[Index].BreakAddress, &BPGroup[Index].szOldCode, sizeof(BPGroup[Index].szOldCode), &stWriteLength);
		CloseHandle(hProcess);
		//RIP指令寄存器往后退1还原断点前的位置
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
		else if (_stricmp(szCMD,"u") == 0)//反汇编当前地址 显示20行
		{
			UtilDisassemblyRipContext(20);
		}
		else if (_stricmp(szCMD,"t") == 0)//步入
		{
			UtilSetSingelStep();
			break;
		}
		else if (_stricmp(szCMD,"p") == 0)//步过
		{
			UtilSetSingelStepOver();
			break;
		}
		else if ((_stricmp(szCMD,"b" ) == 0) || (_stricmp(szCMD, "bp") == 0))//软件断点
		{
			printf_s("[Address]>>>");
			DWORD64 dwTempValue = 0;
			scanf_s("%llx", &dwTempValue);
			UtilSetInt3BreakPoint((VOID*)dwTempValue);
			continue;
		}
		else if(_stricmp(szCMD,"r") == 0)//读取寄存器
		{
			UtilShowReg();
			continue;
		}
		else if (_stricmp(szCMD, "mbp") == 0)//内存断点
		{
			printf_s("[Address]>>>");
			DWORD64 dwTempValue = 0;
			scanf_s("%llx", &dwTempValue);
			UtilSetMemoryBreakPoint((VOID*)dwTempValue,8, PAGE_NOACCESS);
			continue;
		}
		else if (_stricmp(szCMD, "hbp") == 0)//内存断点
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
	//获取RIP
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	CONTEXT Ctx;
	Ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &Ctx);
	//获取RIP指向的代码块长度0x1000
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
	//单步步入的实现依赖于单步异常
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	if (hThread == NULL)
	{
		return 0;
	}
	//获取整个结构信息
	CONTEXT Ctx;
	Ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &Ctx);
	//TF：陷阱标志（Trap flag）是标志寄存器的第8位，当其被设置时将开启单步调试模式。
	//在其被设置的情况下，每个指令被执行后都将产生一个调试异常，以便于观察指令执行后的情况。
	Ctx.EFlags |= 0x100;
	SetThreadContext(hThread, &Ctx);
	CloseHandle(hThread);
	return 0;
}

DWORD DebugControl::UtilSetInt3BreakPoint(VOID* pAddress)
{
	//写入断点并保存替换的字节 
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
	//判断当前指令是否为CALL指令
	//若不是CALL指令，设置TF为1触发单步异常
	//若是CALL指令，判断OPCODE是E8还是FF15
	//若OPCODE是E8，在当前地址之后的第5个字节设置软件断点（E8指令占5个字节 相对位置）
	//若OPCODE是FF15，在当前地址之后的第6个字节设置软件断点（FF15指令占6个字节 绝对位置）

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
	
	//判断OPCODE
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
	//C0000005 内存访问异常
	//读异常 写异常 访问异常 执行异常
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
	//与软件断点与内存断点不同，硬件断点不依赖被调试程序，而是依赖于CPU中的调试寄存器。
	//调试寄存器有8个，分别为Dr0~Dr7。
	//用户最多能够设置4个硬件断点，这是由于只有Dr0~Dr3用于存储线性地址。
	//其中，Dr4和Dr5是保留的。
	// 硬件调试断点产生的异常是 STATUS_SINGLE_STEP（单步异常）
	// --------------------------------------
	//Dr7:
	//当中 L0/G0 ~ L3/G3：控制Dr0~Dr3是否有效，局部还是全局；每次异常后，Lx都被清零,Gx不清零
	
	//断点类型(R / Wx)：00(执行断点)、01(写入断点)、11(访问断点)
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
	//断点长度(LENx)：00(1字节)、01(2字节)、11(4字节)、10：未定义或者是8字节（和cpu的系列有关系）
	DR7->fields.len0 = 0b00;
	//L0-L3（由第0，2，4，6位控制）:对应DR0-DR3，设置断点作用范围，
	//如果被置位，那么将只对当前任务有效。每次异常后，Lx都被清零。
	DR7->fields.l0 = 0b01;
	//R/W0-R/W3：（由第16，17，20，21，24，25，28，29位控制）：这个东西的处理有两种情况。
	//如果CR4的DE被置位，那么，他们按照下面的规则处理问题：
	//00：执行断点
	//01：数据写入断点
	//10：I / 0读写断点
	//11：读写断点，读取指令不算
	//如果DE置0，那么问题会这样处理：
	//00：执行断点
	//01：数据写入断点
	//10：未定义
	//11：数据读写断点，读取指令不算
	DR7->fields.rw0 = 0b00;
	ctx.Dr0 = (DWORD64)pAddress;
	SetThreadContext(hThread, &ctx);
	CloseHandle(hThread);
	return 0;
}
