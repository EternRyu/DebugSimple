#pragma once
#include <Windows.h>
#include <thread>
#include <Zydis/Zydis.h>
#include <vector>


//断点结构
struct BreakPointInfo
{
	VOID* BreakAddress;  //断点地址
	UCHAR szOldCode;	 //保存原代码
	//BOOL activate;		 //断点开关
};

//内存断点结构
struct MemoryBreakPointInfo
{
	VOID* BreakAddress;
	DWORD OldProtect;
	DWORD dwLength;
};

/// 参考: SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER
union FlagRegister {
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //<-- [0] Carry flag
		ULONG_PTR reserved1 : 1;   //<-- [1] Always 1
		ULONG_PTR pf : 1;          //<-- [2] Parity flag
		ULONG_PTR reserved2 : 1;   //<-- [3] Always 0
		ULONG_PTR af : 1;          //<-- [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //<-- [5] Always 0
		ULONG_PTR zf : 1;          //<-- [6] Zero flag
		ULONG_PTR sf : 1;          //<-- [7] Sign flag
		ULONG_PTR tf : 1;          //<-- [8] Trap flag
		ULONG_PTR intf : 1;        //<-- [9] Interrupt flag
		ULONG_PTR df : 1;          //<-- [10] Direction flag
		ULONG_PTR of : 1;          //<-- [11] Overflow flag
		ULONG_PTR iopl : 2;        //<-- [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //<-- [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //<-- [15] Always 0
		ULONG_PTR rf : 1;          //<-- [16] Resume flag
		ULONG_PTR vm : 1;          //<-- [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //<-- [18] Alignment check
		ULONG_PTR vif : 1;         //<-- [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //<-- [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //<-- [21] Identification flag
		ULONG_PTR reserved5 : 10;  //<-- [22:31] Always 0
	} fields;
};
static_assert(sizeof(FlagRegister) == sizeof(void*), "Size check");

/// 参考: Debug Control Register (DR7)
union Dr7 {
	ULONG_PTR all;
	struct {
		unsigned l0 : 1;         //<-- [0] Local Breakpoint Enable 0
		unsigned g0 : 1;         //<-- [1] Global Breakpoint Enable 0
		unsigned l1 : 1;         //<-- [2] Local Breakpoint Enable 1
		unsigned g1 : 1;         //<-- [3] Global Breakpoint Enable 1
		unsigned l2 : 1;         //<-- [4] Local Breakpoint Enable 2
		unsigned g2 : 1;         //<-- [5] Global Breakpoint Enable 2
		unsigned l3 : 1;         //<-- [6] Local Breakpoint Enable 3
		unsigned g3 : 1;         //<-- [7] Global Breakpoint Enable 3
		unsigned le : 1;         //<-- [8] Local Exact Breakpoint Enable
		unsigned ge : 1;         //<-- [9] Global Exact Breakpoint Enable
		unsigned reserved1 : 1;  //<-- [10] Always 1
		unsigned rtm : 1;        //<-- [11] Restricted Transactional Memory
		unsigned reserved2 : 1;  //<-- [12] Always 0
		unsigned gd : 1;         //<-- [13] General Detect Enable
		unsigned reserved3 : 2;  //<-- [14:15] Always 0
		unsigned rw0 : 2;        //<-- [16:17] Read / Write 0
		unsigned len0 : 2;       //<-- [18:19] Length 0
		unsigned rw1 : 2;        //<-- [20:21] Read / Write 1
		unsigned len1 : 2;       //<-- [22:23] Length 1
		unsigned rw2 : 2;        //<-- [24:25] Read / Write 2
		unsigned len2 : 2;       //<-- [26:27] Length 2
		unsigned rw3 : 2;        //<-- [28:29] Read / Write 3
		unsigned len3 : 2;       //<-- [30:31] Length 3
	} fields;
};
static_assert(sizeof(Dr7) == sizeof(void*), "Size check");

/// 参考: Debug Status Register (DR6)
union Dr6 {
	ULONG_PTR all;
	struct {
		unsigned b0 : 1;          //<-- [0] Breakpoint Condition Detected 0
		unsigned b1 : 1;          //<-- [1] Breakpoint Condition Detected 1
		unsigned b2 : 1;          //<-- [2] Breakpoint Condition Detected 2
		unsigned b3 : 1;          //<-- [3] Breakpoint Condition Detected 3
		unsigned reserved1 : 8;   //<-- [4:11] Always 1
		unsigned reserved2 : 1;   //<-- [12] Always 0
		unsigned bd : 1;          //<-- [13] Debug Register Access Detected
		unsigned bs : 1;          //<-- [14] Single Step
		unsigned bt : 1;          //<-- [15] Task Switch
		unsigned rtm : 1;         //<-- [16] Restricted Transactional Memory
		unsigned reserved3 : 15;  //<-- [17:31] Always 1
	} fields;
};
static_assert(sizeof(Dr6) == sizeof(void*), "Size check");

class DebugControl
{
public:
	DebugControl();
	~DebugControl();

	//启动调试程序并分发事件
	VOID DebugStartExecute(const char* szFilePath);
	//创建线程事件回调函数
	DWORD UtilCreateThreadEventManage();
	//创建进程事件回调函数
	DWORD UtilCreateProcessEventManage();
	//退出线程事件回调函数
	DWORD UtilExitThreadEventManage();
	//退出进程事件回调函数
	DWORD UtilExitProcessEventManage();
	//加载模块事件回调函数
	DWORD UtilLoadDllEventManage();
	//卸载模块事件回调函数
	DWORD UtilUnLoadDllEventManage();
	//输出调试字符串事件回调函数
	DWORD UtilOutputDebugStringEventManage();
	//调试事件回调函数
	DWORD UtilDebugEventManage();
	//内存访问异常回调函数
	DWORD UtilExceptionMemoryAccess();
	//单步异常回调函数
	DWORD UtilExceptionSingelStep();
	//断点异常回调函数
	DWORD UtilExceptionBreakPoint();
	//获取指令
	DWORD UtilGetCommandLine();
	//反汇编
	DWORD UtilDisassemblyRipContext(DWORD dwLine);
	//单步步入
	DWORD UtilSetSingelStep();
	//设置断点函数
	DWORD UtilSetInt3BreakPoint(VOID* pAddress);
	//单步步过
	DWORD UtilSetSingelStepOver();
	//显示寄存器
	DWORD UtilShowReg();
	//设置内存断点函数
	DWORD UtilSetMemoryBreakPoint(VOID* pAddress, DWORD SegmentLength, DWORD flNewProtect);
	//设置硬件断点函数
	DWORD UtilSetHardBreakPoint(VOID* pAddress);
private:

	STARTUPINFO si;//当Windows 创建新进程时，它将使用该结构的有关成员
	PROCESS_INFORMATION pi;
	DEBUG_EVENT DebugEvent;

	std::vector<BreakPointInfo> BPGroup;//断点组
	DWORD BreakPointCount;//断点总数

	MemoryBreakPointInfo MBP;//内存断点


};


