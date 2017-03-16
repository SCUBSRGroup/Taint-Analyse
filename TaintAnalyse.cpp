#include <iostream>
#include <fstream>
#include "pin.H"

#include "z3++.h"


#include <cassert>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stack>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <stdint.h>
#include <time.h>
#include <list>
#include <string>
//#include<capstone.h>
#include<algorithm>
#include "disasmble.h"
//#include<X86Disasm.hh>

#pragma warning( push )  
#pragma warning( disable : 4551 )
#pragma warning( disable : 4700 )
#pragma warning( disable : 4715 )   



std::list< std::pair<UINT64, std::string> > constraintList;


z3::context *z3Context;
z3::expr *z3Var;
z3::solver *z3solver;
z3::expr *z3Equation;
z3::model *z3Model;


static char goodSerial[32] = { 0 };
static unsigned int offsetSerial;



#define ID_EAX 0
#define ID_EBX 1
#define ID_ECX 2
#define ID_EDX 3
#define ID_EDI 4
#define ID_ESI 5


static UINT32 regID[] =
{
	-1,/*ID_RAX*/
	-1,/*ID_RBX*/
	-1,/*ID_RCX*/
	-1,/*ID_RDX*/
	-1,/*ID_RDI*/
	-1/*ID_RSI*/
};




UINT32 getRegID(REG reg)
{
	switch (reg)
	{
	case  REG_EAX:
	case REG_AX:
	case REG_AH:
	case REG_AL:
		return regID[ID_EAX];
	case REG_EBX:
	case REG_BX:
	case REG_BH:
	case REG_BL:
		return regID[ID_EBX];
	case REG_ECX:
	case REG_CX:
	case REG_CH:
	case REG_CL:
		return regID[ID_ECX];
	case REG_EDX:
	case REG_DX:
	case REG_DH:
	case REG_DL:
		return regID[ID_EDX];
	//case REG_RDI:
	case REG_EDI:
	case REG_DI:
	//case REG_DL:
		return regID[ID_EDI];

	//case REG_RSI:
	case REG_ESI:
	case REG_SI:
	//case REG_SH:
	//case REG_SL:
		return regID[ID_ESI];
	default:
		return -1;
	}
}

VOID setRegID(REG reg, UINT64 id)
{
	switch (reg) {
	//case REG_RAX:
	case REG_EAX:
	case REG_AX:
	case REG_AH:
	case REG_AL:
		regID[ID_EAX] = id;
		break;

//	case REG_RBX:
	case REG_EBX:
	case REG_BX:
	case REG_BH:
	case REG_BL:
		regID[ID_EBX] = id;
		break;

	//case REG_ECX:
	case REG_ECX:
	case REG_CX:
	case REG_CH:
	case REG_CL:
		regID[ID_ECX] = id;
		break;

	//case REG_RDX:
	case REG_EDX:
	case REG_DX:
	case REG_DH:
	case REG_DL:
		regID[ID_EDX] = id;
		break;

	//case REG_RDI:
	case REG_EDI:
	case REG_DI:
	//case REG_DIL:
		regID[ID_EDI] = id;
		break;

	//case REG_RSI:
	case REG_ESI:
	case REG_SI:
	//case REG_SIL:
		regID[ID_ESI] = id;
		break;

	default:
		break;
	}
}

REG getHighReg(REG reg)
{
	switch (reg) {
	//case REG_RAX:
	case REG_EAX:
	case REG_AX:
	case REG_AH:
	case REG_AL:
		return REG_EAX;

	//case REG_RBX:
	case REG_EBX:
	case REG_BX:
	case REG_BH:
	case REG_BL:
		return REG_EBX;

	//case REG_RCX:
	case REG_ECX:
	case REG_CX:
	case REG_CH:
	case REG_CL:
		return REG_ECX;

	//case REG_RDX:
	case REG_EDX:
	case REG_DX:
	case REG_DH:
	case REG_DL:
		return REG_EDX;

	//case REG_RDI:
	case REG_EDI:
	case REG_DI:
	//case REG_DIL:
		return REG_EDI;

	//case REG_RSI:
	case REG_ESI:
	case REG_SI:
	//case REG_SIL:
		return REG_ESI;

	default:
		return REG_AL; /* hack exception */
	}
}



FILE *fp = NULL;
//extern "C"
//{
//#include "libvex.h"
//}

//#include "vexmem.h"
//#include "vexir.cpp"
#ifdef _WIN32

//const char* const windowsDll = "kernel32.dll";
//const char* const wsDll = "WS2_32.dll";

//const int callbackNum = 5;

//const unsigned int accessViolation = 0xc0000005;

namespace WINDOWS
{
#include "Winsock2.h"
#include "Windows.h"
}
#endif

typedef WINDOWS::HANDLE HANDLE;
typedef int DWORD;
typedef WINDOWS::LPCTSTR LPCTSTR;
typedef const VOID *LPCVOID;

KNOB<uint32_t> TaintStart(KNOB_MODE_WRITEONCE, "pintool", "taint-start", "0x0", "All logged instructions will have higher addresses");

KNOB<uint32_t> TaintEnd(KNOB_MODE_WRITEONCE, "pintool", "taint-end", "0xffffffff", "All logged instructions will have lower addresses");

KNOB<bool> LogAsm(KNOB_MODE_WRITEONCE, "pintool", "ll", "false", "generate asm ll");

KNOB<bool> LogVexir(KNOB_MODE_WRITEONCE, "pintool", "vexir", "false", "generate vex ir");

KNOB<string> InputFile(KNOB_MODE_WRITEONCE, "pintool", "input", "", "specify a new input file");

KNOB<string> TaintFile(KNOB_MODE_WRITEONCE, "pintool", "taint-file", "", "specify a taint file");


// This function is called before every instruction is executed


struct range
{
	UINT32 start;
	UINT32 end;
};


struct Inst
{
	ADDRINT key;
	string inst;
};

UINT64 ST1 = 0;
UINT64 ST2 = 0;


/************************************************************************/
/* global variable                                                                     */
/************************************************************************/

ofstream LlOutFile;
ofstream sfFile;
//std::map<ADDRINT, RegFrame*>rfs;
WINDOWS::HANDLE g_inputfileHandle = (WINDOWS::HANDLE) - 1;
std::map<HANDLE, string>taintfiles;
std::map<HANDLE, HANDLE>mapfiles; //first handle is mapview handle, second is file handle
std::map<LPCVOID, HANDLE>views;
std::string g_taintfile;
HANDLE g_tainfilehandle = (HANDLE)-1;

std::list<struct range>g_bytesTainted;

//std::list<struct Inst>g_InstList;
std::map<ADDRINT,string>g_InstList;

//这个地方存放被污染过的地址
std::list<UINT32>addressTainted;
//这里存放被污染的寄存器。
std::list<REG>regsTainted;

uint32_t g_memreadptr = 0;
uint32_t g_memwriteptr = 0;
BOOL g_branchistaken = FALSE;
BOOL g_blogvexir = FALSE;



void Instruction(INS ins,VOID *v);



/*
BOOL UnmapViewOfFile(
LPCVOID lpBaseAddress   // address where mapped view begins
);
*/

BOOL UnmapViewOfFileWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, LPCVOID lpBaseAddress)
{
	BOOL ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(BOOL), &ret,
		PIN_PARG(LPCVOID), lpBaseAddress,
		PIN_PARG_END());

	views.erase(lpBaseAddress);
	return ret;
}

/*
在链表中收索查找指令。
*/

void SearchInst(std::map<ADDRINT,string> g_inst,string & inst,ADDRINT address)
{
	//string inst;
	list<struct Inst>::iterator j; 
	std::map<ADDRINT, string>::iterator iter;;
	iter = g_InstList.find(address);
	if (iter != g_InstList.end())
		//表示找到
		inst = iter->second;
	//if (g_inst.find(address) != g_inst.end())
	//{
		//表示找到内容提供
	//}
	/*for (j = g_inst.begin(); j != g_inst.end(); j++)
	{
		if (j->key == address)
		{
			inst = j->inst;
			break;
		}
	}*/
}




/*
HANDLE CreateFileMapping(
HANDLE hFile,              // handle to file to map
LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
// optional security attributes
DWORD flProtect,           // protection for mapping object
DWORD dwMaximumSizeHigh,   // high-order 32 bits of object size
DWORD dwMaximumSizeLow,    // low-order 32 bits of object size
LPCTSTR lpName             // name of file-mapping object
);

*/

HANDLE CreateFileMappingWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	HANDLE hFile,              // handle to file to map
	WINDOWS::LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	// optional security attributes
	DWORD flProtect,           // protection for mapping object
	DWORD dwMaximumSizeHigh,   // high-order 32 bits of object size
	DWORD dwMaximumSizeLow,    // low-order 32 bits of object size
	LPCTSTR lpName             // name of file-mapping object
)
{
	HANDLE ret;

	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(HANDLE), &ret,
		PIN_PARG(HANDLE), hFile,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpFileMappingAttributes,
		PIN_PARG(DWORD), flProtect,
		PIN_PARG(DWORD), dwMaximumSizeHigh,
		PIN_PARG(DWORD), dwMaximumSizeLow,
		PIN_PARG(LPCTSTR), lpName,
		PIN_PARG_END());

	if (taintfiles.find(hFile) != taintfiles.end())
	{
		mapfiles.insert(pair<HANDLE, HANDLE>(ret, hFile));
	}
	return ret;
}


/*
BOOL CloseHandle(
HANDLE hObject   // handle to object to close
);

*/
BOOL CloseHandleWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	HANDLE hObject)
{
	BOOL ret;
	//z这个地方添加相关注释。
	if (hObject == g_inputfileHandle)
	{
		cerr << "[+] Close Input File..." << endl;
		g_inputfileHandle = (HANDLE)-1;
	}
	if (hObject == g_tainfilehandle)
	{
		cerr << "[+] Close Taint File..." << endl;
		g_tainfilehandle = (HANDLE)-1;
	}

	taintfiles.erase(hObject);
	mapfiles.erase(hObject);

	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(BOOL), &ret,
		PIN_PARG(HANDLE), hObject,
		PIN_PARG_END());

	return ret;
}


/*
LPVOID MapViewOfFile(
HANDLE hFileMappingObject,  // file-mapping object to map into
// address space
DWORD dwDesiredAccess,      // access mode
DWORD dwFileOffsetHigh,     // high-order 32 bits of file offset
DWORD dwFileOffsetLow,      // low-order 32 bits of file offset
DWORD dwNumberOfBytesToMap  // number of bytes to map
);

*/

void* MapViewOfFileWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	HANDLE hFileMappingObject,
	DWORD dwDesiredAccess,
	DWORD dwFileOffsetHigh,
	DWORD dwFileOffsetLow,
	DWORD dwNumberOfBytesToMap)
{
	void* ret;
	//cerr<<"[WARN] Enter MapViewOfFileWrapper..."<<endl;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(void*), &ret,
		PIN_PARG(HANDLE), hFileMappingObject,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwFileOffsetHigh,
		PIN_PARG(DWORD), dwFileOffsetLow,
		PIN_PARG(DWORD), dwNumberOfBytesToMap,
		PIN_PARG_END());


	if (mapfiles.find(hFileMappingObject) != mapfiles.end())
	{
		for (int i = 0; i < dwNumberOfBytesToMap; i++)
		{
			printf("[+]map byte (%d) : %02x from 0x%08x \n", i, *((char*)((char*)ret + i)), (uint32_t)ret + i);
			//uint32_t j = add_dependency_addr((uint32_t)ret + i, 8);
			//_snprintf(depaddr8[j].cons, XXX_MAX_BUF, "input(%d)", (uint32_t)dwFileOffsetLow + i);
		}
	}

	views.insert(pair<LPCVOID, HANDLE>((LPCVOID)ret, hFileMappingObject));
	return ret;
}

/*
HANDLE CreateFile(
LPCTSTR lpFileName,          // pointer to name of the file
DWORD dwDesiredAccess,       // access (read-write) mode
DWORD dwShareMode,           // share mode
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
// pointer to security attributes
DWORD dwCreationDisposition,  // how to create
DWORD dwFlagsAndAttributes,  // file attributes
HANDLE hTemplateFile         // handle to file with attributes to
// copy
);
*/

std::string& to_string(std::string& dest, std::wstring const & src)
{
	setlocale(LC_CTYPE, "");
	//get src's size
	size_t const mbs_len = wcstombs(NULL, src.c_str(), 0);
	std::vector<char> tmp(mbs_len + 1);
	wcstombs(&tmp[0], src.c_str(), tmp.size());

	dest.assign(tmp.begin(), tmp.end() - 1);

	return dest;
}


WINDOWS::HANDLE CreateFileWWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	wchar_t* lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	HANDLE ret;


	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(HANDLE), &ret,
		PIN_PARG(wchar_t*), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(HANDLE), hTemplateFile,
		PIN_PARG_END());
	std::wstring filename = lpFileName;
	std::string filenameA;
	filenameA = to_string(filenameA, filename);
	//	taintfiles.insert(std::pair<HANDLE, string>(ret, filenameA));

	cerr << "[+] Create File(UNICODE) Name : " << filenameA << endl;

	string k = filenameA.substr(filenameA.rfind('\\')+1);
	if (filenameA.substr(filenameA.rfind('\\')+1) == g_taintfile)
	{
		cerr << "[+] Taint File Is Created..." << endl;
		taintfiles.insert(std::pair<HANDLE, string>(ret, filenameA));
		g_tainfilehandle = ret;
	}
	return ret;
}


WINDOWS::HANDLE CreateFileAWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	WINDOWS::LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	HANDLE ret;


	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(HANDLE), &ret,
		PIN_PARG(LPCTSTR), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(HANDLE), hTemplateFile,
		PIN_PARG_END());
	std::string filename = lpFileName;
	//taintfiles.insert(std::pair<HANDLE, string>(ret, filename));

	cerr << "[+] Create File (ANSI) Name : " << filename << endl;

	printf(" * CreateFile : %s\n\t\tHandle:%x\n\n", filename.c_str(), ret);
	if (filename == g_taintfile)//被多次打开了，所以要注意跟踪。
	{
		printf(" * Taint File is Created...\n\n");
		cerr << "[+] Taint File Is Created..." << endl;
		taintfiles.insert(std::pair<HANDLE, string>(ret, filename));
		g_tainfilehandle = ret;
	}
	return ret;
}


/* ReadFile Protocol
BOOL ReadFile(
HANDLE hFile,                // handle of file to read
LPVOID lpBuffer,             // pointer to buffer that receives data
DWORD nNumberOfBytesToRead,  // number of bytes to read
LPDWORD lpNumberOfBytesRead, // pointer to number of bytes read
LPOVERLAPPED lpOverlapped    // pointer to structure for data
);

*/
BOOL ReadFileWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, WINDOWS::HANDLE hFile, void* lpBuffer, int nNumberOfBytesToRead, int* lpNumberOfBytesRead, WINDOWS::LPOVERLAPPED lpOverlapped)
{
	BOOL ret;

#define GetFilePointer(hFile) WINDOWS::SetFilePointer(hFile, 0, NULL, FILE_CURRENT)

	BOOL IsTaintFile = FALSE;
	uint32_t cur_pointer = 0;

	printf(" * ReadFile : %x\n\n", hFile);
	if (taintfiles.find(hFile) != taintfiles.end())
	{
		IsTaintFile = TRUE;
		if (g_inputfileHandle != (WINDOWS::HANDLE) - 1)
		{
			WINDOWS::CloseHandle(hFile);
			hFile = g_inputfileHandle;
		}
		cur_pointer = GetFilePointer(hFile);//设置到初始位置。
	}
	PIN_CallApplicationFunction(ctx, tid,
		CALLINGSTD_STDCALL, fp,
		PIN_PARG(BOOL), &ret,
		PIN_PARG(HANDLE), hFile,
		PIN_PARG(void*), lpBuffer,
		PIN_PARG(int), nNumberOfBytesToRead,
		PIN_PARG(int*), lpNumberOfBytesRead,
		PIN_PARG(WINDOWS::LPOVERLAPPED), lpOverlapped,
		PIN_PARG_END());

	
	//这里添加输入点
	//从lpbuffer开始，读了多少个字节，都设置为污点
	if (IsTaintFile)//这里面来进行处理。
	{
		
		//struct range taint;
		//首先获取到相应的污染源的大小
		//taint.start = (UINT32)((char *)lpBuffer);
		//taint.end = (UINT32)(taint.start) + *lpNumberOfBytesRead;
		//g_bytesTainted.push_back(taint);
		//printf("Traint Area from：%08x to %08x\n", taint.start, taint.end);
		for (UINT32 i = 0; i < *lpNumberOfBytesRead; i++)
		{	
			addressTainted.push_back((UINT32)((char *)lpBuffer + i));
		}
		std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << lpBuffer << " to 0x" << (UINT32 )lpBuffer + *lpNumberOfBytesRead << " (via read)" << std::endl;
		/*******************************
		for (int i = 0; i < nNumberOfBytesToRead; i++)
		{
			printf("[+]read byte (%d) : %02x from 0x%08x \n", i, *((char*)((char*)lpBuffer + i)), (uint32_t)lpBuffer + i);
			//uint32_t j = add_dependency_addr((uint32_t)lpBuffer + i, 8);
			//_snprintf(depaddr8[j].cons, XXX_MAX_BUF, "input(%d)", (uint32_t)cur_pointer + i);
		}
		*****/
	}

	return ret;
}

//检测是否被污染过的数据。
bool checkAlreadyRegTainted(REG reg)
{
	list<REG>::iterator i;

	for (i = regsTainted.begin(); i != regsTainted.end(); i++) {
		if (*i == reg) {
			return true;
		}
	}
	return false;
}

bool taintReg(REG reg)
{
	if (checkAlreadyRegTainted(reg) == true) {
		std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
		return false;
	}

	switch (reg) {

	//case REG_EAX:  regsTainted.push_front(REG_RAX);
	case REG_EAX:  regsTainted.push_front(REG_EAX);
	case REG_AX:   regsTainted.push_front(REG_AX);
	case REG_AH:   regsTainted.push_front(REG_AH);
	case REG_AL:   regsTainted.push_front(REG_AL);
		break;

	//case REG_RBX:  regsTainted.push_front(REG_RBX);
	case REG_EBX:  regsTainted.push_front(REG_EBX);
	case REG_BX:   regsTainted.push_front(REG_BX);
	case REG_BH:   regsTainted.push_front(REG_BH);
	case REG_BL:   regsTainted.push_front(REG_BL);
		break;

	//case REG_RCX:  regsTainted.push_front(REG_RCX);
	case REG_ECX:  regsTainted.push_front(REG_ECX);
	case REG_CX:   regsTainted.push_front(REG_CX);
	case REG_CH:   regsTainted.push_front(REG_CH);
	case REG_CL:   regsTainted.push_front(REG_CL);
		break;

	//case REG_RDX:  regsTainted.push_front(REG_RDX);
	case REG_EDX:  regsTainted.push_front(REG_EDX);
	case REG_DX:   regsTainted.push_front(REG_DX);
	case REG_DH:   regsTainted.push_front(REG_DH);
	case REG_DL:   regsTainted.push_front(REG_DL);
		break;

	//case REG_RDI:  regsTainted.push_front(REG_RDI);
	case REG_EDI:  regsTainted.push_front(REG_EDI);
	case REG_DI:   regsTainted.push_front(REG_DI);
	//case REG_DL:  regsTainted.push_front(REG_DIL);
		break;

	//case REG_RSI:  regsTainted.push_front(REG_RSI);
	case REG_ESI:  regsTainted.push_front(REG_ESI);
	case REG_SI:   regsTainted.push_front(REG_SI);
	//case REG_SL:  regsTainted.push_front(REG_SIL);
		break;

	default:
		std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
		return false;
	}
	std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
	return true;
}


//移除寄存器的污染值
bool removeRegTainted(REG reg)
{
	switch (reg) {

	//case REG_RAX:  regsTainted.remove(REG_RAX);
	case REG_EAX:  regsTainted.remove(REG_EAX);
	case REG_AX:   regsTainted.remove(REG_AX);
	case REG_AH:   regsTainted.remove(REG_AH);
	case REG_AL:   regsTainted.remove(REG_AL);
		break;

	//case REG_RBX:  regsTainted.remove(REG_RBX);
	case REG_EBX:  regsTainted.remove(REG_EBX);
	case REG_BX:   regsTainted.remove(REG_BX);
	case REG_BH:   regsTainted.remove(REG_BH);
	case REG_BL:   regsTainted.remove(REG_BL);
		break;

	//case REG_RCX:  regsTainted.remove(REG_RCX);
	case REG_ECX:  regsTainted.remove(REG_ECX);
	case REG_CX:   regsTainted.remove(REG_CX);
	case REG_CH:   regsTainted.remove(REG_CH);
	case REG_CL:   regsTainted.remove(REG_CL);
		break;

	//case REG_RDX:  regsTainted.remove(REG_RDX);
	case REG_EDX:  regsTainted.remove(REG_EDX);
	case REG_DX:   regsTainted.remove(REG_DX);
	case REG_DH:   regsTainted.remove(REG_DH);
	case REG_DL:   regsTainted.remove(REG_DL);
		break;

	//case REG_RDI:  regsTainted.remove(REG_RDI);
	case REG_EDI:  regsTainted.remove(REG_EDI);
	case REG_DI:   regsTainted.remove(REG_DI);
	//case REG_DIL:  regsTainted.remove(REG_DIL);
		break;

	//case REG_RSI:  regsTainted.remove(REG_RSI);
	case REG_ESI:  regsTainted.remove(REG_ESI);
	case REG_SI:   regsTainted.remove(REG_SI);
	//case REG_SIL:  regsTainted.remove(REG_SIL);
		break;

	default:
		return false;
	}
	std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
	return true;
}



VOID removeMemTainted(UINT32 addr)
{
	//list<UINT32>::iterator kz;
	addressTainted.remove(addr);
	std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
	
}


VOID addMemTainted(UINT32 addr)
{
	addressTainted.push_back(addr);
	std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;

}


//进行污染传播的数据
void ReadMem(ADDRINT address, std::string &Inst,REG reg_0,UINT32 OperandCount,UINT32 memop,UINT32 memorySize)
{
	list<UINT32>::iterator k;
	list<struct range>::iterator i;
	list<struct Inst>::iterator j;
	UINT32 addr = memop;
	string inst;
	REG reg_r;
	if (OperandCount != 2)
		return;
	reg_r = reg_0;

	for (k = addressTainted.begin(); k != addressTainted.end(); k++)
	{
		if (addr == *k)
		{
			std::cout << std::hex << "[READ in " << addr << "]\t" << address<< ": " << Inst << std::endl;
			taintReg(reg_r);
			return;

		}
	}
	if (checkAlreadyRegTainted(reg_r)) {
		std::cout << std::hex << "[READ in " << addr << "]\t" <<address << ": " << Inst << std::endl;
		removeRegTainted(reg_r);
	}
}

//如果涉及到内存写操作，则需要关注内存的写的内容。

//void WriteMem(INS ins, UINT32 memop)
void WriteMem(ADDRINT insaddr, std::string &Inst,UINT32 opCount,REG reg_r,UINT32 memory1,UINT32 memorySize)
{
	//这个地方的写内存操作要注意。
	list<struct range>::iterator i;
	list<struct Inst>::iterator j;
	string inst;
	UINT32 addr = memory1;
	//UINT32 TaintLength=0;
	//REG reg_r;
	list<UINT32>::iterator k;
	/************
	if (opCount != 2)
		return;


***************/
	//需要考虑两种情况，分别是通过寄存器向内存写入值，或者直接写入数据到内存中。
	//这时第一中情况。
	
	//还需要分别考虑
	for (unsigned int i = 0; i < memorySize; i++)
	{
		//if(k=addressTainted.)
		k=find(addressTainted.begin(), addressTainted.end(), (addr+i));
		//判断元素是否找到
		if (k != addressTainted.end())
		{
			//找到元素，开始进一步操作
			//SearchInst(g_InstList, inst, insaddr);
			std::cout << std::hex << "[WRITE in " << (addr+i) << "]\t" << insaddr << ": " << Inst << std::endl;
			if (!REG_valid(reg_r) || (!checkAlreadyRegTainted(reg_r)))
			{
				//针对两种情况，要么包含有寄存器，要么不包含寄存器
				removeMemTainted(addr+i);
			}
		}
		else
		{
			//没有找到元素，表示没有被污染，这时需要判断寄存器是否被污染
			if (checkAlreadyRegTainted(reg_r))
			{
				//SearchInst(g_InstList, inst, insaddr);
				std::cout << std::hex << "[WRITE in " << addr+i << "]\t" << insaddr << ": " << Inst << std::endl;
				addMemTainted(addr+i);
			}
		}
	}
	
}


VOID spreadRegTaint(ADDRINT address, std::string &Inst,UINT32 opCount,REG reg_r,REG reg_w)
{
	//寄存器只有寄存器是目标寄存器时候才能够被污染，否需要被考虑。
	if (opCount != 2)
		return;
	list<struct Inst>::iterator j;
	string k1 = REG_StringShort(reg_r);
	string k2 = REG_StringShort(reg_w);
	//如果目标寄存器是已经被污染过得，并且写入寄存器未被污染，则需要将该寄存器进行进一步的污染。
	if (REG_valid(reg_w)) {
		if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
			//SearchInst(g_InstList, inst, address);
			std::cout << "[SPREAD]\t\t" << address << ": " << Inst << std::endl;
			std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
			removeRegTainted(reg_w);
		}
		else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)) {
			//SearchInst(g_InstList, inst, address);
			std::cout << "[SPREAD]\t\t" << address << ": " << Inst << std::endl;
			std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " << REG_StringShort(reg_r) << std::endl;
			taintReg(reg_w);
		}
	}
}




//跟踪使用污点的指令，将这些指令打印出来

void followData(ADDRINT address, std::string &Inst,REG reg)
{
	string inst;
	list<struct Inst>::iterator j;

	if (!REG_valid(reg))
		return;
	if (checkAlreadyRegTainted(reg))
	{
		std::cout << "[FOLLOW]\t\t" << address << ":"<< Inst << std::endl;
	}
}
void MemoryMove(ADDRINT insaddr, std::string &Inst,UINT32 opCount, REG reg_r, UINT32 memory1,UINT32 memory2, UINT32 memorySize)
{
	//总共对这种指令的漏洞进行操作
	string inst;
	list<UINT32>::iterator k;
	list<struct Inst>::iterator j;
	//首先检查源地址，是否被污染，如果是则应该将目的地址进行污染。
	for (unsigned int i = 0; i < memorySize; i++)
	{
		//首选判断源是否被污染，如果是则直接将目标进行污染
		k = find(addressTainted.begin(), addressTainted.end(), (memory2+i));
		//判断元素是否找到
		if (k != addressTainted.end())
		{
			//找到元素，表示源被污染，直接将目的地址进行污染
			SearchInst(g_InstList, inst, insaddr);
			addMemTainted(memory1+i);
			std::cout << std::hex << "[WRITE in " << memory1+i << "]\t" << insaddr << ": " << inst << std::endl;
		}
		else
		{
			//如果没有找到，则需要判断源是否被污染，如果被污染，则相应的要移除掉源内存。
			k = find(addressTainted.begin(), addressTainted.end(), (memory1+i));
			if (k != addressTainted.end())
			{
				//表示找到，则需要去除。
				std::cout << std::hex << "[Write in " << (memory1 + i) << "]\t" << insaddr << ": " << inst << std::endl;
				removeMemTainted(memory1+i);
			}
		}
	}
	

//首先检查院地址是否被污染，然后再检测目的地址是否被污染。
	//if (checkAlreadyRegTainted(reg))
	//{
		/*	for (j = g_InstList.begin(); j != g_InstList.end(); j++)
		{
		if (j->key == address)
		{
		inst = j->inst;
		}
		}*/
		//SearchInst(g_InstList, inst, insaddr);
		//std::cout << "[FOLLOW]\t\t" << insaddr << ":" << inst << std::endl;
	//}
}

//进行污点传播的分析
void Instruction(INS ins,VOID *v)
{
	Inst instdis;
	std::map<ADDRINT, string>mapInst;
	ADDRINT insAddress = INS_Address(ins);
	UINT32 insSize = INS_Size(ins);
	/******************
	//int ret2 = instdis.inst.compare("rep stosd dword ptr [edi]");
	//if (ret2 == 0 && insAddress<0x70000000)
	//{
	//	int yyk=0;
	//}
	//int ret3 = instdis.inst.compare("rep movsd dword ptr [edi], dword ptr [esi]");
	//if (ret3 == 0 && insAddress<0x70000000)
	//{
	//	temp = 1;
	//}
	*******************/

	if (INS_OperandCount(ins)>1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0))
	{
		//这个地方将数据存放起来。
		//g_InstList.insert(pair<ADDRINT, string>(insAddress, INS_Disassemble(ins)));
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
			IARG_ADDRINT,INS_Address(ins),
			IARG_PTR,new std::string(INS_Disassemble(ins)),
			IARG_ADDRINT, INS_OperandReg(ins, 0),
			IARG_UINT32,INS_OperandCount(ins),
			IARG_MEMORYOP_EA, 0,
			IARG_MEMORYREAD_SIZE,
			IARG_END);
		
	}
	else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0))
	{
		//g_InstList.insert(pair<ADDRINT, string>(insAddress, INS_Disassemble(ins)));
		if(!(instdis.inst.compare("rep movsd dword ptr [edi], dword ptr [esi]")) ||
			!(instdis.inst.compare("rep movsd word ptr [edi], word ptr [esi]")) ||
			!(instdis.inst.compare("rep movsd byte ptr [edi], byte ptr [esi]")))
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)MemoryMove,
				IARG_ADDRINT, INS_Address(ins),
				IARG_PTR, new std::string(INS_Disassemble(ins)),
				IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_OperandReg(ins, 1),
				IARG_MEMORYOP_EA, 0,
				IARG_MEMORYOP_EA,1,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
		}
		else
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
				IARG_ADDRINT, INS_Address(ins),
				IARG_PTR, new std::string(INS_Disassemble(ins)),
				IARG_UINT32, INS_OperandCount(ins),
				IARG_UINT32, INS_OperandReg(ins, 1),
				IARG_MEMORYOP_EA, 0,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
		}

	}
	//如果目标指令有两个寄存器，并且第一个操作数是寄存器，则我们调用寄存器污点传播函数。
	else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins,0))
	{
		//每个地方都把数据插入进去。
	//	g_InstList.insert(pair<ADDRINT, string>(insAddress, INS_Disassemble(ins)));
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
			IARG_ADDRINT,INS_Address(ins),
			IARG_PTR, new std::string(INS_Disassemble(ins)),
			IARG_UINT32,INS_OperandCount(ins),
			IARG_UINT32,INS_RegR(ins,0),
			IARG_UINT32,INS_RegW(ins,0),
			IARG_END
		);
	}

	//对那个operand进行跟踪。
	if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0))
	{
		//g_InstList.insert(pair<ADDRINT, string>(insAddress, INS_Disassemble(ins)));
		INS_InsertCall(
			ins,
			IPOINT_BEFORE,
			(AFUNPTR)followData,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new std::string(INS_Disassemble(ins)),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_END);
	}

}


//这个地方开始污点标记，下一步就是对污点数据传播进行记录。

#define BUFSIZE 128
VOID ModLoad(IMG img, VOID *v)
{

	//cerr << "This is modload()" << endl;
	ADDRINT low_addr = IMG_LowAddress(img);
	ADDRINT high_addr = IMG_HighAddress(img);
	ADDRINT start_addr = IMG_StartAddress(img);
	ADDRINT load_offset = IMG_LoadOffset(img);

	const string &name = IMG_Name(img);
	char tempbuf[BUFSIZE];
	char *tok = NULL;
	char *lasttok = NULL;

	// Fill up the temporary buffer
	strncpy(tempbuf, name.c_str(), BUFSIZE);

	// We don't need a lock, since this is an instrumentation function (strtok is not re-entrant)
	strtok(tempbuf, "\\");

	while ((tok = strtok(NULL, "\\")) != NULL)
	{
		// Just keep parsing...
		lasttok = tok;
	}

	if (lasttok == NULL) return;

	if (strncmp("kernel32.dll", lasttok, BUFSIZE) == 0)
	{
		RTN r;
		//cerr << "find in " << string(lasttok) << endl;
		r = RTN_FindByName(img, "ReadFile");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(BOOL), CALLINGSTD_STDCALL,
				"ReadFile",
				PIN_PARG(WINDOWS::HANDLE),
				PIN_PARG(void*),
				PIN_PARG(int),
				PIN_PARG(int*),
				PIN_PARG(WINDOWS::LPOVERLAPPED),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(ReadFileWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_END);


			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find ReadFile" << endl;
		}


		r = RTN_FindByName(img, "CreateFileA");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(HANDLE), CALLINGSTD_STDCALL,
				"CreateFileA",
				PIN_PARG(LPCTSTR),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(HANDLE),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(CreateFileAWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
				IARG_END);


			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find CreateFileA" << endl;
		}

		r = RTN_FindByName(img, "CreateFileW");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(HANDLE), CALLINGSTD_STDCALL,
				"CreateFileW",
				PIN_PARG(LPCTSTR),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(HANDLE),
				PIN_PARG_END());
			RTN_ReplaceSignature(r, AFUNPTR(CreateFileWWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
				IARG_END);


			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find CreateFileW" << endl;
		}

		r = RTN_FindByName(img, "CreateFileMappingW");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(HANDLE), CALLINGSTD_STDCALL,
				"CreateFileMapping",
				PIN_PARG(HANDLE),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(LPCTSTR),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(CreateFileMappingWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
				IARG_END);


			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find CreateFileMapping" << endl;
		}

		r = RTN_FindByName(img, "MapViewOfFile");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(void *), CALLINGSTD_STDCALL,
				"MapViewOfFile",
				PIN_PARG(HANDLE),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(MapViewOfFileWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_END);


			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find MapViewofFile" << endl;
		}

		r = RTN_FindByName(img, "UnmapViewOfFile");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(BOOL), CALLINGSTD_STDCALL,
				"UnmapViewOfFile",
				PIN_PARG(LPCVOID),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(UnmapViewOfFileWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);

			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find UnmapViewOfFile" << endl;
		}

		r = RTN_FindByName(img, "CloseHandle");
		if (r != RTN_Invalid())
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(BOOL), CALLINGSTD_STDCALL,
				"CloseHandle",
				PIN_PARG(HANDLE),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(CloseHandleWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);

			PROTO_Free(proto);

		}
		else
		{
			cerr << "Couldn't find CloseHandle" << endl;
		}

	}

}

PIN_LOCK lock;
VOID ThreadStart(THREADID threadid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	// Get the command line arguments before _start is called
	// This only works with Linux conventions in mind
	static int firstthread = true;

	GetLock(&lock, threadid + 1);

	//cerr << "Thread " << threadid << " starting" << endl;

	if (firstthread)
	{
		firstthread = false;
	}
	char *aptr = WINDOWS::GetCommandLineA();

	wchar_t *wptr = WINDOWS::GetCommandLineW();
	/*
	wchar_t *q = wptr;
	if(q != NULL)
	{
	while(*q != L'\0')
	{
	printf("[+]read command line  : %02x from 0x%08x \n", *q, q);
	uint32_t j = add_dependency_addr((uint32_t)q , 8);
	_snprintf(depaddr8[j].cons, XXX_MAX_BUF, "input(%d)", (uint32_t)q );
	q++;
	}
	}
	*/
	ReleaseLock(&lock);



}
INT32 Usage()
{
	//cerr << "This tool counts the number of dynamic instructions executed" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

VOID Fini(INT32 code, VOID *v)
{
	// Write to a file since cout and cerr maybe closed by the application
	// 	ofstream OutFile;
	// 	OutFile.open(KnobOutputFile.Value().c_str());
	// 	OutFile.setf(ios::showbase);
	// 	OutFile << "Count " << icount << endl;
	// 	OutFile.close();
	//printf("%16X,%16X\n", ST1, ST2);
	//g_InstList.clear();
	printf("The traint address is:%08x\n", *(addressTainted.begin()));
	if (fp != NULL)
		fclose(fp);

}

int main(int argc, char * argv[])
{
	// Initialize pin
	
	//fp = fopen("log.txt","w");


	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) return Usage();


	// Register Instruction to be called to instrument instructions
	INS_AddInstrumentFunction(Instruction, 0);

	//PIN_AddThreadStartFunction(ThreadStart, 0);
	IMG_AddInstrumentFunction(ModLoad, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	taintfiles.clear();
	g_InstList.clear();//进行数据清理操作
	mapfiles.clear();
	views.clear();
	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);
	if (TaintFile.Value() != "")
		g_taintfile = TaintFile.Value();
	//string InputFile1 = "123.txt";
	if (InputFile.Value() != "")
	{
		WINDOWS::SECURITY_ATTRIBUTES la;
		g_inputfileHandle = WINDOWS::CreateFile(InputFile.Value().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		printf("g_inputfileHandle : %x\n", g_inputfileHandle);
		//taintfiles.insert(pair<HANDLE, string>(g_inputfileHandle, InputFile.Value()));
	}
	cerr << endl;
	cerr << "[+] Concrete Execution Is Running ......" << endl;
	// Start the program, never returns
	PIN_StartProgram();
	return 0;
}


#pragma warning( pop )