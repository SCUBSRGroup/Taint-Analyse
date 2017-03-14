//#include<capstone.h>
#ifdef _WIN32

const char* const windowsDll = "kernel32.dll";
const char* const wsDll = "WS2_32.dll";

const int callbackNum = 5;

const unsigned int accessViolation = 0xc0000005;

namespace WINDOWS
{
#include "Winsock2.h"
#include "Windows.h"
}
#endif


//typedef cs_err(*CSOpen)(cs_arch, cs_mode, csh *);
//typedef size_t(*CS_disasm)(csh handle, const uint8_t *code, size_t code_size, uint64_t address, size_t count, cs_insn **insn);
//typedef void(*CS_Free)(cs_insn *insn, size_t count);
//typedef cs_err(*CS_Close)(csh *handle); 
//bool disamble(char *Code, char *InstStr);
