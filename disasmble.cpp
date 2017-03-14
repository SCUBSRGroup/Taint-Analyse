#include"disasmble.h"

bool disamble(char *Code, char *InstStr)
{
	CSOpen cspen1 = NULL;
	CS_disasm csdisam1 = NULL;
	CS_Free  csfree = NULL;
	CS_Close csclose = NULL;
	WINDOWS::HMODULE hm = WINDOWS::LoadLibraryA("capstone.dll");
	cspen1 = (CSOpen)WINDOWS::GetProcAddress(hm, "cs_open");
	csdisam1 = (CS_disasm)WINDOWS::GetProcAddress(hm, "cs_disasm");
	csfree = (CS_Free)WINDOWS::GetProcAddress(hm, "cs_free");
	csclose = (CS_Close)WINDOWS::GetProcAddress(hm, "cs_close");
	csh handle;
	cs_insn *insn;
	size_t count;
	if (InstStr == NULL || Code == NULL)
	{
		return false;
	}
	if (cspen1(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return false;
	count = csdisam1(handle, (const uint8_t*)Code, sizeof(Code) - 1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++)
		{
			sprintf(InstStr, "%s %s", insn[j].mnemonic, insn[j].op_str);
			//printf("%16x:\t%s\t%s\n", insn[j].address, insn[j].mnemonic,
			//	insn[j].op_str);

		}
		csfree(insn, count);

	}
	else
		return false;
		//printf("ERROR: Failed to disassemble given code!\n");
	csclose(&handle);
	return true;
}