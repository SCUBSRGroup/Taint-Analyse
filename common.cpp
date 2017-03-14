#include "common.h"
bool stringCompareIgnoreCase(std::string lhs,std::string rhs)
{
	return _stricmp(lhs.c_str(),rhs.c_str());
}