#ifndef _SSDT_H
#define _SSDT_H

#include "head.h"

class SSDT
{
public:
    static PVOID GetFunctionAddress(const char* apiname);
};

#endif