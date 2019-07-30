#pragma once

#include <Windows.h>

#include "entypreter_types.h"

#define MIMISHIM_X64_OFFSET 7620


BOOL entypreter_create_sysnative_process(LPCSTR program, LPDWORD dwPID);
BOOL entypreter_fork_x64(entypreter_shim_parsed *parsed, LPWSTR lpParam, char *data, DWORD dwDataSize);
