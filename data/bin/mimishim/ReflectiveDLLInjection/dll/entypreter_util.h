#pragma once

#include <Windows.h>

#include "entypreter_types.h"

BOOL entypreter_get_debug_priv();
BOOL entypreter_cpu_matches_process();

// proposed buffalo format:
// UUIDHEADER~~UUIDSHIMX64~~UUIDMIMIKATZX86~~UUIDMIMIKATZ64~~WORKURL
BOOL entypreter_parse_shim(LPWSTR buffalo, entypreter_shim_parsed *parsed);