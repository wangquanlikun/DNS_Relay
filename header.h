#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#if defined(__GNUC__) && !defined(__MINGW32__)
    #define CONDITION_VARIABLE_INIT {0}
    typedef struct _RTL_CONDITION_VARIABLE {
        void *Ptr;
    } CONDITION_VARIABLE, *PCONDITION_VARIABLE;
    #define InitializeConditionVariable(cv) ((cv)->Ptr = NULL)
    #define SleepConditionVariableCS(cv, cs, ms) SleepConditionVariableCS_win(cv, cs, ms)
    #define WakeAllConditionVariable(cv) WakeAllConditionVariable_win(cv)

    BOOL SleepConditionVariableCS_win(PCONDITION_VARIABLE cv, PCRITICAL_SECTION cs, DWORD ms) {
        SleepConditionVariableCS(cv, cs, ms);
    }

    void WakeAllConditionVariable_win(PCONDITION_VARIABLE cv) {
        WakeAllConditionVariable(cv);
    }
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#else
#if _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <synchapi.h>
#pragma comment(lib, "ws2_32.lib")

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "func.h"
#include "data.h"

#endif