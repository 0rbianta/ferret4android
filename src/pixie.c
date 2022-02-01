/* Copyright: (c) 2009-2010 by Robert David Graham
** License: This code is private to the author, and you do not 
** have a license to run it, or own a copy, unless given 
** a license personally by the author. This is 
** explained in the LICENSE file at the root of the project. 
**/
/*
    Portable APIs modeled after Linux/Windows APIs
*/
#if malloc==errmalloc
#undef malloc
#undef free
#endif
#if defined linux || defined __linux || defined __linux__
#define _GNU_SOURCE
#endif

#include "pixie.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#ifdef WIN32
#define _WIN32_WINNT 0x0400
#pragma warning(disable:4115)
#include <windows.h>
#include <winerror.h>
#include <process.h>
#include <rpc.h>
#include <rpcdce.h>
#pragma comment(lib,"rpcrt4.lib")
#else
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/time.h>
#endif

#if defined linux || defined __linux || defined __linux__
#include <sched.h>	/* for getting CPU count and setting thread CPU affinity */
#include <sys/types.h>
#endif

#if defined __APPLE__ || defined __FreeBSD__
#include <sys/sysctl.h>
#endif


#ifndef UNUSEDPARM
#define UNUSEDPARM(x) x=(x)
#endif

/*===========================================================================
 * IPHLPAPI.H (IP helper API)
 *  This include file is not included by default with Microsoft's compilers,
 *  but requires a seperate download of their SDK. In order to make
 *  compiling easier, we are going to copy the definitions from that file
 *  directly into this file, so that the header file isn't required.
 *===========================================================================*/
#if defined(WIN32) && !defined(__IPHLPAPI_H__)
/* __IPHLPAPI_H__ is the mutual-exclusion identifier used in the
 * original Microsoft file. We are going to use the same identifier here
 * so that if the programmer chooses, they can simply include the 
 * original file up above, and these definitions will automatically be
 * excluded. */
#define MAX_ADAPTER_DESCRIPTION_LENGTH  128
#define MAX_ADAPTER_NAME_LENGTH         256
#define MAX_ADAPTER_ADDRESS_LENGTH      8
#define DEFAULT_MINIMUM_ENTITIES        32
#define MAX_HOSTNAME_LEN                128
#define MAX_DOMAIN_NAME_LEN             128
#define MAX_SCOPE_ID_LEN                256
typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;
typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    DWORD ComboIndex;
    char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    UINT AddressLength;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;


typedef DWORD (WINAPI *GETADAPTERSINFO)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef DWORD (WINAPI *GETBESTINTERFACE)(DWORD ip_address, DWORD *r_interface_index);

DWORD WINAPI
GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
    static GETADAPTERSINFO xGetAdaptersInfo;

    if (xGetAdaptersInfo == 0) {
        void *h = pixie_load_library("iphlpapi.dll");
        if (h == NULL) {
            fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %d\n", GetLastError());
            return GetLastError(); 
        }
        xGetAdaptersInfo = (GETADAPTERSINFO)GetProcAddress(h, "GetAdaptersInfo");
        if (xGetAdaptersInfo == NULL) {
            fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %d\n", "GetAdaptersInfo", GetLastError());
            return GetLastError();
        }
    }

    return xGetAdaptersInfo(pAdapterInfo, pOutBufLen);
}

DWORD WINAPI
GetBestInterface(DWORD  dwDestAddr, DWORD  *pdwBestIfIndex) 
{
    static GETBESTINTERFACE xGetBestInterface;
    if (xGetBestInterface == 0) {
        void *h = pixie_load_library("iphlpapi.dll");
        if (h == NULL) {
            fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %d\n", GetLastError());
            return GetLastError(); 
        }
        xGetBestInterface = (GETBESTINTERFACE)GetProcAddress(h, "GetBestInterface");
        if (xGetBestInterface == NULL) {
            fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %d\n", "GetBestInterface", GetLastError());
            return GetLastError();
        }
    }

    return xGetBestInterface(dwDestAddr, pdwBestIfIndex);
}


#endif


/****************************************************************************
 ****************************************************************************/
void
pixie_strerror(char *error_msg, size_t sizeof_error_msg)
{
#ifdef WIN32
    DWORD err = GetLastError();
    CHAR *msg;

     if(FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |              // [15]
                        FORMAT_MESSAGE_FROM_SYSTEM |                  // [16]
                        0,                                        // [17]
                        0,                                 // [18]
                        err,                                          // [19]
                        0, // language ID
                        (CHAR*)&msg,                                 // [20]
                        0, // size ignored
                        NULL) // arglist
                              == 0)
    { /* not found */
            sprintf_s(error_msg, sizeof_error_msg, "unknown error");

     } else {
         sprintf_s(error_msg, sizeof_error_msg, "%s", msg);
         LocalFree(msg);
     }

#else
    snprintf(error_msg, sizeof_error_msg, "%s", strerror(errno));
#endif
}

/****************************************************************************
 * Load a dynamic link library. By loading this manually with code,
 * we can catch errors when the library doesn't exist on the system.
 * We can also go hunting for the library, or backoff and run without
 * that functionality. Otherwise, in the normal method, when the
 * operating system can't find the library, it simply refuses to run
 * our program
 ****************************************************************************/
void *
pixie_load_library(const char *library_name)
{
#ifdef WIN32
	void *h = LoadLibraryA(library_name);
	if (h == 0) {
		switch (GetLastError()) {
		case ERROR_BAD_EXE_FORMAT:
			printf("LoadLibrary(%s): bad DLL format (maybe 64-bit or 32-bit?)\n", library_name);
			break;
		case ERROR_MOD_NOT_FOUND:
			/* silently ignore this error */
			break;
		default:
			printf("LoadLibrary(%s): error# %u\n", library_name, GetLastError());
			break;
		}
	}
	return h;
#else
	void *h;

    h = dlopen(library_name,RTLD_LAZY);
	if (h == NULL) {
		; /*printf("dlopen(%s) err: %s\n", library_name, dlerror());*/
	}
	return h;
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_close_library(void *library_handle)
{
#ifdef WIN32
	BOOL x;
	x = FreeLibrary(library_handle);
	if (x == 0)
		fprintf(stderr, "FreeLibrary(): return error #%u\n", GetLastError());
#else
	int x;
	x = dlclose(library_handle);
	if (x != 0)
		fprintf(stderr, "dlclose(): returned error #%u (%s)\n", errno, dlerror());
#endif
}


/****************************************************************************
 * Retrieve a pointer to the named function. The 'library' is a handle for
 * a dynamic library (.dll or .so) that was loaded with 'pixie_load_library'
 ****************************************************************************/
PIXIE_FUNCTION
pixie_get_proc_symbol(void *library, const char *symbol)
{
#ifdef WIN32
    return (PIXIE_FUNCTION)GetProcAddress(library, symbol);
#else
    /* ISO C doesn't allow us to cast a data pointer to a function
     * pointer, therefore we have to cheat and use a union */
    union {
        void *data;
        PIXIE_FUNCTION func;
    } result;
    result.data = dlsym(library, symbol);
    return result.func;
#endif
}


/****************************************************************************
 * Retrieve the MAC address of the system
 ****************************************************************************/
unsigned
pixie_get_mac_address(unsigned char macaddr[6])
{
    memset(macaddr, 0, sizeof(macaddr));
#ifdef WIN32
    {
        DWORD dwStatus;
        IP_ADAPTER_INFO *p;
        IP_ADAPTER_INFO AdapterInfo[16];
        DWORD dwBufLen = sizeof(AdapterInfo);
        DWORD interface_index = (DWORD)-1;

        GetBestInterface(0x01010101, &interface_index);
        
        dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
        if (dwStatus != ERROR_SUCCESS)
              return 1;

        for (p=AdapterInfo; p; p = p->Next) {

            if (p->Index == interface_index || interface_index == -1) {
                memcpy(macaddr, p->Address, 6);
                return 0;
            }
            /*(
            printf("[%02x:%02x:%02x:%02x:%02x:%02x]\n",
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5]
            );
            printf("    %s\n", p->AdapterName);
            printf("    %s\n", p->Description);
            printf("    IP: ");
            for (a = &p->IpAddressList; a; a = a->Next) {
                printf("%s ", a->IpAddress.String);
            }
            printf("\n");
            */
        }
        return (unsigned)-1;
    }
#else
    return (unsigned)-1;
#endif
}


/****************************************************************************
 * Retrieve the name of the host computer.
 ****************************************************************************/
unsigned
pixie_get_host_name(char *name, unsigned name_size)
{
#ifdef WIN32
    {
        DWORD nSize = (DWORD)name_size;
        /*
        BOOL WINAPI GetComputerName(
          __out    LPTSTR lpBuffer,
        __inout  LPDWORD lpnSize
        );
        Return Value: If the function succeeds, the return value is a nonzero value.
        The variable 'lpnsize' must be set to the length of the number of
        bytes in the string, and it be set to the resulting length */
        if (GetComputerNameA(name, &nSize))
            return (unsigned)nSize;
        else
            return 0;
    }
#else
    /*
    int gethostname(char *name, size_t namelen)
    'namelen' is the size of the 'name' buffer.
    Returns 0 on success, -1 on failure
    */
    if (gethostname(name, name_size) == 0) {
        /* If the buffer is too small, it might not nul terminate the
         * string, so let's guarantee a nul-termination */
        name[name_size-1] = '\0';
        return name_size;
    } else
        return 0;
#endif
}



/****************************************************************************
 ****************************************************************************/
void
pixie_lower_thread_priority()
{
#if defined(WIN32) && defined(_MT)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_lower_thread_priority undefimed
#endif
}



/****************************************************************************
 ****************************************************************************/
void
pixie_raise_thread_priority()
{
#if defined(WIN32) && defined(_MT)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_ABOVE_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_raise_thread_priority undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_enter_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32) && defined(_MT)
    if (TryEnterCriticalSection((CRITICAL_SECTION*)cs))
        return;
    else {
        EnterCriticalSection((CRITICAL_SECTION*)cs);
    }
#elif defined(__GNUC__)
    pthread_mutex_lock(cs);
#else
#error pixie_enter_critical_section undefimed
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_leave_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32) && defined(_MT)
    LeaveCriticalSection(cs);
#elif defined(__GNUC__)
	if (pthread_mutex_unlock(cs) != 0) printf("mutex: failed %d\n", errno);
#else
#error pixie_leave_critical_section undefimed
#endif
}

/****************************************************************************
 ****************************************************************************/
void *
pixie_initialize_critical_section(void)
{
#if defined(WIN32) && defined(_MT)
    CRITICAL_SECTION *cs = (CRITICAL_SECTION*)malloc(sizeof(*cs));
	if (cs == NULL) {
		fprintf(stderr, "%s: out of memory error\n", "pixie");
		exit(1);
	}
    memset(cs, 0, sizeof(*cs));
    InitializeCriticalSection(cs);
    return cs;
#elif defined(__GNUC__)
    pthread_mutex_t *mutex = (pthread_mutex_t*)malloc(sizeof(*mutex));
	if (mutex == NULL) {
		fprintf(stderr, "%s: out of memory error\n", "pixie");
		exit(1);
	}
    memset(mutex, 0, sizeof(*mutex));
    pthread_mutex_init(mutex, 0);
    return mutex;
#else
#error pixie_initialize_critical_section undefimed
#endif
}

/****************************************************************************
 ****************************************************************************/
ptrdiff_t
pixie_begin_thread(void (*worker_thread)(void*), unsigned flags, void *worker_data)
{
#if defined(WIN32) && defined(_MT)
	UNUSEDPARM(flags);
	return _beginthread(worker_thread, 0, worker_data);
#elif defined(__GNUC__)
	typedef void *(*PTHREADFUNC)(void*);
	pthread_t thread_id;
	return pthread_create(&thread_id, NULL, (PTHREADFUNC)worker_thread, worker_data);
#else
#error pixie_begin_thread undefined
#endif
}


/****************************************************************************
 ****************************************************************************/
void
pixie_close_thread(ptrdiff_t thread_handle)
{
#if defined(WIN32) && defined(_MT)
	CloseHandle((HANDLE)thread_handle);
#elif defined(__GNUC__)
	/* TODO: does anything go here */
#else
#error pixie_close_thread undefined
#endif
}



/****************************************************************************
 ****************************************************************************/
void 
pixie_delete_critical_section(void *cs)
{
#if defined(WIN32) && defined(_MT)
    if (cs) {
        DeleteCriticalSection(cs);
        free(cs);
    }
#elif defined(__GNUC__)
	if (cs) {
		pthread_mutex_destroy(cs);
		free(cs);
	}
#else
#error pixie_delete_critical_section undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_sleep(unsigned milliseconds)
{
#ifdef WIN32
    Sleep(milliseconds);
/*#elif defined(_POSIX_C_SOURCE)
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = milliseconds * 1000 * 1000;
	nanosleep(&delay, 0);
#else
#error test*/
#else
    usleep(milliseconds*1000);
#endif
}


/****************************************************************************
 ****************************************************************************/
uint64_t
pixie_microseconds()
{
#ifdef WIN32
    {
        FILETIME ft;
        uint64_t result;

        GetSystemTimeAsFileTime(&ft);

        result = ((uint64_t)ft.dwHighDateTime) << 32;
        result |= ft.dwLowDateTime;

        return result/10;
    }
#else
    {
        struct timeval tv;
        gettimeofday(&tv,0);

        return ((uint64_t)tv.tv_sec)*1000000 + tv.tv_usec;
    }
#endif
}


/****************************************************************************
 * Set the current thread (implicit) to run exclusively on the explicit
 * process.
 * http://en.wikipedia.org/wiki/Processor_affinity
 ****************************************************************************/
void
pixie_cpu_set_affinity(unsigned processor)
{

#if defined WIN32
	DWORD_PTR mask;
	DWORD_PTR result;
	if (processor > 0)
		processor--;
	mask = ((size_t)1)<<processor;

	//printf("mask(%u) = 0x%08x\n", processor, mask);
	result = SetThreadAffinityMask(GetCurrentThread(), mask);
	if (result == 0) {
		fprintf(stderr, "set_affinity: returned error win32:%d\n", GetLastError());
	}
#elif defined(linux) && defined(__GNUC__)
	int x;
	pthread_t thread = pthread_self();
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);

	CPU_SET(processor+1, &cpuset);

	/*x = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (x != 0) {
		fprintf(stderr, "set_affinity: returned error linux:%d\n", errno);
	}*/
#elif defined(__APPLE__) && defined(__GNUC__)
	
#else
#error pixie_assign_processor undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
unsigned
pixie_cpu_get_count()
{
#if defined WIN32
	/* WINDOWS - use GetProcessAffinityMask() function */
	size_t x;
#if defined _M_X64
	DWORD_PTR process_mask = 0;
	DWORD_PTR system_mask = 0;
#else
	unsigned long process_mask = 0;
	unsigned long system_mask = 0;
#endif
	unsigned count = 0;
	unsigned i;

	x = GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask);
	if (x == 0) {
		printf("GetProcessAffinityMask() returned error %d\n", GetLastError());
		return 1;
	}
	for (i=0; i<32; i++) {
		if (system_mask & 1)
			count++;
		system_mask >>= 1;
	}
	if (count == 0)
		return 1;
	else
		return count;
#elif defined __APPLE__
	/* BSD - use sysctl() function */
		int x;
		int mib[2];
		size_t ncpu_length;
		int ncpu = 1;

		mib[0] = CTL_HW;
		mib[1] = HW_NCPU;
		ncpu_length = sizeof(ncpu);
		x = sysctl(mib, 2, &ncpu, &ncpu_length, NULL, 0);
		if (x == -1) {
		  perror("sysctl(HW_NCPU) failed");
		  return 1;
		} else
		  return (unsigned)ncpu;
#elif defined linux
	/* http://linux.die.net/man/2/sched_getaffinity */
	{
		pid_t pid;
		cpu_set_t mask;
		int err;
  
		/* Gegret our process ID */
		pid = getpid();

		/* Get list of available CPUs for our system */
		err = sched_getaffinity(pid, sizeof(mask), &mask);
		if (err) {
			perror("sched_getaffinity");
			return 1;
		} else {
			return CPU_COUNT(&mask);
		}
	}
#else
#error need to find CPU count
	/* UNKNOWN - Well, we don't know the type of system which means we won't
	 * be able to start multiple threads anyway, so just return '1' */
	return 1;
#endif
}

/****************************************************************************
 ****************************************************************************/
unsigned 
pixie_locked_xadd_u32(unsigned *lhs, unsigned rhs)
{
#if defined(_MSC_VER)
    return InterlockedExchangeAdd((long*)lhs, rhs);
#elif defined(__GNUC__) && __GNUC__ == 4 
	return (unsigned)__sync_fetch_and_add(lhs, rhs);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "xaddl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        return ret;
#endif
#else
#error pixie_locked_xadd_u32: undefined (unknown compiler or OS)
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_locked_add_u32(volatile unsigned *lhs, unsigned rhs)
{
#if defined(_MSC_VER)
#ifdef _M_X64
    InterlockedAdd((long*)lhs, rhs);
#else
    __asm {
            push eax
            push ebx
            push ecx
            mov ecx, lhs
            mov ebx, rhs

            lock add dword ptr[ecx], ebx

            pop ecx
            pop ebx
            pop eax
    }
#endif
#elif defined(__GNUC__) 
	__sync_add_and_fetch(lhs, rhs);
#if 0 && defined(__i386__)
	 __asm__ __volatile__ (
                      "   lock       ;\n"
                      "   addl %1,%0 ;\n"
                      : "=m"  (lhs)
                      : "ir"  (rhs), "m" (lhs)
                      :  "memory"                               /* no clobber-list */
                      );
#endif
#if 0
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "add %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error: pixie_locked_add_u32: undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
void
pixie_locked_subtract_u32(unsigned *lhs, unsigned rhs)
{
#if defined(_MSC_VER)
#if _M_X64
	InterlockedAdd((long*)lhs, -(long)rhs);
#else
    __asm {
            push eax
            push ebx
            push ecx
            mov ecx, lhs
            mov ebx, rhs

            lock sub dword ptr[ecx], ebx

            pop ecx
            pop ebx
            pop eax
    }
#endif
#elif defined(__GNUC__)
	__sync_sub_and_fetch(lhs, rhs);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "subl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error pixie_locked_subtract_u32: not implemented yet
#endif
}

/****************************************************************************
 ****************************************************************************/
bool 
pixie_locked_compare_and_swap(volatile unsigned *dst, unsigned src, unsigned expected)
{
#if defined(_MSC_VER)
	return InterlockedCompareExchange((LONG*)dst, src, expected) == (LONG)expected;
#elif defined(__GNUC__)
	return __sync_bool_compare_and_swap(dst, src, expected);
#if 0 && defined(__i386__)
    unsigned ret;
    __asm__ (
        "lock\n\t"
        "subl %0,(%1)"
        :"=r" (ret)
        :"r" (lhs), "0" (rhs)
        :"memory" );
        /*return ret;*/
#endif
#else
#error pixie_locked_subtract_u32: not implemented yet
#endif
}


/****************************************************************************
 * Retrives the total amount of memory in the system, as well as the current
 * amount of free memory. The reason for this is that the program can
 * size its internal tables so that they fit within physical RAM, otherwise
 * it will cause a lot of swapping.
 ****************************************************************************/
void
pixie_get_memory_size(uint64_t *available, uint64_t *total_physical)
{
#if defined(WIN32)
	MEMORYSTATUSEX status;

	status.dwLength = sizeof(status);

	GlobalMemoryStatusEx(&status);

	*available = status.ullAvailPhys;
	*total_physical = status.ullTotalPhys;

#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
	/* Use 'sysctl' instead? */
	size_t page_count = sysconf(_SC_PHYS_PAGES);
	size_t page_size = sysconf(_SC_PAGESIZE);
	*total_physical = page_count * page_size;
	available = total_physical;
#elif defined(__APPLE__)

        size_t oldlen;
        uint64_t physmem_size;

        oldlen = sizeof(physmem_size);
        sysctlbyname("hw.memsize", &physmem_size, &oldlen, NULL, 0);

	*total_physical = physmem_size;
	available = total_physical;
#else
#error pixie_get_memory_size: not implemented yet
#endif
}



/****************************************************************************
 ****************************************************************************/
void 
pixie_thread_ignore_signals()
{
#ifndef WIN32
	sigset_t mask;
	sigfillset(&mask);
	pthread_sigmask(SIG_SETMASK, &mask, 0);
#endif
}


/****************************************************************************
 ****************************************************************************/
#if defined(WIN32)
#define _PTHREAD_BARRIER_FLAG (1<<30)
int
pixie_barrier_init(pixie_barrier_t *barrier, void *attr, int count)
{
	CONDITION_VARIABLE *cv;
	UNUSEDPARM(attr);

	barrier->cs = pixie_initialize_critical_section();
	barrier->cv = (CONDITION_VARIABLE*)malloc(sizeof(*cv));
	InitializeConditionVariable((CONDITION_VARIABLE*)barrier->cv);
	barrier->count = count;
	barrier->total = 0;
	return 0;
}

/****************************************************************************
 ****************************************************************************/
int
pixie_barrier_destroy(pixie_barrier_t *barrier)
{
	EnterCriticalSection((CRITICAL_SECTION*)barrier->cs);
	{
		/* Wait until everyone exits the barrier */
		while (barrier->total > _PTHREAD_BARRIER_FLAG)
			SleepConditionVariableCS(	(CONDITION_VARIABLE*)barrier->cv, 
										(CRITICAL_SECTION*)barrier->cs, 
										INFINITE);
	}
	LeaveCriticalSection((CRITICAL_SECTION*)barrier->cs);
	DeleteCriticalSection((CRITICAL_SECTION*)barrier->cs);
	free(barrier->cs);
	free(barrier->cv);
	return 0;
}


/****************************************************************************
 ****************************************************************************/
int
pixie_barrier_wait(pixie_barrier_t *barrier)
{
	EnterCriticalSection((CRITICAL_SECTION*)barrier->cs);

	/* Wait until everyone exits the barrier */
	while (barrier->total > _PTHREAD_BARRIER_FLAG)
		SleepConditionVariableCS(	(CONDITION_VARIABLE*)barrier->cv, 
									(CRITICAL_SECTION*)barrier->cs, 
									INFINITE);
	
	/* Are we the first to enter? */
	if (barrier->total == _PTHREAD_BARRIER_FLAG)
		barrier->total = 0;
	
	barrier->total++;
	
	if (barrier->total == barrier->count) {
		/* Has everyone entered the wait state? */
		barrier->total += _PTHREAD_BARRIER_FLAG - 1;
		WakeAllConditionVariable((CONDITION_VARIABLE*)barrier->cv);

		LeaveCriticalSection((CRITICAL_SECTION*)barrier->cs);
		return 1;
	} else {
		/* Wait until enough threads enter the barrier */
		while (barrier->total < _PTHREAD_BARRIER_FLAG)
			SleepConditionVariableCS((CONDITION_VARIABLE*)barrier->cv, (CRITICAL_SECTION*)barrier->cs, INFINITE);
		barrier->total--;
		
		/* Get entering threads to wake up */
		if (barrier->total == _PTHREAD_BARRIER_FLAG)
			WakeAllConditionVariable((CONDITION_VARIABLE*)barrier->cv);

		LeaveCriticalSection((CRITICAL_SECTION*)barrier->cs);
		return 0;
	}
}

#endif
