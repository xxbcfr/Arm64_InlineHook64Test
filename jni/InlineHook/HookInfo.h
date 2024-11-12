#ifndef _HOOK_INFO_H
#define _HOOK_INFO_H


#include <stdio.h>
#include <Android/log.h> //用于LogCat进行显示调试
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>  //user_pt_regs结构所在头文件，用于arm64的各种寄存器的值
#include <stdbool.h>
//#include <cacheflush.h>



#define LOG_TAG "InlineHook"
//#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define OPCODEMAXLEN 24      //inline hook所需要的opcodes最大长度,arm64为20
#ifndef BYTE
#define BYTE unsigned char
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

#define BACKUP_CODE_NUM_MAX 6  //尽管备份原程序6条arm64指令
//#define __flush_cache(c, n)        __builtin___clear_cache(reinterpret_cast<char *>(c), reinterpret_cast<char *>(c) + n)

extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s;
extern unsigned long _old_function_addr_s;





//hook点信息
typedef struct TAG_INLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct user_pt_regs *);       //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE BackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
    int BackUpLength; //备份代码的长度，arm64模式下为20
    int BackUpFixLengthList[BACKUP_CODE_NUM_MAX]; //保存
    uint64_t *pNewEntryForOldFunction;
} INLINE_HOOK_INFO;

bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);
bool BuildStub(INLINE_HOOK_INFO* pInlineHook);
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);
bool RebuildHookTarget(INLINE_HOOK_INFO* pInlineHook);
extern bool HookArm(INLINE_HOOK_INFO* pInlineHook);
bool BuildOldFunction(INLINE_HOOK_INFO* pInlineHook);
bool ChangePageProperty(void *pAddress, size_t Size);

#endif