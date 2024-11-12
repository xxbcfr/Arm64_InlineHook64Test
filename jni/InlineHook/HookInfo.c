#include "HookInfo.h"
#include "FixOpcode.h"


bool HookArm(INLINE_HOOK_INFO* pInlineHook)
{
    bool ReturnValue = false;
    LOGI("执行到HookArm");
    
    while(1)
    {  
        if(pInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //设置ARM下的inline hook的基础信息
        if(InitArmHookInfo(pInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail");
            break;
        }
        LOGI("Step2");
        
        //LOGI("BuildStub fail 1.");
        //第二步，构造stub，功能是保存寄存器状态，同时跳转到目标函数，然后跳转回原函数
        //需要目标地址，返回stub地址，同时还有old指针给后续填充 
        if(BuildStub(pInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        LOGI("Step3");
        
        //LOGI("BuildOldFunction fail 1.");
        //第四步，负责重构原函数头，功能是修复指令，构造跳转回到原地址下
        //需要原函数地址
        
        if(BuildOldFunction(pInlineHook) == false)
        {
            LOGI("BuildOldFunction fail");
            break;
        }
        LOGI("LIVE4");
        
        //LOGI("RebuildHookAddress fail 1.");
        //第一步，负责重写原函数头，功能是实现inline hook的最后一步，改写跳转
        //需要cacheflush，防止崩溃
        if(RebuildHookTarget(pInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        LOGI("Step5");
        
        ReturnValue = true;
        break;
    }
    LOGI("Step6");

    return ReturnValue;
}

bool InitArmHookInfo(INLINE_HOOK_INFO* pInlineHook)
{
    bool ReturnValue = false;
    uint32_t *CurrentOpcode = pInlineHook->pHookAddr;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pInlineHook->BackUpFixLengthList[i] = -1;
    }
    LOGI("pInlineHook->BackupOpcodes is at %x",pInlineHook->BackupOpcodes);

    
    if(pInlineHook == NULL)
    {
        LOGI("pInlineHook is null");
        return ReturnValue;
    }

    pInlineHook->BackUpLength = 24;
    
    memcpy(pInlineHook->BackupOpcodes, pInlineHook->pHookAddr, pInlineHook->BackUpLength);

    for(int i=0;i<6;i++){
        //currentOpcode += i; //GToad BUG
        LOGI("Arm64 Opcode to fix %d : %x",i,*CurrentOpcode);
        LOGI("Fix length : %d",LengthFixArm32(*CurrentOpcode));
        pInlineHook->BackUpFixLengthList[i] = LengthFixArm64(*CurrentOpcode);
        CurrentOpcode += 1; //GToad BUG
    }
    
    return true;
}

bool BuildStub(INLINE_HOOK_INFO* pInlineHook)
{
    bool ReturnValue = false;
    
    while(1)
    {
        if(pInlineHook == NULL)
        {
            LOGI("pInlineHook is null");
            break;
        }
        
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;

        size_t ShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        //malloc一段新的stub代码
        void *pNewShellCode = malloc(ShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, ShellCodeLength);
        //更改stub代码页属性，改成可读可写可执行
        if(ChangePageProperty(pNewShellCode, ShellCodeLength) == false)
        {
            LOGI("change shell code page property fail");
            break;
        }

        //设置跳转到外部stub函数去
        LOGI("_hookstub_function_addr_s : %lx",p_hookstub_function_addr_s);
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pInlineHook->onCallBack;
        LOGI("ppHookStubFunctionAddr : %lx",ppHookStubFunctionAddr);
        LOGI("*ppHookStubFunctionAddr : %lx",*ppHookStubFunctionAddr);
        
        //备份外部stub函数运行完后跳转的函数地址指针，用于填充老函数的新地址
        pInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
            
        //填充shellcode地址到hookinfo中，用于构造hook点位置的跳转指令
        pInlineHook->pStubShellCodeAddr = pNewShellCode;

        

        ReturnValue = true;
        break;
    }
    
    return ReturnValue;
}
bool BuildOldFunction(INLINE_HOOK_INFO* pInlineHook)
{
    bool ReturnValue = false;

    void *FixOpcodes;
    int FixLength;
    LOGI("Step3.1");

    FixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    LOGI("Step3.2");
    while(1)
    {
        if(pInlineHook == NULL)
        {
            LOGI("pInlineHook is null");
            break;
        }
        LOGI("Step3.3");
        
        //8个bytes存放原来的opcodes，另外8个bytes存放跳转回hook点下面的跳转指令
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }
        LOGI("Step3.4");

        pInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        LOGI("%x",pNewEntryForOldFunction);
        
        if(ChangePageProperty(pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        LOGI("Step3.5");
        
        FixLength =FixPCOpcodeArm(FixOpcodes, pInlineHook); //把第三部分的起始地址传过去
        memcpy(pNewEntryForOldFunction, FixOpcodes, FixLength);
        LOGI("Step3.6");
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //填充跳转指令
        if(BuildArmJumpCode(pNewEntryForOldFunction + FixLength, pInlineHook->pHookAddr + pInlineHook->BackUpLength - 4) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("Step3.7");
        //填充shellcode里stub的回调地址
        *(pInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        LOGI("Step3.8");
        
        ReturnValue = true;
        break;
    }
    LOGI("Step3.9");
    
    return ReturnValue;
}

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    LOGI("Step4.3.1");
    bool ReturnValue = false;
    while(1)
    {
        LOGI("Step4.3.2");
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null");
            break;
        }    
        LOGI("Step4.3.3");    
        //LDR PC, [PC, #-4]
        //addr
        //LDR PC, [PC, #-4]对应的机器码为：0xE51FF004
        //addr为要跳转的地址。该跳转指令范围为32位，对于32位系统来说即为全地址跳转。
        //缓存构造好的跳转指令（ARM下32位，两条指令只需要8个bytes）
        //BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};

        //STP X1, X0, [SP, #-0x10]
        //LDR X0, 8
        //BR X0
        //ADDR(64)
        //LDR X0, [SP, -0x8]
        BYTE LdrPCOpcodes[24] = {0xe1, 0x03, 0x3f, 0xa9, 0x40, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6};
        //将目的地址拷贝到跳转指令缓存位置
        memcpy(LdrPCOpcodes + 12, &pJumpAddress, 8);
        LdrPCOpcodes[20] = 0xE0;
        LdrPCOpcodes[21] = 0x83;
        LdrPCOpcodes[22] = 0x5F;
        LdrPCOpcodes[23] = 0xF8;
        LOGI("Step4.3.4");
        
        //将构造好的跳转指令刷进去
        memcpy(pCurAddress, LdrPCOpcodes, 24);
        LOGI("Step4.3.5");
        //__flush_cache(*((uint32_t*)pCurAddress), 20);
        //__builtin___clear_cache (*((uint64_t*)pCurAddress), *((uint64_t*)(pCurAddress+20)));
        //cacheflush(*((uint32_t*)pCurAddress), 20, 0);
        LOGI("Step4.3.6");
        ReturnValue = true;
        break;
    }
    LOGI("Step4.3.7");
    return ReturnValue;
}
bool RebuildHookTarget(INLINE_HOOK_INFO* pInlineHook)
{
    bool ReturnValue = false;
    
    while(1)
    {
        LOGI("Step4.1");
        if(pInlineHook == NULL)
        {
            LOGI("pInlineHook is null");
            break;
        }
        LOGI("Step4.2");
        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pInlineHook->pHookAddr, 24) == false)
        {
            LOGI("change page property error.");
            break;
        }
        LOGI("Step4.3");
        //填充跳转指令
        if(BuildArmJumpCode(pInlineHook->pHookAddr, pInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        LOGI("Step4.4");
        ReturnValue = true;
        break;
    }
    LOGI("Step4.5");
    
    return ReturnValue;
}
bool ChangePageProperty(void *pAddress, size_t Size)
{
    bool ReturnValue = false;
    
    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return ReturnValue;
    }
    
    //计算包含的页数、对齐起始地址
    unsigned long PageSize = sysconf(_SC_PAGESIZE); //得到页的大小
    int Protect = PROT_READ | PROT_WRITE | PROT_EXEC;
    unsigned long NewPageStartAddress = (unsigned long)(pAddress) & ~(PageSize - 1); //pAddress & 0x1111 0000 0000 0000
    long PageCount = (Size / PageSize) + 1;
    
    long l = 0;
    while(l < PageCount)
    {
        //利用mprotect改页属性
        int IsOk = mprotect((const void *)(NewPageStartAddress), PageSize, Protect);
        if(-1 == IsOk)
        {
            LOGI("mprotect error:%s", strerror(errno));
            return ReturnValue;
        }
        l++; 
    }
    
    return true;
}
