#include <vector>
#include <dlfcn.h>


extern "C"
{
    #include "HookInfo.h"
}

void InputHookInfo() __attribute__((constructor));
void IsLoader() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoManager;
static InlineHookInfoManager __InlineHookInfoManager;     

bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *))
{
    bool ReturnValue = false;
    LOGI("InlineHook");

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return ReturnValue;
    }

    INLINE_HOOK_INFO * InlineHookInfo = new INLINE_HOOK_INFO();
    InlineHookInfo->pHookAddr = pHookAddr;
    InlineHookInfo->onCallBack = onCallBack;

    if(HookArm(InlineHookInfo) == false)
    {
        LOGI("HookArm fail");
        delete InlineHookInfo;
        return ReturnValue;
    }

    
    __InlineHookInfoManager.push_back(InlineHookInfo);
    return true;
}

bool UnInlineHook(void *pHookAddr)
{
    bool ReturnValue = false;

    if(pHookAddr == NULL)
    {
        return ReturnValue;
    }

    InlineHookInfoManager::iterator itr = __InlineHookInfoManager.begin();
    InlineHookInfoManager::iterator itrend = __InlineHookInfoManager.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            __InlineHookInfoManager.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
            {
                delete *(pTargetInlineHookInfo->ppOldFuncAddr);
            }
            delete pTargetInlineHookInfo;
            ReturnValue = true;
        }
    }

    return ReturnValue;
}
void IsLoader(){
    LOGI("Hook is auto loaded");
} 
void FakeFunction(user_pt_regs *regs){
    LOGI("FakeFunction is Successful");
}
int TestFunction(){
    int a=1;
    int b=2;
    int c=3;
    int d=4;
    int e=5;
    int f=6;
    int g=7;
    int h=8;
    int i=9;
    int j=10;
    int k=11;
    int l=12;
    int m=13;
    int sum=0;
    sum=a+b+c+d+e+f+g+h+i+j+k+l+m;
    return sum;
}
void InputHookInfo()
{
    LOGI("Input HookInfo");
    int OutCome=TestFunction();
    LOGI("计算的结果是：%d",OutCome);
    InlineHook((void*)((uint64_t)InputHookInfo-12), FakeFunction); 
    OutCome=TestFunction();
    LOGI("计算的结果是：%d",OutCome);



    void* handle=dlopen("libc.so",RTLD_NOW);
    uint64_t uiHookAddr=(uint64_t)dlsym(handle,"fopen");
    const char *filePath = "/data/local/tmp/example.txt";
    FILE *file = fopen(filePath, "r");
     LOGI("So内文件对象指针:%x",file);
    if (file == NULL) {
        LOGI("So内文件对象指针:%x",file);
        perror("Error opening file");
        return ;
    }
    fclose(file);

    InlineHook((void*)(uiHookAddr+16), FakeFunction); //*第二个参数就是Hook想要插入的功能处理函数*
}