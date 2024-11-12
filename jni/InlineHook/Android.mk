LOCAL_PATH := $(call my-dir)  


include $(CLEAR_VARS)

LOCAL_CXXFLAGS +=  -g -O0
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := HookInfo
LOCAL_SRC_FILES := HookInfo.c Hookstub.s FixOpcode.c
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_STATIC_LIBRARY)
