#ifndef _FIXOPCODE_H
#define _FIXOPCODE_H

#include <stdio.h>
#include "HookInfo.h"

#define ALIGN_PC(pc)	(pc & 0xFFFFFFFC)

bool IsTargetAddrInBackup(uint64_t TargetAddr, uint64_t HookAddr, int BackupLength);

int LengthFixArm64(uint32_t Opcode);
int LengthFixArm32(uint32_t Opcode);

static int GetTypeInArm64(uint32_t Instruction);
static int GetTypeInArm32(uint32_t Instruction);

int FixPCOpcodeArm(void *FixOpcodes , INLINE_HOOK_INFO* pInlineHook);

int FixPCOpcodeArm64(uint64_t pc, uint64_t lr, uint32_t Instruction, uint32_t *TrampolineInstructions, INLINE_HOOK_INFO* pInlineHook);


#endif