#include "FixOpcode.h"

enum INSTRUCTION_TYPE {


	// BLX <label>
	BLX_ARM,
	// BL <label>
	BL_ARM,
	// B <label>
	B_ARM,

    // <Add by GToad>
    // B <label>
	BEQ_ARM,
    // B <label>
	BNE_ARM,
    // B <label>
	BCS_ARM,
    // B <label>
	BCC_ARM,
    // B <label>
	BMI_ARM,
    // B <label>
	BPL_ARM,
    // B <label>
	BVS_ARM,
    // B <label>
	BVC_ARM,
    // B <label>
	BHI_ARM,
    // B <label>
	BLS_ARM,
    // B <label>
	BGE_ARM,
    // B <label>
	BLT_ARM,
    // B <label>
	BGT_ARM,
    // B <label>
	BLE_ARM,
    // </Add by GToad>

	// BX PC
	BX_ARM,
	// ADD Rd, PC, Rm (Rd != PC, Rm != PC) 在对ADD进行修正时，采用了替换PC为Rr的方法，当Rd也为PC时，由于之前更改了Rr的值，可能会影响跳转后的正常功能;实际汇编中没有发现Rm也为PC的情况，故未做处理。
	ADD_ARM,
	// ADR Rd, <label>
	ADR1_ARM,
	// ADR Rd, <label>
	ADR2_ARM,
	// MOV Rd, PC
	MOV_ARM,
	// LDR Rt, <label>
	LDR_ARM,


	ADR_ARM64,

	ADRP_ARM64,

	LDR_ARM64,

	B_ARM64,

	B_COND_ARM64,

	BR_ARM64,

	BL_ARM64,

	BLR_ARM64,

	CBNZ_ARM64,

	CBZ_ARM64,

	TBNZ_ARM64,

	TBZ_ARM64,

	LDR_ARM64_32,

	UNDEFINE,
};

int LengthFixArm64(uint32_t Opcode)
{
    int Type;
    Type = GetTypeInArm64(Opcode);
    switch(Type)
    {
        case B_COND_ARM64:return 32;break;
        case BNE_ARM:
        case BCS_ARM:
        case BCC_ARM:
        case BMI_ARM:
        case BPL_ARM:
        case BVS_ARM:
        case BVC_ARM:
        case BHI_ARM:
        case BLS_ARM:
        case BGE_ARM:
        case BLT_ARM:
        case BGT_ARM:
        case BLE_ARM:return 12;break;
        case BLX_ARM:
        case BL_ARM:return 12;break;
        case B_ARM:
        case BX_ARM:return 8;break;
        case ADD_ARM:return 24;break;
        case ADR1_ARM:
        case ADR2_ARM:
        case LDR_ARM:
        case MOV_ARM:return 12;break;
        case UNDEFINE:return 4;
    }    
}


int LengthFixArm32(uint32_t Opcode)
{
    int Type;
    Type = GetTypeInArm32(Opcode);
    switch(Type)
    {
        case BEQ_ARM:
        case BNE_ARM:
        case BCS_ARM:
        case BCC_ARM:
        case BMI_ARM:
        case BPL_ARM:
        case BVS_ARM:
        case BVC_ARM:
        case BHI_ARM:
        case BLS_ARM:
        case BGE_ARM:
        case BLT_ARM:
        case BGT_ARM:
        case BLE_ARM:return 12;break;
        case BLX_ARM:
        case BL_ARM:return 12;break;
        case B_ARM:
        case BX_ARM:return 8;break;
        case ADD_ARM:return 24;break;
        case ADR1_ARM:
        case ADR2_ARM:
        case LDR_ARM:
        case MOV_ARM:return 12;break;
        case UNDEFINE:return 4;
    }    
}

static int GetTypeInArm64(uint32_t Instruction)
{
    LOGI("GetTypeInArm64 : %x", Instruction);
	if ((Instruction & 0x9F000000) == 0x10000000) {
		return ADR_ARM64;
	}
	if ((Instruction & 0x9F000000) == 0x90000000) {
		return ADRP_ARM64;
	}
    if ((Instruction & 0xFC000000) == 0x14000000) {
		return B_ARM64;
	}
    if ((Instruction & 0xFF000010) == 0x54000010) {
		return B_COND_ARM64;
	}
    if ((Instruction & 0xFC000000) == 0x94000000) {
		return BL_ARM64;
	}


    if ((Instruction & 0xFF000000) == 0x58000000) {//LDR Lliteral need to learn
		return LDR_ARM64;
	}
	if ((Instruction & 0x7F000000) == 0x35000000) {
		return CBNZ_ARM64;
	}
	if ((Instruction & 0x7F000000) == 0x34000000) {
		return CBZ_ARM64;
	}
	if ((Instruction & 0x7F000000) == 0x37000000) {
		return TBNZ_ARM64;
	}
	if ((Instruction & 0x7F000000) == 0x36000000) {
		return TBZ_ARM64;
	}

	if ((Instruction & 0xFF000000) == 0x18000000) {//LDR Lliteral 32 need to learn
		return LDR_ARM64_32;
	}
	
	return UNDEFINE;
}

static int GetTypeInArm32(uint32_t Instruction)
{
    LOGI("GetTypeInArm : %x", Instruction);
	if ((Instruction & 0xFE000000) == 0xFA000000) {
		return BLX_ARM;
	}
	if ((Instruction & 0xF000000) == 0xB000000) {
		return BL_ARM;
	}
	if ((Instruction & 0xFE000000) == 0x0A000000) {
		return BEQ_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x1A000000) {
		return BNE_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x2A000000) {
		return BCS_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x3A000000) {
		return BCC_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x4A000000) {
		return BMI_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x5A000000) {
		return BPL_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x6A000000) {
		return BVS_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x7A000000) {
		return BVC_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x8A000000) {
		return BHI_ARM;
	}
    if ((Instruction & 0xFE000000) == 0x9A000000) {
		return BLS_ARM;
	}
    if ((Instruction & 0xFE000000) == 0xAA000000) {
		return BGE_ARM;
	}
    if ((Instruction & 0xFE000000) == 0xBA000000) {
		return BLT_ARM;
	}
    if ((Instruction & 0xFE000000) == 0xCA000000) {
		return BGT_ARM;
	}
    if ((Instruction & 0xFE000000) == 0xDA000000) {
		return BLE_ARM;
	}
    if ((Instruction & 0xFE000000) == 0xEA000000) {
		return B_ARM;
	}
    
    /*
    if ((Instruction & 0xFF000000) == 0xFA000000) {
		return BLX_ARM;
	} *//*
    if ((Instruction & 0xF000000) == 0xA000000) {
		return B_ARM;
	}*/
    
	if ((Instruction & 0xFF000FF) == 0x120001F) {
		return BX_ARM;
	}
	if ((Instruction & 0xFEF0010) == 0x8F0000) {
		return ADD_ARM;
	}
	if ((Instruction & 0xFFF0000) == 0x28F0000) {
		return ADR1_ARM;
	}
	if ((Instruction & 0xFFF0000) == 0x24F0000) {
		return ADR2_ARM;		
	}
	if ((Instruction & 0xE5F0000) == 0x41F0000) {
		return LDR_ARM;
	}
	if ((Instruction & 0xFE00FFF) == 0x1A0000F) {
		return MOV_ARM;
	}
	return UNDEFINE;
}

int FixPCOpcodeArm(void *FixOpcodes , INLINE_HOOK_INFO* pInlineHook)
{
    uint64_t pc;
    uint64_t lr;
    int BackUpPos = 0;
    int FixPos = 0;
    int Offset = 0;
    //int isConditionBcode = 0;
    uint32_t *CurrentOpcode;
    uint32_t TmpFixOpcodes[40]; //对于每条PC命令的修复指令都将暂时保存在这里。
    //uint32_t tmpBcodeFix;
    //uint32_t tmpBcodeX = 0;
	//trampoline_instructions[trampoline_pos++] == 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register

    LOGI("Fixing Arm");

    CurrentOpcode = pInlineHook->BackupOpcodes + sizeof(uint8_t)*BackUpPos;
    LOGI("sizeof(uint8_t) : %D", sizeof(uint8_t));

    pc = pInlineHook->pHookAddr; //pc变量用于保存原本指令执行时的pc值
    lr = pInlineHook->pHookAddr + pInlineHook->BackUpLength;

    if(pInlineHook == NULL)
    {
        LOGI("pInlineHook is null");
    }

	TmpFixOpcodes[0] = 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register
	Offset = 4;
	memcpy(FixOpcodes+FixPos, TmpFixOpcodes, Offset);
	FixPos=+Offset;

    while(1) // 在这个循环中，每次都处理一个arm64命令
    {
        //LOGI("-------------START----------------");
        LOGI("currentOpcode is %x",*CurrentOpcode);
        
        Offset = FixPCOpcodeArm64(pc, lr, *CurrentOpcode, TmpFixOpcodes, pInlineHook);
        //LOGI("isConditionBcode : %d", isConditionBcode);
        //LOGI("offset : %d", offset);
        memcpy(FixOpcodes+FixPos, TmpFixOpcodes, Offset);
        /*
        if (isConditionBcode==1) { // the first code is B??
            if (backUpPos == 4) { // the second has just been processed
                LOGI("Fix the first b_code.");
                LOGI("offset : %d",offset);
                tmpBcodeFix += (offset/4 +1);
                memcpy(fixOpcodes, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 1.");

                tmpBcodeFix = 0xE51FF004;
                LOGI("Fix the first b_code 1.5");
                memcpy(fixOpcodes+fixPos+offset, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 2.");

                tmpBcodeFix = pstInlineHook->pHookAddr + 8;
                memcpy(fixOpcodes+fixPos+offset+4, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 3.");

                tmpBcodeFix = 0xE51FF004;
                memcpy(fixOpcodes+fixPos+offset+8, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 4.");

                tmpBcodeFix = tmpBcodeX;
                memcpy(fixOpcodes+fixPos+offset+12, &tmpBcodeFix, 4);
                LOGI("Fix the first b_code 5.");

                offset += 4*4;
            }
            else if (backUpPos == 0) { //save the first B code
                tmpBcodeFix = (*currentOpcode & 0xFE000000);
                tmpBcodeX = (*currentOpcode & 0xFFFFFF) << 2; // x*4
                LOGI("tmpBcodeX : %x", tmpBcodeX);
                tmpBcodeX = tmpBcodeX + 8 + pstInlineHook->pHookAddr;
            }
        }*/
        
        BackUpPos += 4; //arm32的话下一次取后面4 byte偏移的指令
        pc += sizeof(uint32_t);

        FixPos += Offset;
        //LOGI("fixPos : %d", fixPos);
        //LOGI("--------------END-----------------");

        if (BackUpPos < pInlineHook->BackUpLength)
        {
			LOGI("ONE FINISH");
            CurrentOpcode = pInlineHook->BackupOpcodes + sizeof(uint8_t)*BackUpPos;
        }
        else{
            LOGI("pInlineHook->BackUpLength : %d", pInlineHook->BackUpLength);
            LOGI("backUpPos : %d",BackUpPos);
            LOGI("fixPos : %d", FixPos);
            LOGI("Fix finish !");
            return FixPos;
        }
    }

    LOGI("Something wrong in arm64 fixing...");

    return 0;
}

int FixBcond(uint64_t pc, uint64_t lr, uint32_t Instruction, uint32_t *TrampolineInstructions, INLINE_HOOK_INFO* pInlineHook)
{
	
}

int FixPCOpcodeArm64(uint64_t pc, uint64_t lr, uint32_t Instruction, uint32_t *TrampolineInstructions, INLINE_HOOK_INFO* pInlineHook)
{
    int Type;
	//int offset;
    int TrampolinePos;
    uint32_t NewEntryAddr = (uint32_t)pInlineHook->pNewEntryForOldFunction;
    LOGI("NewEntryAddr : %x",NewEntryAddr);

    TrampolinePos = 0;
	//TrampolineInstructions[TrampolinePos++] == 0xf85f83e0; // ldr x0, [sp, #-0x8] recover the x0 register
    LOGI("THE ARM64 OPCODE IS %x",Instruction);
    Type = GetTypeInArm64(Instruction);
    //Type = GetTypeInArm(instruction); //判断该arm指令的种类
	
	if (Type == B_COND_ARM64) {
		//STP X_tmp1, X_tmp2, [SP, -0x10]
		//LDR X_tmp2, ?
		//[target instruction fix code] if you want
		//BR X_tmp2
		//B 8
		//PC+imm*4
        LOGI("B_COND_ARM64");
		uint32_t TargetIns;
		uint32_t Imm19;
		uint64_t Value;

		Imm19 = (Instruction & 0xFFFFE0) >> 5;
		Value = pc + Imm19*4;
		if((Imm19>>18)==1){
			Value = pc - 4*(0x7ffff-Imm19+1);
		}
		if(IsTargetAddrInBackup(Value, (uint64_t)pInlineHook->pHookAddr, pInlineHook->BackUpLength)){
			//backup to backup
			//B.COND ???
			//B 28
			int TargetIdx = (int)((Value - (uint64_t)pInlineHook->pHookAddr)/4);
			int BcInsIdx = (int)((pc - (uint64_t)pInlineHook->pHookAddr)/4);
			int Idx = 0;
			int Gap = 0;
			for(Idx=BcInsIdx+1;Idx<TargetIdx;Idx++){
				Gap += pInlineHook->BackUpFixLengthList[Idx];
			}
			TrampolineInstructions[TrampolinePos++] = (Instruction & 0xff00000f) + ((Gap+32)<<3); // B.XX 32+gap
			TrampolineInstructions[TrampolinePos++] = 0x14000007; //B 28
		}
		else{
			//backup to outside
			TargetIns = *((uint32_t *)Value);
			TrampolineInstructions[TrampolinePos++] = ((Instruction & 0xff00000f) + (32<<3)) ^ 0x1; // B.anti_cond 32
			TrampolineInstructions[TrampolinePos++] = TargetIns; //target_ins (of cource the target ins maybe need to fix, do it by yourself if you need)
			TrampolineInstructions[TrampolinePos++] = 0xa93f03e0; //STP X0, X0, [SP, -0x10] default
			TrampolineInstructions[TrampolinePos++] = 0x58000080; //LDR X0, 12
			TrampolineInstructions[TrampolinePos++] = 0xd61f0000; //BR X0
			TrampolineInstructions[TrampolinePos++] = 0x14000002; //B 8
			TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value >> 32);
			TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value & 0xffffffff);
		}
		
        return 4*TrampolinePos;
    }
	if (Type == ADR_ARM64) {
		//LDR Rn, 4
		//PC+imm*4
        LOGI("ADR_ARM64");
		uint32_t Imm21;
		uint64_t Value;
		uint32_t rd;
		Imm21 = ((Instruction & 0xFFFFE0)>>3) + ((Instruction & 0x60000000)>>29);
		Value = pc + 4*Imm21;
		if((Imm21 & 0x100000)==0x100000)
		{
			LOGI("NEG");
			Value = pc - 4 * (0x1fffff - Imm21 + 1);
		}
		LOGI("value : %x",Value);
		
		rd = Instruction & 0x1f;
		TrampolineInstructions[TrampolinePos++] = 0x58000020+rd; // ldr rd, 4
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value >> 32);
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value & 0xffffffff);

        return 4*TrampolinePos;
    }
    if (Type == ADRP_ARM64) {
		//LDR Rn, 8
		//B 12
		//PC+imm*4096
        LOGI("ADRP_ARM64");
		uint32_t Imm21;
		uint64_t Value;
		uint32_t rd;
		Imm21 = ((Instruction & 0xFFFFE0)>>3) + ((Instruction & 0x60000000)>>29);
		Value = (pc & 0xfffffffffffff000) + 4096*Imm21;
		if((Imm21 & 0x100000)==0x100000)
		{
			LOGI("NEG");
			Value = (pc & 0xfff) - 4096 * (0x1fffff - Imm21 + 1);
		}
		LOGI("pc    : %lx",pc);
		LOGI("imm21 : %x",Imm21);
		LOGI("value : %lx",Value);
		LOGI("valueh : %x",(uint32_t)(Value >> 32));
		LOGI("valuel : %x",(uint32_t)(Value & 0xffffffff));
		
		rd = Instruction & 0x1f;
		TrampolineInstructions[TrampolinePos++] = 0x58000040+rd; // ldr rd, 8
		TrampolineInstructions[TrampolinePos++] = 0x14000003; // b 12
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value & 0xffffffff);
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value >> 32);
		

        return 4*TrampolinePos;
    }
    if (Type == LDR_ARM64) {
		//STP Xt, Xn, [SP, #-0x10]
		//LDR Xn, 16
		//LDR Xt, [Xn, 0]
		//LDR Xn, [sp, #-0x8]
		//B 8
		//PC+imm*4
        LOGI("LDR_ARM64");
		uint32_t Imm19;
		uint64_t Value;
		uint32_t rt;
		uint32_t rn;
		rt = Instruction & 0x1f;
		int i;
		for(i=0;i<31;i++)
		{
			if(i!=rt){
				rn = i;
				break;
			}
		}
		LOGI("Rn : %d",rn);
		Imm19 = ((Instruction & 0xFFFFE0)>>5);
		TrampolineInstructions[TrampolinePos++] = 0xa93f03e0 + rt + (rn << 10); //STP Xt, Xn, [SP, #-0x10]
		TrampolineInstructions[TrampolinePos++] = 0x58000080 + rn; //LDR Xn, 16
		TrampolineInstructions[TrampolinePos++] = 0xf9400000 + (rn << 5); //LDR Xt, [Xn, 0]
		TrampolineInstructions[TrampolinePos++] = 0xf85f83e0 + rn; //LDR Xn, [sp, #-0x8]
		TrampolineInstructions[TrampolinePos++] = 0x14000002; //B 8

		Value = pc + 4*Imm19;
		if((Imm19 & 0x40000)==0x40000){
			Value = pc - 4*(0x7ffff-Imm19+1);
		}
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value >> 32);
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value & 0xffffffff);

        return 4*TrampolinePos;
    }
	if (Type == B_ARM64) {
		//STP X_tmp1, X_tmp2, [SP, -0x10]
		//LDR X_tmp2, ?
		//[target instruction fix code] if you want
		//BR X_tmp2
		//B 8
		//PC+imm*4
        LOGI("B_ARM64");
		uint32_t TargetIns;
		uint32_t Imm26;
		uint64_t Value;

		Imm26 = Instruction & 0x3FFFFFF;
		Value = pc + Imm26*4;
		if((Imm26>>25)==1){
			Value = pc - 4*(0x3ffffff-Imm26+1);
		}
		TargetIns = *((uint32_t *)Value);
		LOGI("target_ins : %x",TargetIns);

		TrampolineInstructions[TrampolinePos++] = 0xa93f03e0; //STP X0, X0, [SP, -0x10] default
		TrampolineInstructions[TrampolinePos++] = 0x58000080; //LDR X0, 16
		TrampolineInstructions[TrampolinePos++] = TargetIns; //[target instruction fix code] if you want
		TrampolineInstructions[TrampolinePos++] = 0xd61f0000; //BR X0
		TrampolineInstructions[TrampolinePos++] = 0x14000002; //B 8
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value >> 32);
		TrampolineInstructions[TrampolinePos++] = (uint32_t)(Value & 0xffffffff);

        return 4*TrampolinePos;
    }
	else {
        LOGI("OTHER_ARM");
		TrampolineInstructions[TrampolinePos++] = Instruction;
        return 4*TrampolinePos;
	}
	//pc += sizeof(uint32_t);
	
	//trampoline_instructions[trampoline_pos++] = 0xe51ff004;	// LDR PC, [PC, #-4]
	//trampoline_instructions[trampoline_pos++] = lr;
    return 4*TrampolinePos;
}

bool IsTargetAddrInBackup(uint64_t TargetAddr, uint64_t HookAddr, int BackupLength)
{
    if((TargetAddr<=HookAddr+BackupLength)&&(TargetAddr>=HookAddr))
        return true;
    return false;
}