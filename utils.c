#include "arm_single.h"
#include "utils.h"
#include "tracer.h"

char arm_instr_group_name[34][32] = {
	"ARM_GRP_INVALID",
	"ARM_GRP_JUMP",
	"ARM_GRP_CRYPTO",
	"ARM_GRP_DATABARRIER",
	"ARM_GRP_DIVIDE",
	"ARM_GRP_FPARMV8",
	"ARM_GRP_MULTPRO",
	"ARM_GRP_NEON",
	"ARM_GRP_T2EXTRACTPACK",
	"ARM_GRP_THUMB2DSP",
	"ARM_GRP_TRUSTZONE",
	"ARM_GRP_V4T",
	"ARM_GRP_V5T",
	"ARM_GRP_V5TE",
	"ARM_GRP_V6",
	"ARM_GRP_V6T2",
	"ARM_GRP_V7",
	"ARM_GRP_V8",
	"ARM_GRP_VFP2",
	"ARM_GRP_VFP3",
	"ARM_GRP_VFP4",
	"ARM_GRP_ARM",
	"ARM_GRP_MCLASS",
	"ARM_GRP_NOTMCLASS",
	"ARM_GRP_THUMB",
	"ARM_GRP_THUMB1ONLY",
	"ARM_GRP_THUMB2",
	"ARM_GRP_PREV8",
	"ARM_GRP_FPVMLX",
	"ARM_GRP_MULOPS",
	"ARM_GRP_CRC",
	"ARM_GRP_DPVFP",
	"ARM_GRP_V6M",
	"ARM_GRP_ENDING"
};

// Find the start address of Keyword in the 'maps' file
int getMapsAddr(pid_t pid, const char * keyword, mapdump_t * target_map)
{
	char szMapsPath[128];
	char szTemp[256] = {0,};
	char sprt[] = " \t";
	char *token;

	FILE *pFile;

	sprintf(szMapsPath, "/proc/%d/maps", pid);

	pFile = fopen(szMapsPath, "r");

	if(pFile == NULL) {
		return 0;
	}

	int i, j, count = 0;

	while(!feof(pFile))
	{
		for ( i = 0 ; !feof(pFile) && (szTemp[i] = fgetc(pFile)) != 0x0a ; i++ );

		if( strstr(szTemp, keyword) != NULL )
		{
			//fprintf(stderr, "%s", szTemp);

			token = strtok( szTemp, sprt );

			target_map[count].map_start_addr = 0;
			target_map[count].map_end_addr = 0;
			sscanf(token, "%x-%x", &target_map[count].map_start_addr, &target_map[count].map_end_addr);

			for ( j = 0 ; j < 5 ; j++ ) {
				token = strtok( NULL, sprt );
			}
			sscanf(token, "%s", &target_map[count].map_name);

			count++;
		}
		memset(szTemp, 0x00, 256);
	}
	fclose(pFile);

	return count;
}

// Using the 'maps' file, Find a function address in Library
unsigned long getLibFuncAddr(pid_t pid, const char * lname, const char * fname)
{
	int memsize, asdf = 0;

	unsigned long offset;
	unsigned long addr_func_debugger;
	unsigned long addr_func_debuggee;

	void *hLibc;

	mapdump_t map_libc_debugger[3], map_libc_debuggee[3];

	memsize = getMapsAddr(getpid(), lname, map_libc_debugger);
	memsize = getMapsAddr(pid, lname, map_libc_debuggee);

	if(map_libc_debugger == NULL || map_libc_debuggee == NULL) {
		return 0;
	}

	offset = map_libc_debugger[asdf].map_start_addr - map_libc_debuggee[asdf].map_start_addr;

	hLibc = dlopen(lname, RTLD_LAZY);

	if(hLibc == NULL) {
		return 0;
	}

	map_libc_debugger[asdf].map_start_addr = (unsigned long)dlsym(hLibc, fname);

	dlclose(hLibc);

	addr_func_debuggee = map_libc_debugger[asdf].map_start_addr - offset;

	return addr_func_debuggee;
}

void simple_disassem(int mode, arm_regs * regs, unsigned long instr) 
{
	int instr_len;
	size_t  cnt;
	csh handle;
	cs_mode cmode;
	cs_insn *insn;

	// Thumb state
	if ( mode == 1 ) {
		cmode = CS_MODE_THUMB;
		unsigned short inst1;
		memcpy(&inst1, &instr, 2);
		instr_len = thumb_insn_size(inst1);
	}
	// ARM state
	else {
		cmode = CS_MODE_ARM;
		instr_len = 4;
	}

	if ( cs_open(CS_ARCH_ARM, cmode, &handle) != CS_ERR_OK ) {
		perror("[Disassem_Open] ");
	}
	else {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cnt = cs_disasm(handle, (char *)&instr, instr_len, 0x0, 0, &insn);
		if ( cnt > 0 ) {
			fprintf(stdout, "\t%s\t%s\n", insn[0].mnemonic, insn[0].op_str);

			// free memory allocated by cs_disasm_ex()
			cs_free(insn, cnt);
		}
		else {
			fprintf(stderr, "Can't Disassemble\n");
		}
		cs_close(&handle);
	}
}

void disassem(unsigned long * mode, int instr_len, Instruction * curr_ins, arm_regs * regs)
{
	size_t cnt;
	csh	handle;
	cs_mode	cmode;
	cs_insn	*insn;
	
	if ( *mode == CPSR_T ) {
		cmode = CS_MODE_THUMB;
	}
	else {
		cmode = CS_MODE_ARM;
	}

	if ( cs_open(CS_ARCH_ARM, cmode, &handle) != CS_ERR_OK ) {
		perror("[Disassem_Open] ");
	}
	else {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cnt = cs_disasm(handle, (char *)&curr_ins->instrs, instr_len, 0x0, 0, &insn);
		if ( cnt > 0 ) {
			strncpy(log_entry.Members.Mnemonic, insn[0].mnemonic, sizeof(log_entry.Members.Mnemonic));
			strncpy(log_entry.Members.OperandStr, insn[0].op_str, sizeof(log_entry.Members.OperandStr));
			//memcpy(log_entry.Members.Mnemonic, insn[0].mnemonic, strlen(insn[0].mnemonic));
			//memcpy(log_entry.Members.OperandStr, insn[0].op_str, sizeof(log_entry.Members.OperandStr));


			if ( DEBUG_MSG_PRINT > 0 ) {
				if ( instr_len == 2 ) {
					fprintf(stderr, "\t\t\t=> [ %s\t%s ]\n", insn[0].mnemonic, insn[0].op_str);
				}
				else {
					fprintf(stderr, "\t=> [ %s\t%s ]\n", insn[0].mnemonic, insn[0].op_str);
				}
			}

			// Detail Print
			int i;
			cs_arm *arm = &(insn->detail->arm);
			if ( DEBUG_MSG_PRINT > 2 ) {
				fprintf(stderr, "\tInstruction-Mnemonic : %s\n", cs_insn_name(handle, insn->id));
				for ( i = 0 ; i < insn->detail->groups_count ; i++ ) {
					fprintf(stderr, "\tInstruction-Groups : %s\n", arm_instr_group_name[insn->detail->groups[i]]);
				}
				if (arm->op_count) {
					fprintf(stderr, "\top_count: %u\n", arm->op_count);
				}
			}

			int op_num = 0;
			int reg_num = 0;
			for (i = 0; i < arm->op_count; i++) {
				cs_arm_op *op = &(arm->operands[i]);
				switch((int)op->type) {
					default:
						break;
					case ARM_OP_REG:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: REG = %d, %s\n", i, op->reg, cs_reg_name(handle, op->reg));
						}
						if ( op->reg >= 66 ) {
							log_entry.Members.Operands[op_num++] = regs->uregs[op->reg - 66];
							reg_num++;
						}
						else if ( op->reg == 10 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_lr;
							reg_num++;
						}
						else if ( op->reg == 11 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_pc;
							reg_num++;
						}
						else if ( op->reg == 12 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_sp;
							reg_num++;
						}

						break;
					case ARM_OP_IMM:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
						}
						log_entry.Members.Operands[op_num++] = op->imm;
						break;
					case ARM_OP_FP:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: FP = %f\n", i, op->fp);
						}
						log_entry.Members.Operands[op_num++] = op->fp;
						reg_num++;
						break;
					case ARM_OP_MEM:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: MEM\n", i);
						}
						if (op->mem.base != ARM_REG_INVALID) {
							if ( DEBUG_MSG_PRINT > 2 ) {
								fprintf(stderr, "\t\t\toperands[%u].mem.base: REG = %d, %s\n",
									i, op->mem.base, cs_reg_name(handle, op->mem.base));
							}
							if ( op->mem.base >= 66 ) {
								log_entry.Members.Operands[op_num++] = regs->uregs[op->mem.base - 66];
								reg_num++;
							}
							else if ( op->mem.base == 10 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_lr;
								reg_num++;
							}
							else if ( op->mem.base == 11 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_pc;
								reg_num++;
							}
							else if ( op->mem.base == 12 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_sp;
								reg_num++;
							}
						}
						if (op->mem.index != ARM_REG_INVALID) {
							if ( DEBUG_MSG_PRINT > 2 ) {
								fprintf(stderr, "\t\t\toperands[%u].mem.index: REG = %d, %s\n",
									i, op->mem.index, cs_reg_name(handle, op->mem.index));
							}
							if ( op->mem.index >= 66 ) {
								log_entry.Members.Operands[op_num++] = regs->uregs[op->mem.index - 66];
								reg_num++;
							}
							else if ( op->mem.index == 10 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_lr;
								reg_num++;
							}
							else if ( op->mem.index == 11 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_pc;
								reg_num++;
							}
							else if ( op->mem.index == 12 ) {
								log_entry.Members.Operands[op_num++] = regs->ARM_sp;
								reg_num++;
							}
						}
						if (op->mem.scale != 1) {
							if ( DEBUG_MSG_PRINT > 2 ) {
								fprintf(stderr, "\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
							}
							log_entry.Members.Operands[op_num++] = op->mem.scale;
							reg_num++;
						}
						if (op->mem.disp != 0) {
							if ( DEBUG_MSG_PRINT > 2 ) {
								fprintf(stderr, "\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
							}
							log_entry.Members.Operands[op_num++] = op->mem.disp;
						}
						break;
					case ARM_OP_PIMM:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
						}
						log_entry.Members.Operands[op_num++] = op->imm;
						break;
					case ARM_OP_CIMM:
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
						}
						log_entry.Members.Operands[op_num++] = op->imm;
						break;
				}

				if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
					if (op->shift.type < ARM_SFT_ASR_REG) {
						// shift with constant value
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
						}
						log_entry.Members.Operands[op_num++] = op->shift.value;
					}
					else {
						// shift with register
						if ( DEBUG_MSG_PRINT > 2 ) {
							fprintf(stderr, "\t\t\tShift: %u = %d, %s\n", op->shift.type,
								op->shift.value, cs_reg_name(handle, op->shift.value));
						}
						if ( op->shift.value >= 66 ) {
							log_entry.Members.Operands[op_num++] = regs->uregs[op->shift.value - 66];
							reg_num++;
						}
						else if ( op->shift.value == 10 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_lr;
							reg_num++;
						}
						else if ( op->shift.value == 11 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_pc;
							reg_num++;
						}
						else if ( op->shift.value == 12 ) {
							log_entry.Members.Operands[op_num++] = regs->ARM_sp;
							reg_num++;
						}
					}
				}
			}
			if ( arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID ) {
				if ( DEBUG_MSG_PRINT > 2 ) {
					fprintf(stderr, "\t\tCode Condition: %u\n", arm->cc);
				}
				if ( arm->cc >= 66 ) {
					log_entry.Members.Operands[op_num++] = regs->uregs[arm->cc - 66];
					reg_num++;
				}
				else if ( arm->cc == 10 ) {
					log_entry.Members.Operands[op_num++] = regs->ARM_lr;
					reg_num++;
				}
				else if ( arm->cc == 11 ) {
					log_entry.Members.Operands[op_num++] = regs->ARM_pc;
					reg_num++;
				}
				else if ( arm->cc == 12 ) {
					log_entry.Members.Operands[op_num++] = regs->ARM_sp;
					reg_num++;
				}
			}

			// free memory allocated by cs_disasm_ex()
			cs_free(insn, cnt);

			log_entry.Members.BitMask = (log_entry.Members.BitMask | reg_num);
		}
		else {
			memset(log_entry.Members.Mnemonic, 0x00, sizeof(log_entry.Members.Mnemonic));
			memset(log_entry.Members.OperandStr, 0x00, sizeof(log_entry.Members.OperandStr));
			strncpy(log_entry.Members.Mnemonic, "udf", sizeof(log_entry.Members.Mnemonic));
			strncpy(log_entry.Members.OperandStr, "Can't Disassemble", sizeof(log_entry.Members.OperandStr));
			fprintf(stderr, "Can't Disassemble\n");
		}
		cs_close(&handle);
	}
}

int strexHandler(unsigned long * mode, pid_t * pid, unsigned long * curr_pc, unsigned long * next_pc, Instruction * curr_ins, Instruction * bkup_ins, arm_regs * regs)
{
	int instr_len, cnt;
	int handler = 0;
	Instruction next_ins;

	if ( *mode == CPSR_T ) {

		unsigned short inst1;
		memcpy(&inst1, &(curr_ins->instrs), 2);

		instr_len = thumb_insn_size (inst1);

		// Thumb
		if ( instr_len == 2 ) {
			if ( (curr_ins->instrs&0x0000FF00) == 0x00004700 ) {
				// BX, BLX
				handler = 1;
			}
			else if ( (curr_ins->instrs&0x0000F000) == 0x0000D000 ) {
				if ( (curr_ins->instrs&0x00000E00) != 0x00000E00 ) {
					// B
					handler = 1;
				}
			}
		}
		// Thumb2
		else {
			if ( (curr_ins->instrs&0xF8008000) == 0xF0008000 ) {
				if ( (curr_ins->instrs&0x0000D000) == 0x00008000 ) {
					if ( (curr_ins->instrs&0x0FF00000) == 0x03C00000 ) {
						// BXJ
						handler = 1;
					}
					else if ( (curr_ins->instrs&0x0B800000) != 0x03800000 ) {
						// B
						handler = 1;
					}
				}
				else if ( (curr_ins->instrs&0x0000D000) == 0x00009000 ) {
					// B
					handler = 1;
				}
				else if ( (curr_ins->instrs&0x0000C000) == 0x0000C000 ) {
					// BL, BLX
					handler = 1;
				}
			}
		}

		/* [THUMB] LDREX,STREX Handler (Branch) on Android */
		if ( handler == 1 ) {
			*next_pc = *curr_pc + (instr_len + 1);

			// Current PC, Instruction Print
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Disassemble the current instruction
			disassem( mode, instr_len, curr_ins, regs );

			// Print the Next PC and instruction
			next_ins.instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)UNMAKE_THUMB_ADDR(*next_pc), NULL);

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tNEXT(4) : 0x%.8lX\t", UNMAKE_THUMB_ADDR(*next_pc));
				for ( cnt = 0 ; cnt <= 3 ; cnt++ ) {
					fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
				}
				fprintf(stderr, "\n");
			}

			bkup_ins->instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)*next_pc, NULL);
			ptrace(PTRACE_POKEDATA, *pid, (void *)*next_pc, (void *)thumb_breakpoint);

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "-[THUMB]\tSTREX HANDLE IT\n");
			}

			return 0;
		}
	}
	else {
		if ( (curr_ins->instrs&0x0FF000C0) == 0x01200000 ) {
			// BX, BXJ, BLX
			handler = 1;
		}
		else if ( (curr_ins->instrs&0x0E000000) == 0x0A000000 ) {
			// B, BL, BLX
			handler = 1;
		}

		// CVE TEST... TEMP Condition * FIXME *
		if ( (curr_ins->instrs&0x012FFF1E) == 0x012FFF1E ) {
			*next_pc = regs->ARM_lr;

			instr_len = 4;

			// Print the Current PC and instruction
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Disasemble the current instruction
			disassem( mode, instr_len, curr_ins, regs );

			// Print the Next PC and instruction
			next_ins.instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)UNMAKE_THUMB_ADDR(*next_pc), NULL);

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tNEXT(4) : 0x%.8lX\t", UNMAKE_THUMB_ADDR(*next_pc));
				for ( cnt = 0 ; cnt <= 3 ; cnt++ ) {
					fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
				}
				fprintf(stderr, "\n");
			}

			bkup_ins->instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)*next_pc, NULL);
			if ( IS_THUMB_ADDR(*next_pc) == 1 ) {
				ptrace(PTRACE_POKEDATA, *pid, (void *)*next_pc, (void *)thumb_breakpoint);
			}
			else {
				ptrace(PTRACE_POKEDATA, *pid, (void *)*next_pc, (void *)arm_breakpoint);
			}

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "-[ARM]\tSTREX HANDLE IT\n");
			}

			return 0;
		}

		/* [ARM] LDREX,STREX Handler (Branch) on Android */
		if ( handler == 1 ) {
			*next_pc = *curr_pc + 4;

			instr_len = 4;

			// Print the Current PC and instruction
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Disassemble the current instruction
			disassem( mode, instr_len, curr_ins, regs );

			// Print the Next PC and instruction
			next_ins.instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)UNMAKE_THUMB_ADDR(*next_pc), NULL);

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tNEXT(4) : 0x%.8lX\t", UNMAKE_THUMB_ADDR(*next_pc));
				for ( cnt = 0 ; cnt <= 3 ; cnt++ ) {
					fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
				}
				fprintf(stderr, "\n");
			}

			bkup_ins->instrs = ptrace(PTRACE_PEEKDATA, *pid, (void *)*next_pc, NULL);
			ptrace(PTRACE_POKEDATA, *pid, (void *)*next_pc, (void *)arm_breakpoint);

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "-[ARM]\tSTREX HANDLE IT\n");
			}

			return 0;
		}
	}

	return 1;
}

int strexHandler_check(unsigned long * mode, Instruction * curr_ins, unsigned int check)
{
	/* [THUMB] LDREX, STREX Handle - STREX check */
	if ( *mode == CPSR_T ) {
		if ( (curr_ins->instrs&0x0000FFF0) == 0x0000e840 ) {
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "-[THUMB]\tSTREX HANDLE ON\n");
			}

			return 1;
		}
	}
	/* [ARM] LDREX, STREX Handle - STREX check */
	else {
		if ( (curr_ins->instrs&0x0F9000F0) == 0x01800090 ) {
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "-[ARM]\tSTREX HANDLE ON\n");
			}

			return 1;
		}
	}

	return check;
}