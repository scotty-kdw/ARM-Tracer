/* Common target dependent code for GDB on ARM systems.

   Copyright (C) 1988-2016 Free Software Foundation, Inc.

   This file is part of gdb/arm-tdep.c

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */
   

#include "arm_single.h"

/* Find the next PC after the current instruction executes.  In some
   cases we can not statically determine the answer (see the IT state
   handling in this function); in that case, a breakpoint may be
   inserted in addition to the returned PC, which will be used to set
   another breakpoint by our caller.  */

CORE_ADDR
thumb_get_next_pc(pid_t pid, CORE_ADDR pc, arm_regs* regs, int * code_pass)
{
	unsigned long pc_val = ((unsigned long) pc) + 4;	/* PC after prefetch */
	unsigned long inst;
	unsigned short inst1;
	CORE_ADDR nextpc = pc + 2;		/* Default is next instruction.  */
	unsigned long offset;
	ULONGEST status, itstate;

	nextpc = MAKE_THUMB_ADDR (nextpc);
	pc_val = MAKE_THUMB_ADDR (pc_val);

	inst = ptrace(PTRACE_PEEKDATA, pid, (void *)pc, NULL);
	memcpy(&inst1, &inst, 2);

	/* Thumb-2 conditional execution support.  There are eight bits in
	   the CPSR which describe conditional execution state.  Once
	   reconstructed (they're in a funny order), the low five bits
	   describe the low bit of the condition for each instruction and
	   how many instructions remain.  The high three bits describe the
	   base condition.  One of the low four bits will be set if an IT
	   block is active.  These bits read as zero on earlier
	   processors.  */
	status = regs->ARM_cpsr;;
	itstate = ((status >> 8) & 0xfc) | ((status >> 25) & 0x3);

	/* If-Then handling.  On GNU/Linux, where this routine is used, we
	   use an undefined instruction as a breakpoint.  Unlike BKPT, IT
	   can disable execution of the undefined instruction.  So we might
	   miss the breakpoint if we set it on a skipped conditional
	   instruction.  Because conditional instructions can change the
	   flags, affecting the execution of further instructions, we may
	   need to set two breakpoints.  */

	//fprintf(stderr, "inst = %.8lx / inst1 = %.8lx\n", inst, inst1);

	if (thumb2_breakpoint != NULL)
	{
		// IT instruction
		if ((inst1 & 0xff00) == 0xbf00 && (inst1 & 0x000f) != 0)
		{
			/* An IT instruction.  Because this instruction does not
			   modify the flags, we can accurately predict the next
			   executed instruction.  */
			itstate = inst1 & 0x00ff;
			pc += thumb_insn_size (inst1);

			while (itstate != 0 && ! condition_true (itstate >> 4, status))
			{
				inst = ptrace(PTRACE_PEEKDATA, pid, (void *)pc, NULL);
				memcpy(&inst1, &inst, 2);

				pc += thumb_insn_size (inst1);
				itstate = thumb_advance_itstate (itstate);

				*code_pass = *code_pass + 1;
			}

			return MAKE_THUMB_ADDR (pc);
		}
		else if (itstate != 0)
		{
			/* We are in a conditional block.  Check the condition.  */
			if (! condition_true (itstate >> 4, status))
			{
				/* Advance to the next executed instruction.  */
				pc += thumb_insn_size (inst1);
				itstate = thumb_advance_itstate (itstate);

				while (itstate != 0 && ! condition_true (itstate >> 4, status))
				{
					inst = ptrace(PTRACE_PEEKDATA, pid, (void *)pc, NULL);
					memcpy(&inst1, &inst, 2);

					pc += thumb_insn_size (inst1);
					itstate = thumb_advance_itstate (itstate);

					*code_pass = *code_pass + 1;
				}

				return MAKE_THUMB_ADDR (pc);
			}
			else if ((itstate & 0x0f) == 0x08)
			{
				/* This is the last instruction of the conditional
				   block, and it is executed.  We can handle it normally
				   because the following instruction is not conditional,
				   and we must handle it normally because it is
				   permitted to branch.  Fall through.  */
			}
			else
			{
				int cond_negated;

				/* There are conditional instructions after this one.
				   If this instruction modifies the flags, then we can
				   not predict what the next executed instruction will
				   be.  Fortunately, this instruction is architecturally
				   forbidden to branch; we know it will fall through.
				   Start by skipping past it.  */

				cond_negated = (itstate >> 4) & 1;

				pc += thumb_insn_size (inst1);
				itstate = thumb_advance_itstate (itstate);

				/* Skip all following instructions with the same
				   condition.  If there is a later instruction in the IT
				   block with the opposite condition, set the other
				   breakpoint there.  If not, then set a breakpoint on
				   the instruction after the IT block.  */
				while (itstate != 0 && ((itstate >> 4) & 1) != cond_negated)
				{
					inst = ptrace(PTRACE_PEEKDATA, pid, (void *)pc, NULL);
					memcpy(&inst1, &inst, 2);

					pc += thumb_insn_size (inst1);
					itstate = thumb_advance_itstate (itstate);

					*code_pass = *code_pass + 1;
				}

				return MAKE_THUMB_ADDR (pc);
			}

		}
	}
	else if (itstate & 0x0f)
	{
		/* We are in a conditional block.  Check the condition.  */
		int cond = itstate >> 4;

		if (! condition_true (cond, status))
			/* Advance to the next instruction.  All the 32-bit
			   instructions share a common prefix.  */
			*code_pass = *code_pass + 1;
			return MAKE_THUMB_ADDR (pc + thumb_insn_size (inst1));

		/* Otherwise, handle the instruction normally.  */
	}

	if ((inst1 & 0xff00) == 0xbd00)	/* pop {rlist, pc} */
	{
		CORE_ADDR sp;

		/* Fetch the saved PC from the stack.  It's stored above
		   all of the other registers.  */
		offset = bitcount (bits (inst1, 0, 7)) * INT_REGISTER_SIZE;
		sp = regs->ARM_sp;

		nextpc = ptrace(PTRACE_PEEKDATA, pid, (void *)(sp+offset), NULL);
	}
	else if ((inst1 & 0xf000) == 0xd000)	/* conditional branch */
	{
		unsigned long cond = bits (inst1, 8, 11);
		if (cond == 0x0f)  /* 0x0f = SWI */
		{
			/*
			struct gdbarch_tdep *tdep;
			tdep = gdbarch_tdep (gdbarch);

			if (tdep->syscall_next_pc != NULL)
				nextpc = tdep->syscall_next_pc (frame);
			*/
		}
		else if (cond != 0x0f && condition_true (cond, status))
			nextpc = pc_val + (sbits (inst1, 0, 7) << 1);
	}
	else if ((inst1 & 0xf800) == 0xe000)	/* unconditional branch */
	{
		nextpc = pc_val + (sbits (inst1, 0, 10) << 1);
	}
	else if (thumb_insn_size (inst1) == 4) /* 32-bit instruction */
	{
		unsigned short inst2;
		inst = ptrace(PTRACE_PEEKDATA, pid, (void *)(pc+2), NULL);
		memcpy(&inst2, &inst, 2);

		/* Default to the next instruction.  */
		nextpc = pc + 4;
		nextpc = MAKE_THUMB_ADDR (nextpc);

		if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000)
		{
			/* Branches and miscellaneous control instructions.  */

			if ((inst2 & 0x1000) != 0 || (inst2 & 0xd001) == 0xc000)
			{
				/* B, BL, BLX.  */
				int j1, j2, imm1, imm2;

				imm1 = sbits (inst1, 0, 10);
				imm2 = bits (inst2, 0, 10);
				j1 = bit (inst2, 13);
				j2 = bit (inst2, 11);

				offset = ((imm1 << 12) + (imm2 << 1));
				offset ^= ((!j2) << 22) | ((!j1) << 23);

				nextpc = pc_val + offset;
				/* For BLX make sure to clear the low bits.  */
				if (bit (inst2, 12) == 0)
					nextpc = nextpc & 0xfffffffc;
			}
			else if (inst1 == 0xf3de && (inst2 & 0xff00) == 0x3f00)
			{
				/* SUBS PC, LR, #imm8.  */
				nextpc = regs->ARM_lr;
				nextpc -= inst2 & 0x00ff;
			}
			else if ((inst2 & 0xd000) == 0x8000 && (inst1 & 0x0380) != 0x0380)
			{
				/* Conditional branch.  */
				if (condition_true (bits (inst1, 6, 9), status))
				{
					int sign, j1, j2, imm1, imm2;

					sign = sbits (inst1, 10, 10);
					imm1 = bits (inst1, 0, 5);
					imm2 = bits (inst2, 0, 10);
					j1 = bit (inst2, 13);
					j2 = bit (inst2, 11);

					offset = (sign << 20) + (j2 << 19) + (j1 << 18);
					offset += (imm1 << 12) + (imm2 << 1);

					nextpc = pc_val + offset;
				}
			}
		}
		else if ((inst1 & 0xfe50) == 0xe810)
		{
			/* Load multiple or RFE.  */
			int rn, offset, load_pc = 1;

			rn = bits (inst1, 0, 3);
			if (bit (inst1, 7) && !bit (inst1, 8))
			{
				/* LDMIA or POP */
				if (!bit (inst2, 15))
					load_pc = 0;
				offset = bitcount (inst2) * 4 - 4;
			}
			else if (!bit (inst1, 7) && bit (inst1, 8))
			{
				/* LDMDB */
				if (!bit (inst2, 15))
					load_pc = 0;
				offset = -4;
			}
			else if (bit (inst1, 7) && bit (inst1, 8))
			{
				/* RFEIA */
				offset = 0;
			}
			else if (!bit (inst1, 7) && !bit (inst1, 8))
			{
				/* RFEDB */
				offset = -8;
			}
			else
				load_pc = 0;

			if (load_pc)
			{
				CORE_ADDR addr = regs->uregs[ rn ];

				nextpc = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr+offset), NULL);
			}
		}
		else if ((inst1 & 0xffef) == 0xea4f && (inst2 & 0xfff0) == 0x0f00)
		{
			/* MOV PC or MOVS PC.  */
			nextpc = regs->uregs[ bits(inst2, 0, 3) ];
			nextpc = MAKE_THUMB_ADDR (nextpc);
		}
		else if ((inst1 & 0xff70) == 0xf850 && (inst2 & 0xf000) == 0xf000)
		{
			/* LDR PC.  */
			CORE_ADDR base;
			int rn, load_pc = 1;

			rn = bits (inst1, 0, 3);
			base = regs->uregs[ rn ];

			if (rn == ARM_PC_REGNUM)
			{
				base = (base + 4) & ~(CORE_ADDR) 0x3;
				if (bit (inst1, 7))
					base += bits (inst2, 0, 11);
				else
					base -= bits (inst2, 0, 11);
			}
			else if (bit (inst1, 7))
				base += bits (inst2, 0, 11);
			else if (bit (inst2, 11))
			{
				if (bit (inst2, 10))
				{
					if (bit (inst2, 9))
						base += bits (inst2, 0, 7);
					else
						base -= bits (inst2, 0, 7);
				}
			}
			else if ((inst2 & 0x0fc0) == 0x0000)
			{
				int shift = bits (inst2, 4, 5), rm = bits (inst2, 0, 3);
				base += regs->uregs[ rm ] << shift;
			}
			else
				/* Reserved.  */
				load_pc = 0;

			if (load_pc)
				nextpc = ptrace(PTRACE_PEEKDATA, pid, (void *)base, NULL);
		}
		else if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf000)
		{
			/* TBB.  */
			CORE_ADDR tbl_reg, table, offset, length;

			tbl_reg = bits (inst1, 0, 3);
			if (tbl_reg == 0x0f)
				table = pc + 4;  /* Regcache copy of PC isn't right yet.  */
			else
				table = regs->uregs[ tbl_reg ];

			offset = regs->uregs[ bits(inst2, 0, 3) ];

			length = 2 * ( ptrace(PTRACE_PEEKDATA, pid, (void *)(table+offset), NULL) & 0xFF );
			nextpc = pc_val + length;
		}
		else if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf010)
		{
			/* TBH.  */
			CORE_ADDR tbl_reg, table, offset, length;

			tbl_reg = bits (inst1, 0, 3);
			if (tbl_reg == 0x0f)
				table = pc + 4;  /* Regcache copy of PC isn't right yet.  */
			else
				table = regs->uregs[ tbl_reg ];

			offset = 2 * regs->uregs[ bits(inst2, 0, 3) ];

			inst = ptrace(PTRACE_PEEKDATA, pid, (void *)(table+offset), NULL);
			length = bits(inst, 0, 15);
			length = 2 * length;

			nextpc = pc_val + length;
		}
	}
	else if ((inst1 & 0xff00) == 0x4700)	/* bx REG, blx REG */
	{
		if (bits (inst1, 3, 6) == 0x0f)
			nextpc = UNMAKE_THUMB_ADDR (pc_val);
		else
			nextpc = regs->uregs[ bits(inst1, 3, 6) ];
	}
	else if ((inst1 & 0xff87) == 0x4687)	/* mov pc, REG */
	{
		if (bits (inst1, 3, 6) == 0x0f)
			nextpc = pc_val;
		else
			nextpc = regs->uregs[ bits(inst1, 3, 6) ];

		nextpc = MAKE_THUMB_ADDR (nextpc);
	}
	else if ((inst1 & 0xf500) == 0xb100)
	{
		/* CBNZ or CBZ.  */
		int imm = (bit (inst1, 9) << 6) + (bits (inst1, 3, 7) << 1);
		ULONGEST reg = regs->uregs[ bits(inst1, 0, 2) ];

		if (bit (inst1, 11) && reg != 0)
			nextpc = pc_val + imm;
		else if (!bit (inst1, 11) && reg == 0)
			nextpc = pc_val + imm;
	}
	return nextpc;
}
