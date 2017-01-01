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

/* Get the raw next address.  PC is the current program counter, in
   FRAME, which is assumed to be executing in ARM mode.

   The value returned has the execution state of the next instruction
   encoded in it.  Use IS_THUMB_ADDR () to see whether the instruction is
   in Thumb-State, and gdbarch_addr_bits_remove () to get the plain memory
   address.  */

CORE_ADDR
arm_get_next_pc(pid_t pid, CORE_ADDR pc, arm_regs* regs, int * code_pass)
{
	unsigned long pc_val;
	unsigned long this_instr;
	unsigned long status;
	CORE_ADDR nextpc;

	int cnt;
	unsigned long arg_temp;
	unsigned char arg_str[128] = {0, };

	pc_val = (unsigned long) pc;
	this_instr = ptrace(PTRACE_PEEKDATA, pid, (void *)pc, NULL);


	status = regs->ARM_cpsr;
	nextpc = (CORE_ADDR) (pc_val + 4);

	if (bits (this_instr, 28, 31) == INST_NV)
	{
		switch (bits (this_instr, 24, 27))
		{
			case 0xa:
			case 0xb:
				{
					/* Branch with Link and change to Thumb.  */
					nextpc = BranchDest (pc, this_instr);
					nextpc |= bit (this_instr, 24) << 1;
					nextpc = MAKE_THUMB_ADDR (nextpc);
					break;
				} // case 0xb: end
			case 0xc:
			case 0xd:
			case 0xe:
				{
					/* Coprocessor register transfer.  */
					if (bits (this_instr, 12, 15) == 15) {
						fprintf(stderr, "Invalid update to pc in instruction 1\n");
						fprintf(stderr, "%X : %X\n", pc, this_instr);
					}
				} // case 0xe: end
				break;
		} // switch (bits (this_instr, 24, 27)) end
	} // if (bits (this_instr, 28, 31) == INST_NV) end
	else if (condition_true (bits (this_instr, 28, 31), status))
	{
		switch (bits (this_instr, 24, 27))
		{
			case 0x0:
			case 0x1:			/* data processing */
			case 0x2:
			case 0x3:
				{
					unsigned long operand1, operand2, result = 0;
					unsigned long rn;
					int c;

					if (bits (this_instr, 12, 15) != 15)
						break;

					if (bits (this_instr, 22, 25) == 0
							&& bits (this_instr, 4, 7) == 9) {	/* multiply */
						fprintf(stderr, "Invalid update to pc in instruction 2\n");
						fprintf(stderr, "%X : %X\n", pc, this_instr);
					}

					/* BX <reg>, BLX <reg> */
					if (bits (this_instr, 4, 27) == 0x12fff1
							|| bits (this_instr, 4, 27) == 0x12fff3)
					{
						rn = bits (this_instr, 0, 3);
						nextpc = (
								(rn == ARM_PC_REGNUM)
								? (pc_val + 8)
								: regs->uregs[ rn ]
								);

						return nextpc;
					} // if (bits (this_instr, 4, 27) == 0x12fff1 end

					/* Multiply into PC.  */
					c = (status & FLAG_C) ? 1 : 0;
					rn = bits (this_instr, 16, 19);
					operand1 = (
							(rn == ARM_PC_REGNUM)
							? (pc_val + 8)
							: regs->uregs[ rn ]
							);

					if (bit (this_instr, 25))
					{
						unsigned long immval = bits (this_instr, 0, 7);
						unsigned long rotate = 2 * bits (this_instr, 8, 11);
						operand2 = ((immval >> rotate) | (immval << (32 - rotate)))
							& 0xffffffff;
					} // if (bit (this_instr, 25)) end
					else /* operand 2 is a shifted register.  */
					{
						operand2 = shifted_reg_val (this_instr, c, pc_val, status, regs);
					} // else end

					switch (bits (this_instr, 21, 24))
					{
						case 0x0:	/*and */
							result = operand1 & operand2;
							break;

						case 0x1:	/*eor */
							result = operand1 ^ operand2;
							break;

						case 0x2:	/*sub */
							result = operand1 - operand2;
							result = regs->ARM_lr;
							break;

						case 0x3:	/*rsb */
							result = operand2 - operand1;
							break;

						case 0x4:	/*add */
							result = operand1 + operand2;
							break;

						case 0x5:	/*adc */
							result = operand1 + operand2 + c;
							break;

						case 0x6:	/*sbc */
							result = operand1 - operand2 + c;
							break;

						case 0x7:	/*rsc */
							result = operand2 - operand1 + c;
							break;

						case 0x8:
						case 0x9:
						case 0xa:
						case 0xb:	/* tst, teq, cmp, cmn */
							fprintf(stderr, "test-cmp\n");
							result = (unsigned long) nextpc;
							break;

						case 0xc:	/*orr */
							result = operand1 | operand2;
							break;

						case 0xd:	/*mov */
							/* Always step into a function.  */
							result = operand2;
							break;

						case 0xe:	/*bic */
							result = operand1 & ~operand2;
							break;

						case 0xf:	/*mvn */
							result = ~operand2;
							break;
					} // switch (bits (this_instr, 21, 24)) end

					/* In 26-bit APCS the bottom two bits of the result are
					   ignored, and we always end up in ARM state. 	*/
					if (!arm_apcs_32)
						nextpc = arm_addr_bits_remove (result);
					else
						nextpc = result;

					break;
				} // case 0x3: end
			case 0x4:
			case 0x5:		/* data transfer */
			case 0x6:
			case 0x7:
				{
					if (bit (this_instr, 20))
					{
						/* load */
						if (bits (this_instr, 12, 15) == 15)
						{
							/* rd == pc */
							unsigned long rn;
							unsigned long base;

							if (bit (this_instr, 22)) {
								fprintf(stderr, "Invalid update to pc in instruction 3\n");
								fprintf(stderr, "%X : %X\n", pc, this_instr);
							}

							/* byte write to PC */
							rn = bits (this_instr, 16, 19);
							base = (
									(rn == ARM_PC_REGNUM)
									? (pc_val + 8)
									: regs->uregs[ rn ]
								   );

							if (bit (this_instr, 24))
							{
								/* pre-indexed */
								int c = (status & FLAG_C) ? 1 : 0;
								unsigned long offset = (
										bit (this_instr, 25)
										? shifted_reg_val (this_instr, c, pc_val, status, regs)
										: bits (this_instr, 0, 11)
										);

								if (bit (this_instr, 23))
									base += offset;
								else
									base -= offset;
							} // if (bit (this_instr, 24)) end
							nextpc = ptrace(PTRACE_PEEKDATA, pid, (void *)(CORE_ADDR) base, NULL);
						} // if (bits (this_instr, 12, 15) == 15) end
					} // if (bit (this_instr, 20))
					break;
				} // case 0x7: end
			case 0x8:
			case 0x9:		/* block transfer */
				{
					if (bit (this_instr, 20))
					{
						/* LDM */
						if (bit (this_instr, 15))
						{
							/* loading pc */
							int offset = 0;
							unsigned long rn_val = regs->uregs[ bits(this_instr, 16, 19) ];

							if (bit (this_instr, 23))
							{
								/* up */
								unsigned long reglist = bits (this_instr, 0, 14);
								offset = bitcount (reglist) * 4;
								if (bit (this_instr, 24))		/* pre */
									offset += 4;
							} // if (bit (this_instr, 23)) end
							else if (bit (this_instr, 24))
								offset = -4;

							nextpc = ptrace(PTRACE_PEEKDATA, pid, (void *)(CORE_ADDR) (rn_val + offset), NULL);
						}
					} // if (bit (this_instr, 15)) end
					break;
				} // case 0x9: end
			case 0xb:		/* branch & link */
			case 0xa:		/* branch */
				{
					nextpc = BranchDest (pc, this_instr);
					break;
				} // case 0xa: end
			case 0xc:
			case 0xd:
			case 0xe:		/* coproc ops */
				break;
			case 0xf:		/* SWI */
				{
					/*
					struct gdbarch_tdep *tdep;
					tdep = gdbarch_tdep (gdbarch);

					if (tdep->syscall_next_pc != NULL)
						nextpc = tdep->syscall_next_pc (frame);
					*/

					// sys_open
					/*
					if ( regs->ARM_r7 == 5 ) {
						for ( cnt = 0 ; cnt < 120 ; cnt = cnt + 4 ) {
							arg_temp = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs->ARM_r0+cnt), NULL);
							strncpy( arg_str+cnt, (unsigned char *)&arg_temp, 4 );
						}
						fprintf(stderr, "-[SWI]\t%s : %s\n", svc_call_name[regs->ARM_r7], arg_str);
						memset( arg_str, 0x00, 128 );
					}
					else if ( regs->ARM_r7 < 512 )
						fprintf(stderr, "-[SWI]\t%s\n", svc_call_name[regs->ARM_r7]);
					else
						fprintf(stderr, "-[SWI]\t0x%.8X(%d)\n", regs->ARM_r7, regs->ARM_r7);
					*/
				} // case 0xf: end
				break;
			default:
				{
					fprintf(stderr, "Bad bit-field extraction\n");
					return (pc);
				} // default: end
		} // switch (bits (this_instr, 24, 27)) end
	} // else if (condition_true (bits (this_instr, 28, 31), status)) end
	else
	{
		*code_pass = 1;
	}

	return nextpc;
}