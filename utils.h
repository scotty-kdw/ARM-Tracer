int getMapsAddr(pid_t pid, const char * keyword, mapdump_t * target_map);
unsigned long getLibFuncAddr(pid_t pid, const char * lname, const char * fname);

void simple_disassem(int mode, arm_regs * regs, unsigned long instr);
void disassem(unsigned long * mode, int instr_len, Instruction * curr_ins, arm_regs * regs);

int strexHandler(unsigned long * mode, pid_t * pid, unsigned long * curr_pc, unsigned long * next_pc, Instruction * curr_ins, Instruction * bkup_ins, arm_regs * regs);
int strexHandler_check(unsigned long * mode, Instruction * curr_ins, unsigned int check);

