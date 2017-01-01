#include "arm_single.h"

void * inputCommand(void * order);
pid_t waitProcess(int no, pid_t * pid, int * stat, unsigned long * next_pc, Instruction * bkup_ins);
int getMapsAddr(pid_t pid, const char * keyword, mapdump_t * target_map);
unsigned long getLibFuncAddr(pid_t pid, const char * lname, const char * fname);

void simple_disassem(int mode, arm_regs * regs, unsigned long instr);
void disassem(unsigned long * mode, int instr_len, Instruction * curr_ins, arm_regs * regs);

int strexHandler(unsigned long * mode, pid_t * pid, unsigned long * curr_pc, unsigned long * next_pc, Instruction * curr_ins, Instruction * bkup_ins, arm_regs * regs);
int strexHandler_check(unsigned long * mode, Instruction * curr_ins, unsigned int check);

pid_t attach_thread(pid_t pid);

void thread_stop(pid_t pid, pid_t except);
void thread_cont(pid_t pid, pid_t except);
char thread_state(pid_t pid);
void thread_pass(pid_t pid, pid_t pid_wait, unsigned long * next_pc, Instruction * bkup_ins);

int DEBUG_MSG_PRINT = 0;
pid_t bkup_pid = 0;

unsigned int counter = 0;
int arm_code_pass = 0;
int thumb_code_pass = 0;
unsigned int arm_pass_pc = 0;
unsigned int thumb_pass_pc = 0;

#define THREAD_LIST_NUM 100
pid_t attach_thread_list[THREAD_LIST_NUM] = {0,};
int thread_list_cnt = 0;

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

typedef struct {
#ifdef _STDIO_REVERSE
	unsigned char   *ptr;  /* next character from/to here in buffer */
	ssize_t         cnt;   /* number of available characters in buffer */
#else
	ssize_t         cnt;   /* number of available characters in buffer */
	unsigned char   *ptr;  /* next character from/to here in buffer */
#endif
	unsigned char   *base; /* the buffer */
	unsigned char   flag;  /* the state of the stream */
	unsigned char   file;  /* UNIX System file descriptor */
	unsigned        orientation:2; /* the orientation of the stream */
	unsigned        ionolock:1;   /* turn off implicit locking */
	unsigned        seekable:1;   /* is file seekable? */
	unsigned        filler:4;
} FileStruct;

typedef union
{
	unsigned char Str[160];
	struct
	{
		unsigned long Count;
		unsigned long BitMask;
		unsigned long Address;
		unsigned long Opcode;
		unsigned char Mnemonic[16];
		unsigned char OperandStr[64];
		unsigned long Operands[16];
	} Members;
} LogEntry;

LogEntry log_entry;
FILE * log_fd;

static void usage(char *ex_name) {
    fprintf(stderr, " [ Usage ]\n\t$ %s [OPTION]\n", ex_name);
    fprintf(stderr, "\n [ OPTION ]\n\
    -d\t(Debug Level)\n\
    \t0 : Default Level. No Debug MSG Print.\n\
    \t1 : Debug Level 1. asdfasdf\n\
    \t2 : Debug Level 2. qwerqwer\n\n\
    -s\t(Skip Dump Instruction line)\n\n\
    -f\t(Fork & attach)\n\
    \tFork > Excution > Attach, So args is Program Name.\n\n\
    -p\t(Pid & attach)\n\
    \tGet PID > Attach, So args is PID.\n\n\
    -i\t(Target Name)\n\
    \tInput Data File Name.\n\n\
    -o\t(Output Name)\n\
    \tOutput File(dump.log) Name.\n\n\
    \n");
    fprintf(stderr, " [ Example ]\n\
    $ %s -d 1 -f /bin/ls\n\
    $ %s -p 1234 -i temp\n\n"\
    , ex_name, ex_name);
    exit(2);
}


unsigned long read_start_addr = 0, read_end_addr = 0;
int main(int argc, char* argv[])
{
	pthread_t thread;
	int argv_opt, opt = 0, order = 0;
	int precond = 1;
	char mapinfo_libc[128] = {0, };
	char mapinfo_libtarget[128] = {0, };

	int skip = 0;
	int status;
	pid_t pid, pid_wait, tid;

	arm_regs regs;

	unsigned long mode;
	unsigned long curr_pc, next_pc;
	Instruction curr_ins, next_ins, bkup_ins;
	unsigned short inst1;
	int instr_len, cnt = 0;

	unsigned long check_func_addr[5];
	Instruction check_func_instr[5];

	unsigned int strex_check = 0;
	unsigned int strex_count = 0;

	int open_btn = 0, open_cnt = 0;
	unsigned long arg_temp;
	char *arg_arg[10] = {0, };
	char arg_str[128] = {0, };
	char target_str[128] = {0, };
	char output_file_name[128] = "./dump.log";
	unsigned long swi_temp;
	unsigned char swi_str[128] = {0, };

	unsigned long open_ret_addr = 0;
	unsigned long fread_ret_addr = 0;
	unsigned long read_ret_addr = 0;
	unsigned long memcpy_ret_addr = 0;
	unsigned long target_fd_num = 0;
	unsigned long target_fd_addr = 0;
	int target_monitor = 0;
	unsigned int read_check = 0, read_size = 0;
	unsigned long read_src_addr = 0;
	unsigned long read_dst_addr = 0;

	unsigned long file_offset = 0;
	unsigned long file_base_offset = 0;
	unsigned long file_start_offset = 0;
	unsigned long file_curr_offset = 0;
	//unsigned long read_start_addr = 0, read_end_addr;

	unsigned long crash_pc = 0;

	clock_t c_start, c_end;
	time_t t_start, t_end;
	double c_time, t_time;

	mapdump_t map_addr[5];
	char keyword[64]={0,};
	int memsize, asdf = 0;

	if ( argc < 2 ) {
		usage(argv[0]);
	}

	while( -1 !=( argv_opt = getopt(argc, argv, "d:s:f:p:i:o:h") ) )
	{
		switch( argv_opt )
		{
			case 'd' :
				DEBUG_MSG_PRINT = atoi(optarg);
				break;
			case 's' :
				skip = atoi(optarg);
				break;
			case 'f' :
				opt = 1;
				strncpy(arg_str, optarg, sizeof(arg_str)-1);
				arg_str[sizeof(arg_str)-1] = '\0';

				int i, length, start_offset;
				for ( i = 0, length = 0, cnt = 0, start_offset = 0 ; i <= strlen(arg_str) ; i++, length++ ) {
					if ( arg_str[i] == ' ' || arg_str[i] == '\0' ) {
						arg_arg[cnt] = (char *)malloc(sizeof(char) * length + 1);
						strncpy(arg_arg[cnt], arg_str + i - length, length);
						length = -1;
						cnt++;
					}
				}

				break;
			case 'p' :
				opt = 2;
				pid = atoi(optarg);
				pid = abs(pid);
				break;
			case 'i' :
				strncpy(target_str, optarg, strlen(optarg));
				//target_str[strlen(optarg)-1] = '\0';
				break;
			case 'o' :
				memset(output_file_name, 0x0, 128);
				strncpy(output_file_name, optarg, strlen(optarg));
				break;
			case 'h' :
				usage(argv[0]);
				break;
			case '?' :
				fprintf(stderr, "\n[?] Unknown Option : %c\n\n", optopt); // optopt 사용
				usage(argv[0]);
		}
	}

	if ( opt == 1 ) {
		precond = 0;
		pid = fork();
		bkup_pid = pid;
		if ( pid == -1 ) {
			perror("fork");
		}
		else if ( pid == 0 ) {
			fprintf(stdout, "%s\n", arg_str);
			ptrace(PTRACE_TRACEME, 0, 0, 0);
			if ( -1 == execv( arg_arg[0], arg_arg ) ) {
				perror("[!] EXECV Fail");
				exit(1);
			}
		}
	}
	else if ( opt == 2 ) {
		precond = 1;

		if ( -1 == ptrace(PTRACE_ATTACH, pid, NULL, NULL) ) {
			perror("[!] ATTACH Fail");
			exit(1);
		}
		bkup_pid = pid;

		attach_thread_list[thread_list_cnt++] = pid;

		if ( target_str == NULL ) {
			sprintf(target_str, ".hwp");
		}
		fprintf(stdout, "target : %s\n", target_str);
	}
	else {
		usage(argv[0]);
	}

	fprintf(stdout, "attach program pid : %d\n", pid);
	fprintf(stdout, "this program pid : %d\n\n", getpid());
	fprintf(stdout, ">>> Skip Dump Line : %d\n", skip);

	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "attach program pid : %d\n", pid);
		fprintf(stderr, "this program pid : %d\n\n", getpid());
		fprintf(stderr, ">>> Skip Dump Line : %d\n", skip);
	}
	pthread_create(&thread, NULL, inputCommand, (void *)&order);

	pid_wait = waitProcess(0, &pid, &status, NULL, NULL);

	ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(PTRACE_O_TRACECLONE) );
	//ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACEEXEC) );

	log_fd = fopen(output_file_name, "wb");


	//-------------------------------------------------- LibraryMapAddr
	if ( precond ) {
		check_func_addr[0] = getLibFuncAddr(pid, "/system/lib/libc.so", "__open");
		check_func_addr[1] = getLibFuncAddr(pid, "/system/lib/libc.so", "__pthread_clone");
		check_func_instr[0].instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)check_func_addr[0], NULL);
		check_func_instr[1].instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)check_func_addr[0] + 4, NULL);

		fprintf(stdout, "# Find it! __Open Func : %.8lX\n", check_func_addr[0]);
		fprintf(stdout, "# Find it! __pthread_clone Func : %.8lX\n\n", check_func_addr[1]);
		fprintf(stdout, " @ [__open] ins : e1a0c007 : %.8lx\n", check_func_instr[0].instrs);
		fprintf(stdout, " @ [__open + 4] ins : e3a07005 : %.8lx\n\n", check_func_instr[1].instrs);

		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "# Find it! __Open Func : %.8lX\n", check_func_addr[0]);
			fprintf(stderr, "# Find it! __pthread_clone Func : %.8lX\n\n", check_func_addr[1]);
			fprintf(stderr, " @ [__open] ins : e1a0c007 : %.8lx\n", check_func_instr[0].instrs);
			fprintf(stderr, " @ [__open + 4] ins : e3a07005 : %.8lx\n\n", check_func_instr[1].instrs);
		}

		sprintf(keyword, "libc.so");
		memsize = getMapsAddr(pid, keyword, map_addr);
		sprintf(mapinfo_libc, "[%s] Memory : %lX - %lX\n", keyword, map_addr[asdf].map_start_addr, map_addr[asdf].map_end_addr);
		fprintf(stdout, "%s\n", mapinfo_libc);
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "%s\n", mapinfo_libc);
		}

		sprintf(keyword, "libpolarisoffice6.so");
		memsize = getMapsAddr(pid, keyword, map_addr);
		sprintf(mapinfo_libtarget, "[%s] Memory : %lX - %lX\n", keyword, map_addr[asdf].map_start_addr, map_addr[asdf].map_end_addr);
		/*
		fprintf(stdout, "%s\n", mapinfo_libtarget);
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "%s\n", mapinfo_libtarget);
		}
		*/

		attach_thread(bkup_pid);
	}

	//-----------------------------------------------------------------
	while( 1 ) {
		// program exit condition
		if ( order == 1 || pid_wait == -1 ) {
			break;
		}

		//-------------------------------------------- PRE-CONDITION Check
		if ( precond ) {
			// 1. Set Breakpoint __open
			next_pc = check_func_addr[0];
			if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)arm_breakpoint) ) {
				perror("[PRE-BreakSet 0] ");
				fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
			}

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "#---------------------------------------------------#\n");
				fprintf(stderr, " @ (%.2d) Break [Func]!!!\n", open_cnt );
				fprintf(stderr, " @ [Func] ins : e1a0c007 : %.8lx\n", check_func_instr[0].instrs);
			}

			// 2. All Thread Continue
			thread_cont(0, 0);

			/*
			while ( precond ) {
				pid_wait = waitpid( -1, &status, __WALL );

				char t_state = thread_state(pid_wait);
				if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
					perror("[PRECOND] ptrace_getregs");
				}
				if ( regs.ARM_pc == next_pc ) {
					// 11. Arg R0 Check
					memset( arg_str, 0x00, 128 );
					for ( cnt = 0 ; cnt < 120 ; cnt = cnt + 4 ) {
						arg_temp = ptrace(PTRACE_PEEKDATA, pid_wait, (void *)(regs.ARM_r0+cnt), NULL);
						strncpy( arg_str+cnt, (unsigned char *)&arg_temp, 4 );
					}
					fprintf(stdout, " @ r0(%.8lx) : %s\n", regs.ARM_r0, arg_str);
					fprintf(stdout, "\t - r1(%.8lx) : %d\n", regs.ARM_r1, regs.ARM_r1);
					if ( DEBUG_MSG_PRINT > 0 ) {
						fprintf(stderr, " @ r0(%.8lx) : %s\n", regs.ARM_r0, arg_str);
						//fprintf(stderr, "\t @ r1(%.8lx)\n", regs.ARM_r1);
					}

					// 12. Target Input File Check
					if ( (regs.ARM_r1 == 0x20000) && (strstr(arg_str, target_str) != NULL) ) {
						precond = 0;
						pid = pid_wait;

						// Target File Descriptor
						check_func_addr[2] = getLibFuncAddr(pid_wait, "/system/lib/libc.so", "fread");
						check_func_addr[2] = UNMAKE_THUMB_ADDR(check_func_addr[2]);
						check_func_addr[3] = getLibFuncAddr(pid_wait, "/system/lib/libc.so", "read");
						check_func_addr[3] = UNMAKE_THUMB_ADDR(check_func_addr[3]);
						check_func_addr[4] = getLibFuncAddr(pid_wait, "/system/lib/libc.so", "memcpy");
						check_func_addr[4] = UNMAKE_THUMB_ADDR(check_func_addr[4]);

						if ( -1 == ptrace(PTRACE_POKEDATA, pid_wait, (void *)next_pc, (void *)check_func_instr[0].instrs) ) {
							perror("[PRE-Restore Open_0] ");
							fprintf(stderr, "\t-(%d) State : %c\n", pid_wait, thread_state(pid_wait));
						}
					}
				}
				else {
					thread_pass(bkup_pid, pid_wait, &next_pc, &check_func_instr[0]);
				}
			}
			*/

			// 3. Wait
			pid_wait = waitProcess(18, &pid, &status, &next_pc, &check_func_instr[0]);
			/*
			while ( 1 ) {
				char temp_state = 'X';
				cnt = 0;
				while ( 1 ) {
					if ( cnt == thread_list_cnt ) {
						cnt = 0;
					}
					temp_state = thread_state(attach_thread_list[cnt++]);
					if ( temp_state == 't' ) {
						pid = attach_thread_list[cnt-1];
						break;
					}
				}
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) {
					perror("[PRECOND] ptrace_getregs");
				}
				if ( regs.ARM_pc == next_pc ) {
					pid = pid_wait;
					break;
				}
				thread_cont(pid_wait, 0);
			}
			for ( cnt = 0 ; cnt < thread_list_cnt ; cnt++ ) {
				fprintf(stderr, "\t[%d] State : %c\n", attach_thread_list[cnt], thread_state(attach_thread_list[cnt]));
			}
			*/
			// 4. All Thread Stop
			thread_stop(0, pid_wait);
			//thread_stop(pid_wait, 0);

			// 5. Restore __open
			if ( -1 == ptrace(PTRACE_POKEDATA, pid_wait, (void *)next_pc, (void *)check_func_instr[0].instrs) ) {
				perror("[PRE-Restore Open_0] ");
				fprintf(stderr, "\t-(%d) State : %c\n", pid_wait, thread_state(pid_wait));
			}

			// 6. Set Breakpoint __opne + 4
			next_pc = check_func_addr[0] + 4;
			if ( -1 == ptrace(PTRACE_POKEDATA, pid_wait, (void *)next_pc, (void *)arm_breakpoint) ) {
				perror("[PRE-BreakSet 1] ");
				fprintf(stderr, "\t-(%d) State : %c\n", pid_wait, thread_state(pid_wait));
			}

			// 7. pid_wait Thread Continue
			thread_cont(pid_wait, 0);

			// 8. Wait
			pid_wait = waitpid( pid_wait, &status, __WALL );
			//pid_wait = waitProcess(19, &pid, &status, &next_pc, &check_func_instr[1]);

			// 9. Restore __open + 4
			if ( -1 == ptrace(PTRACE_POKEDATA, pid_wait, (void *)next_pc, (void *)check_func_instr[1].instrs) ) {
				perror("[PRE-Restore Open_1] ");
				fprintf(stderr, "\t-(%d) State : %c\n", pid_wait, thread_state(pid_wait));
			}

			// 10. Get Register infomation of pid Thread
			if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
				perror("[FuncCheck] ptrace_getregs");
				fprintf(stderr, "\t-(%d) State : %c\n", pid_wait, thread_state(pid_wait));
			}

			// 11. Arg R0 Check
			memset( arg_str, 0x00, 128 );
			for ( cnt = 0 ; cnt < 120 ; cnt = cnt + 4 ) {
				arg_temp = ptrace(PTRACE_PEEKDATA, pid_wait, (void *)(regs.ARM_r0+cnt), NULL);
				strncpy( arg_str+cnt, (unsigned char *)&arg_temp, 4 );
			}
			fprintf(stdout, " @ r0(%.8lx) : %s\n", regs.ARM_r0, arg_str);
			fprintf(stdout, "\t - r1(%.8lx) : %d\n", regs.ARM_r1, regs.ARM_r1);
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, " @ r0(%.8lx) : %s\n", regs.ARM_r0, arg_str);
				//fprintf(stderr, "\t @ r1(%.8lx)\n", regs.ARM_r1);
			}

			// 12. Target Input File Check
			if ( (regs.ARM_r1 == 0x20000) && (strstr(arg_str, target_str) != NULL) ) {
				precond = 0;

				// Target File Descriptor
				check_func_addr[2] = getLibFuncAddr(pid, "/system/lib/libc.so", "fread");
				check_func_addr[2] = UNMAKE_THUMB_ADDR(check_func_addr[2]);
				check_func_addr[3] = getLibFuncAddr(pid, "/system/lib/libc.so", "read");
				check_func_addr[3] = UNMAKE_THUMB_ADDR(check_func_addr[3]);
				check_func_addr[4] = getLibFuncAddr(pid, "/system/lib/libc.so", "memcpy");
				check_func_addr[4] = UNMAKE_THUMB_ADDR(check_func_addr[4]);

				thread_cont(0, pid);
			}

			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "#---------------------------------------------------#\n");
			}
			continue;
		}
		//-----------------------------------------------------------------


		//---------------------------------------------------- Logging Start
		memset(log_entry.Str, 0x00, 160);

		counter++;
		log_entry.Members.Count = counter;

		if ( counter == 1 ) {
			char map_order[256];
			snprintf(map_order, sizeof(map_order), "cat /proc/%d/maps > maps.log", pid);
			system(map_order);

			time(&t_start);
			fprintf(stdout, "- * - * - * - * - * - LOGGING START - * - * - * - * - * -\n");
		}
		if ( counter % 10000 == 0 ) {
			fprintf(stdout, "Number of machine instructions : %d\n", counter);
		}

		//--------------------------------------- Get Current PC & Register
		//while ( ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0 );
		if ( ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0 ) {
			fprintf(stderr, "[Error] Get Current PC & Register\n");
		}

		curr_pc = regs.ARM_pc;
		curr_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)curr_pc, NULL);
		//-----------------------------------------------------------------

		mode = regs.ARM_cpsr&( (FLAG_N|FLAG_Z|FLAG_C|FLAG_V) |CPSR_T);
		log_entry.Members.BitMask = mode;
		mode = mode&CPSR_T;

		if ( mode == CPSR_T ) {
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\n#[THUMB] %10d / PID = %5d / CPSR = %.8lX", counter, pid, regs.ARM_cpsr);
			}
			inst1 = 0;
			memcpy(&inst1, &curr_ins.instrs, 2);
			instr_len = thumb_insn_size (inst1);

			log_entry.Members.Address = MAKE_THUMB_ADDR(curr_pc);
			if ( instr_len == 2 ) {
				log_entry.Members.Opcode = inst1;
			}
			else {
				log_entry.Members.Opcode = curr_ins.instrs;
			}
		}
		else {
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\n#[ARM] %10d / PID = %5d / CPSR = %.8lX", counter, pid, regs.ARM_cpsr);
			}
			instr_len = 4;
			log_entry.Members.Address = curr_pc;
			log_entry.Members.Opcode = curr_ins.instrs;
		}

		if ( DEBUG_MSG_PRINT > 0 ) {
			if ( WSTOPSIG(status) != SIGILL && WSTOPSIG(status) != SIGTRAP ) {
				fprintf(stderr, " / signal = %u, %x", status, status);
			}
		}
		//-----------------------------------------------------------------

		//-------------------------------------------------- Get Next PC
		// Thumb mode
		if ( mode == CPSR_T ) {
			next_pc = thumb_get_next_pc(pid, curr_pc, &regs, &thumb_code_pass);
			thumb_pass_pc = thumb_pass_pc + thumb_code_pass;
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, " / Code Pass = %d\n", thumb_code_pass);
			}
		}
		// ARM mode
		else {
			next_pc = arm_get_next_pc(pid, curr_pc, &regs, &arm_code_pass);
			arm_pass_pc = arm_pass_pc + arm_code_pass;
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, " / Code Pass = %d\n", arm_code_pass);
			}
		}

		if ( strex_check == 1 ) {
			arm_code_pass = 0;
			thumb_code_pass = 0;
		}

		// Get Instruction of Next PC
		next_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)UNMAKE_THUMB_ADDR(next_pc), NULL);
		//--------------------------------------------------------------

		//-------------------------------------------------- SWI Arg Check
		// svc check
		if ( (mode != CPSR_T) && (curr_ins.instrs == 0xef000000) ) {
			// open
			if ( regs.ARM_r7 == 5 ) {
				for ( cnt = 0 ; cnt < 120 ; cnt = cnt + 4 ) {
					swi_temp = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.ARM_r0+cnt), NULL);
					strncpy( swi_str+cnt, (unsigned char *)&swi_temp, 4 );
				}
				fprintf(stdout, "(%8d)-[SWI]\t%s : %s\n", counter, svc_call_name[regs.ARM_r7], swi_str);
				if ( NULL != strstr(swi_str, target_str) ) {
					open_ret_addr = UNMAKE_THUMB_ADDR(regs.ARM_lr);
				}
				memset( swi_str, 0x00, 128 );
			}
			// read
			else if ( regs.ARM_r7 == 3 ) {
				fprintf(stdout, "(%8d)-[SWI]\t%s\n", counter, svc_call_name[regs.ARM_r7]);
			}
			// lseek
			else if ( regs.ARM_r7 == 19 ) {
				fprintf(stdout, "(%8d)-[SWI]\t%s\n", counter, svc_call_name[regs.ARM_r7]);
				// off_t lseek(int fildes, off_t offset, int whence);
				if ( target_fd_num == regs.ARM_r0 ) {
					file_base_offset = regs.ARM_r1;
				}
			}
			// nanosleep
			else if ( regs.ARM_r7 == 162 ) {
				fprintf(stdout, "(%8d)-[SWI]\t%s\n", counter, svc_call_name[regs.ARM_r7]);
				//thread_cont(0, pid);
			}
			// futex
			else if ( regs.ARM_r7 == 240 ) {
				fprintf(stdout, "(%8d)-[SWI]\t%s\n", counter, svc_call_name[regs.ARM_r7]);
			}
			else if ( regs.ARM_r7 < 370 ) {
				fprintf(stdout, "(%8d)-[SWI]\t%s\n", counter, svc_call_name[regs.ARM_r7]);
			}
			else {
				fprintf(stdout, "(%8d)-[SWI]\t0x%.8X(%d)\n", counter, regs.ARM_r7, regs.ARM_r7);
			}
		}


		// Open, File Descriptor check
		if ( curr_pc == open_ret_addr ) {
			/*
			fprintf(stderr, "\t\t[Open RET Check]\n");
			fprintf(stderr, "\t\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
				regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
			fprintf(stderr, "\t\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
				regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
			fprintf(stderr, "\t\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
				regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
			fprintf(stderr, "\t\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
				regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
			fprintf(stderr, "\t\tcpsr=0x%.8X\n", regs.ARM_cpsr);
			*/

			target_fd_num = regs.ARM_r0;
			target_fd_addr = regs.ARM_r4;
			target_monitor = 1;
		}
		// size_t fread ( void * ptr, size_t size, size_t count, FILE * stream );
		if ( curr_pc == check_func_addr[2] && target_fd_addr == regs.ARM_r3 && target_monitor == 1 ) {
			/*
			fprintf(stdout, "\t[Fread Check]\n");
			fprintf(stdout, "\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
				regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
			fprintf(stdout, "\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
				regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
			fprintf(stdout, "\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
				regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
			fprintf(stdout, "\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
				regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
			fprintf(stdout, "\tcpsr=0x%.8X\n", regs.ARM_cpsr);
			*/

			file_curr_offset = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.ARM_r3), NULL);
			file_start_offset = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.ARM_r3+16), NULL);
			file_offset = file_base_offset + (file_curr_offset - file_start_offset);

			/*
			fprintf(stdout, "\t[*] FILE ADDR(%.8X) : %.8X, %.8X\n", regs.ARM_r3, file_curr_offset, file_start_offset);
			fprintf(stdout, "\t[-] ADDR_DATA :");
			for ( cnt = 0 ; cnt < 64 ; cnt = cnt + 4 ) {
				if ( (cnt%16) == 0 ) {
					fprintf(stdout, "\n\t\t\t\t\t");
				}
				fprintf(stdout, " %.8X", ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.ARM_r3+cnt), NULL) );
			}
			fprintf(stdout, "\n");
			fprintf(stdout, "\t\t1) %.8X", ptrace(PTRACE_PEEKDATA, pid, (void *)(file_curr_offset), NULL) );
			fprintf(stdout, "\t\t2) %.8X\n", ptrace(PTRACE_PEEKDATA, pid, (void *)(file_start_offset), NULL) );
			*/

			if ( read_start_addr == 0 ) {
				read_start_addr = regs.ARM_r0;
				read_end_addr = read_start_addr;
			}
			read_dst_addr = regs.ARM_r0;

			fread_ret_addr = UNMAKE_THUMB_ADDR(regs.ARM_lr);
			target_monitor = 2;
		}
		else if ( curr_pc == fread_ret_addr && target_monitor == 2 ) {
			read_size = read_size + regs.ARM_r0;
			read_end_addr = read_end_addr + regs.ARM_r0 - 1;

			fprintf(stdout, "\t[#] READ_ADDR : %.8X - %.8X / READ_SIZE : %d(%d)\n", read_dst_addr, read_dst_addr+regs.ARM_r0-1, regs.ARM_r0, read_size);

			log_entry.Members.BitMask = log_entry.Members.BitMask | 0x01000000;
			log_entry.Members.Operands[13] = file_offset;
			log_entry.Members.Operands[14] = read_dst_addr;
			log_entry.Members.Operands[15] = read_dst_addr+regs.ARM_r0-1;

			fprintf(stdout, "\t[-] READ_DATA : (%.8X)", file_offset);
			if ( regs.ARM_r0 < 20 ) {
				for ( cnt = 0 ; cnt < regs.ARM_r0 ; cnt = cnt + 4 ) {
					fprintf(stdout, " %.8X", ptrace(PTRACE_PEEKDATA, pid, (void *)(read_dst_addr+cnt), NULL) );
				}
			}
			else {
				for ( cnt = 0 ; cnt < 20 ; cnt = cnt + 4 ) {
					fprintf(stdout, " %.8X", ptrace(PTRACE_PEEKDATA, pid, (void *)(read_dst_addr+cnt), NULL) );
				}
			}
			fprintf(stdout, "\n\n");
			target_monitor = 1;
		}
		/*
		// ssize_t read (int fd, void *buf, size_t nbytes)
		else if ( curr_pc == check_func_addr[3] && target_monitor >= 1 ) {
			fprintf(stderr, "\t[Read Check]\n");
			fprintf(stderr, "\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
				regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
			fprintf(stderr, "\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
				regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
			fprintf(stderr, "\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
				regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
			fprintf(stderr, "\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
				regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
			fprintf(stderr, "\tcpsr=0x%.8X\n", regs.ARM_cpsr);
		}
		*/
		//-----------------------------------------------------------------

		//--------------------------------------------- LDREX,STREX Handler
		if ( strex_check == 1 ) {
			strex_check = strexHandler( &mode, &pid, &curr_pc, &next_pc, &curr_ins, &bkup_ins, &regs );

			if ( strex_check == 0 ) {
				strex_count++;

				ptrace(PTRACE_CONT, pid, 0, 0);
				pid_wait = waitpid( pid, &status, __WALL );
				//pid_wait = waitProcess(9, &pid, &status, &next_pc, &bkup_ins);
				ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)bkup_ins.instrs);

				arm_code_pass = 0;
				thumb_code_pass = 0;
				if ( counter > skip ) {
					fwrite(log_entry.Str, 1, sizeof(log_entry.Str), log_fd);
				}
				continue;
			}
		} // if ( strex_check == 1 ) end
		//--------------------------------------------------------------

		//--------------------------------------------- ALL Threads Stop
		//thread_stop(0, 0);
		//--------------------------------------------------------------

		//---------------------------------------------------- Set Break
		// BreakSet Next PC
		bkup_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)next_pc, NULL);

		long setbreak_ret;
		// if NEXT PC is ThumbMode Address
		if ( IS_THUMB_ADDR(next_pc) == 1 ) {
			setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)((bkup_ins.instrs&0xFFFF0000)|thumb_breakpoint));
		}
		else {
			setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)arm_breakpoint);
		}

		// check break-set
		if ( setbreak_ret == -1 ) {
			fprintf(stderr, "\n\t[Break Point ISSUE]\n", curr_pc);

			// Current PC Print
			fprintf(stderr, "\tCURRENT : 0x%.8lX\t", curr_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", curr_ins.instr[cnt]);
			}

			simple_disassem( IS_THUMB_ADDR(curr_pc), &regs, curr_ins.instrs );

			if ( mode == CPSR_T ) {
				unsigned short instr1;
				memcpy(&instr1, &next_ins.instrs, 2);
				next_pc = curr_pc + thumb_insn_size(instr1);
				next_pc = MAKE_THUMB_ADDR(next_pc);
			}
			else {
				next_pc = curr_pc + 4;
			}
			next_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)UNMAKE_THUMB_ADDR(next_pc), NULL);
			bkup_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)next_pc, NULL);
			int temp_len;
			// Thumb mode
			if ( IS_THUMB_ADDR(next_pc) == 1 ) {
				unsigned short instr1;
				memcpy(&instr1, &next_ins.instrs, 2);
				temp_len = thumb_insn_size(instr1);

				setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)((bkup_ins.instrs&0xFFFF0000)|thumb_breakpoint));
			}
			else {
				temp_len = 4;

				setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)arm_breakpoint);
			}

			// Next PC Print
			fprintf(stderr, "\tNEXT(%d) : 0x%.8lX\t", temp_len, next_pc);
			for ( cnt = 0 ; cnt < temp_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
			}
			simple_disassem( IS_THUMB_ADDR(next_pc), &regs, next_ins.instrs );
			fprintf(stderr, "\n");
		}
		/*
		if ( DEBUG_MSG_PRINT > 0 ) {
			switch( setbreak_ret ) {
				case EBUSY:		fprintf(stderr, "\t[ERROR] Set Break(%X) - EBUSY\n", setbreak_ret); break;
				case EFAULT:	fprintf(stderr, "\t[ERROR] Set Break(%X) - EFAULT\n", setbreak_ret); break;
				case EINVAL:	fprintf(stderr, "\t[ERROR] Set Break(%X) - EINVAL\n", setbreak_ret); break;
				case EIO:		fprintf(stderr, "\t[ERROR] Set Break(%X) - EIO\n", setbreak_ret); break;
				case EPERM:		fprintf(stderr, "\t[ERROR] Set Break(%X) - EPERM\n", setbreak_ret); break;
				case ESRCH:		fprintf(stderr, "\t[ERROR] Set Break(%X) - ESRCH\n", setbreak_ret); break;
				default:		fprintf(stderr, "\t[NORMAL] Set Break(%X)\n", setbreak_ret); break;
			}
		}
		*/
		//--------------------------------------------------------------

		//--------------------------------------------- LDREX,STREX Handler
		strex_check = strexHandler_check( &mode, &curr_ins, strex_check );
		//--------------------------------------------------------------

		//------------ Current PC, Instruction of PC Disassemble & print
		if ( DEBUG_MSG_PRINT == 1 ) {
			fprintf(stderr, "\t\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
				regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
			fprintf(stderr, "\t\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
				regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
			fprintf(stderr, "\t\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
				regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
			fprintf(stderr, "\t\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
				regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
			fprintf(stderr, "\t\tcpsr=0x%.8X\n", regs.ARM_cpsr);
		}
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\tCURRENT : 0x%.8lX\t", curr_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", curr_ins.instr[cnt]);
			}
		}

		/*
		while ( ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0 );
		if ( ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0 ) {
			fprintf(stdout, "WTF !!!");
			fprintf(stderr, "WTF !!!");
		}
		*/
		//--------------------------------------------------------------

		//------------------------------------------------------ Logging
		disassem( &mode, instr_len, &curr_ins, &regs );
		log_entry.Members.Operands[12] = regs.ARM_sp;

		if ( arm_code_pass == 1 ) {
			counter--;
		}
		else {
			if ( counter > skip ) {
				fwrite(log_entry.Str, 1, sizeof(log_entry.Str), log_fd);
			}
		}
		//--------------------------------------------------------------

		//---------------- NEXT PC, Instruction of PC(just 4 byte) print
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\tNEXT(4) : 0x%.8lX\t", UNMAKE_THUMB_ADDR(next_pc));
			for ( cnt = 0 ; cnt <= 3 ; cnt++ ) {
				fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
			}
			fprintf(stderr, "\n");
		}
		//--------------------------------------------------------------

		//--------------------------------------- Target Thread Continue
		//thread_cont(pid, 0);
		thread_cont(0, 0);
		//--------------------------------------------------------------

		//-------------------------------------------------- Wait Signal
		pid_wait = waitProcess(9, &pid, &status, &next_pc, &bkup_ins);
		//--------------------------------------------------------------

		//------------------------------------------ Target Process Stop
		//thread_stop(0, 0);
		//--------------------------------------------------------------

		//------------------------------------- Restore Next Instruction
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)bkup_ins.instrs) ) {
			perror("[Target_Restore] ");
		}
		//--------------------------------------------------------------

		arm_code_pass = 0;
		thumb_code_pass = 0;
	} // END while( 1 )

	time(&t_end);
	t_time = difftime(t_end, t_start);
	fprintf(stdout, "\n- * - * - * - * - * - LOGGING FINISH - * - * - * - * - * -\n");

	fprintf(stdout, "\nFINAL status : %x\n", status);
	fprintf(stdout, "\nTotal Time :\t%lf\n", t_time);
	fprintf(stdout, "Total Instructions :\t\t\t%d\n", counter);
	fprintf(stdout, "Total Pass Instruction :\t\t%d = %d(ARM) + %d(Thumb)\n", arm_pass_pc + thumb_pass_pc, arm_pass_pc, thumb_pass_pc);
	fprintf(stdout, "# of Instruction excuted :\t\t%lf\n", counter/t_time);
	fprintf(stdout, "# of Lock Handler called :\t\t%d\n", strex_count);

	fprintf(stdout, "\nInput Data File : %s\n", arg_str);
	fprintf(stdout, "Input Data Size : %d\n", read_size);
	fprintf(stdout, "Input Data Memory : %lX - %lX\n", read_start_addr, read_end_addr);
	fprintf(stdout, "Process PID, Target TID :\t%d, %d\n", bkup_pid, pid);

	//fprintf(stdout, "\n%s\n", mapinfo_libc);
	//fprintf(stdout, "%s\n", mapinfo_libtarget);

	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "\nFINAL status : %x\n", status);
		fprintf(stderr, "\nTotal Time :\t%lf\n", t_time);
		fprintf(stderr, "Total Instructions :\t\t\t%d\n", counter);
		fprintf(stdout, "Total Pass Instruction :\t\t%d = %d(ARM) + %d(Thumb)\n", arm_pass_pc + thumb_pass_pc, arm_pass_pc, thumb_pass_pc);
		fprintf(stderr, "# of Instruction excuted :\t\t%lf\n", counter/t_time);
		fprintf(stderr, "# of Lock Handler called :\t\t%d\n", strex_count);

		fprintf(stderr, "\nInput Data File : %s\n", arg_str);
		fprintf(stderr, "Input Data Size : %d\n", read_size);
		fprintf(stderr, "Input Data Memory : %lX - %lX\n", read_start_addr, read_end_addr);
		fprintf(stderr, "Process PID, Target TID :\t%d, %d\n", bkup_pid, pid);

		//fprintf(stderr, "\n%s\n", mapinfo_libc);
		//fprintf(stderr, "%s\n", mapinfo_libtarget);
	}

	fclose(log_fd);

	if ( -1 == ptrace(PTRACE_KILL, pid, NULL, NULL) ) {
		perror("\t[EXIT] Detach Fail ");
	}

	pthread_kill( thread, SIGKILL );
	pthread_join( thread, (void **)&status );

	return 0;
}

// wait for user input for program exit
void * inputCommand(void * order)
{
	char szCmd[32];

	while( *((int *)order) == 0 )
	{
		scanf("%s", szCmd);

		if(!strcmp("q", szCmd) || !strcmp("quit", szCmd) || !strcmp("Q", szCmd) || !strcmp("Quit", szCmd))
		{
			*((int *)order) = 1;
		}
	}

	pthread_exit(0);
}

// look like waitpid. add status check
pid_t waitProcess(int no, pid_t * pid, int * stat, unsigned long * next_pc, Instruction * bkup_ins)
{
	pid_t pid_wait, tid;
	int ret, cnt, instr_len;
	arm_regs regs;
	unsigned long crash_pc, mode;
	Instruction crash_ins;

	int wait_opt = WNOHANG|__WALL;
	//int wait_opt = __WALL;

	while ( 1 ) {
		pid_wait = waitpid( -1, stat, wait_opt );

		if ( pid_wait == -1 )
		{
			perror("waitpid");
			return -1;
		}

		// Nobody get signal
		else if ( pid_wait == 0 ) {
			if ( no == 9 ) {
				thread_cont(0, *pid);
				if ( thread_state(*pid) == 't' || thread_state(*pid) == 'T' ) {
					return *pid;
				}
			}
			continue;
		}

		// pid_wait == pid
		else if ( pid_wait == *pid )
		{
			// CRASH !!!
			if( WSTOPSIG(*stat) == SIGFPE || WSTOPSIG(*stat) == SIGSEGV ) {
				ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

				fprintf(stdout, "\n<%d> --- [%d / %x(%d)] IS THIS CRASH ?\n\t(%d) : \"%s\" ---\n", no, pid_wait, *stat, *stat, tid, signal_name[WSTOPSIG(*stat)]);
				if ( DEBUG_MSG_PRINT > 0 ) {
					fprintf(stderr, "\n<%d> --- [%d / %x(%d)] IS THIS CRASH ?\n\t(%d) : \"%s\" ---\n", no, pid_wait, *stat, *stat, tid, signal_name[WSTOPSIG(*stat)]);
				}

				if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
					perror("[CRASH] ptrace_getregs");
				}

				counter++;
				log_entry.Members.Count = counter;

				crash_pc = regs.ARM_pc;
				crash_ins.instrs = ptrace(PTRACE_PEEKDATA, pid_wait, (void *)crash_pc, NULL);
				mode = regs.ARM_cpsr&CPSR_T;

				log_entry.Members.BitMask = regs.ARM_cpsr&( (FLAG_N|FLAG_Z|FLAG_C|FLAG_V) |CPSR_T);

				// Thumb mode
				if ( mode == CPSR_T ) {
					unsigned short inst1;
					memcpy(&inst1, &crash_ins.instrs, 2);

					instr_len = thumb_insn_size (inst1);

					log_entry.Members.Address = MAKE_THUMB_ADDR(crash_pc);
					if ( instr_len == 2 ) {
						log_entry.Members.Opcode = inst1;
					}
					else {
						log_entry.Members.Opcode = crash_ins.instrs;
					}
				}
				// ARM mode
				else {
					instr_len = 4;

					log_entry.Members.Address = crash_pc;
					log_entry.Members.Opcode = crash_ins.instrs;
				}

				fprintf(stdout, "\n[*] CRASH PC : 0x%.8lX\t", crash_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stdout, "%.2X ", crash_ins.instr[cnt]);
				}
				if ( DEBUG_MSG_PRINT > 0 ) {
					fprintf(stderr, "\n\t[*] CRASH PC : 0x%.8lX\t", crash_pc);
					for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
						fprintf(stderr, "%.2X ", crash_ins.instr[cnt]);
					}
				}
				disassem( &mode, instr_len, &crash_ins, &regs );

				if ( DEBUG_MSG_PRINT >= 0 ) {
					fprintf(stderr, "\t\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
						regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
					fprintf(stderr, "\t\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
						regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
					fprintf(stderr, "\t\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
						regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
					fprintf(stderr, "\t\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
						regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
					fprintf(stderr, "\t\tcpsr=0x%.8X\n", regs.ARM_cpsr);
				}

				log_entry.Members.Operands[12] = regs.ARM_sp;
				log_entry.Members.Operands[13] = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.ARM_sp, NULL);
				//log_entry.Members.Operands[14] = read_start_addr;
				//log_entry.Members.Operands[15] = read_end_addr;

				fwrite(log_entry.Str, 1, sizeof(log_entry.Str), log_fd);

				return -1;
			}
			else if( WIFSTOPPED(*stat) ) {
				// FORK or BreakPoint
				if( WSTOPSIG(*stat) == SIGTRAP ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGTRAP : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}
					// FORK
					if( (*stat >> 16) == PTRACE_EVENT_FORK ) {
						ret = ptrace(PTRACE_GETEVENTMSG, *pid, NULL, (void *)&tid);

						if ( DEBUG_MSG_PRINT > 0 ) {
							fprintf(stderr, "\n\t[*] IS THIS CHILD? %d, %d\n", ret, tid);
						}
					}
					// if THREAD
					else if( (*stat >> 16) == PTRACE_EVENT_CLONE ) {
						ret = ptrace(PTRACE_GETEVENTMSG, *pid, NULL, (void *)&tid);

						if ( DEBUG_MSG_PRINT > 0 ) {
							fprintf(stderr, "\n\t[*] IS THIS THREAD? %d, %d\n", ret, tid);
						}

						attach_thread_list[thread_list_cnt++] = tid;

						thread_cont(pid_wait, 0);
						continue;
					}
					else {
						return pid_wait;
					}
				}
				// BreakPoint
				else if( WSTOPSIG(*stat) == SIGSTOP ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGSTOP : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}

					if ( no == 9 ) {
						//fprintf(stderr, "[*] What's going on?\n");
						if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
							perror("[SIGSTOP] ptrace_getregs");
						}
						if ( regs.ARM_pc != *next_pc ) {
							//fprintf(stderr, "[SIGSTOP] => %c\n", thread_state(pid_wait));
							//thread_cont(pid_wait, 0);
							thread_cont(0, 0);
							continue;
						}
					}

					return pid_wait;
				}
				// BreakPoint(thumb mode)
				else if( WSTOPSIG(*stat) == SIGILL ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGILL : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}
					return pid_wait;
				}
				else {
					//if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] I Don't Know : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
						char t_state = thread_state(pid_wait);
						fprintf(stderr, "\t[%d] State : %c\n", pid_wait, t_state);
					//}
				}
			} // END if( WIFSTOPPED(*stat) ) {
			else if ( WIFSIGNALED(*stat) ) {
				tid = 0;
				ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

				if ( DEBUG_MSG_PRINT > 1 ) {
					fprintf(stderr, "\n<%d> [%d | %d-%d] SIGNALED : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
				}

				for ( cnt = thread_list_cnt-1 ; cnt >= 0 ; cnt-- ) {
					if ( pid_wait == attach_thread_list[cnt] ) {
						attach_thread_list[cnt] = 0;
						for ( cnt++ ; cnt < thread_list_cnt ; cnt++ ) {
							attach_thread_list[cnt-1] = attach_thread_list[cnt];
						}
						thread_list_cnt--;
						cnt = 0;
					}
				}

				return -1;
			}
			else if( WIFEXITED(*stat) ) {
				if ( DEBUG_MSG_PRINT > 1 ) {
					fprintf(stderr, "\n<%d> [%d | %d-%d] Exited : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
				}

				for ( cnt = thread_list_cnt-1 ; cnt >= 0 ; cnt-- ) {
					if ( pid_wait == attach_thread_list[cnt] ) {
						attach_thread_list[cnt] = 0;
						for ( cnt++ ; cnt < thread_list_cnt ; cnt++ ) {
							attach_thread_list[cnt-1] = attach_thread_list[cnt];
						}
						thread_list_cnt--;
						cnt = 0;
					}
				}

				if ( -1 == ptrace(PTRACE_DETACH, pid_wait, NULL, NULL) ) {
					//perror("\t[EXIT] Detach Fail ");
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\t[EXIT] Detach Fail => No : %d / bkup_pid : %d / pid_wait : %d\n", no, bkup_pid, pid_wait);
					}
				}

				if ( no != 9 ) {
					continue;
				}
				return -1;
			}

			return pid_wait;
		} // END else if ( pid_wait == *pid )

		// pid_wait != pid
		else
		{
			// CRASH !!!
			if( WSTOPSIG(*stat) == SIGFPE || WSTOPSIG(*stat) == SIGSEGV ) {
				ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

				fprintf(stdout, "\n<%d> --- [%d / %x(%d)] IS THIS CRASH ?\n\t(%d) : \"%s\" ---\n", no, pid_wait, *stat, *stat, tid, signal_name[WSTOPSIG(*stat)]);
				if ( DEBUG_MSG_PRINT > 0 ) {
					fprintf(stderr, "\n<%d> --- [%d / %x(%d)] IS THIS CRASH ?\n\t(%d) : \"%s\" ---\n", no, pid_wait, *stat, *stat, tid, signal_name[WSTOPSIG(*stat)]);
				}

				if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
					perror("[CRASH] ptrace_getregs");
				}

				counter++;
				log_entry.Members.Count = counter;

				crash_pc = regs.ARM_pc;
				crash_ins.instrs = ptrace(PTRACE_PEEKDATA, pid_wait, (void *)crash_pc, NULL);
				mode = regs.ARM_cpsr&CPSR_T;

				log_entry.Members.BitMask = regs.ARM_cpsr&( (FLAG_N|FLAG_Z|FLAG_C|FLAG_V) |CPSR_T);

				// Thumb mode
				if ( mode == CPSR_T ) {
					unsigned short inst1;
					memcpy(&inst1, &crash_ins.instrs, 2);

					instr_len = thumb_insn_size (inst1);

					log_entry.Members.Address = MAKE_THUMB_ADDR(crash_pc);
					if ( instr_len == 2 ) {
						log_entry.Members.Opcode = inst1;
					}
					else {
						log_entry.Members.Opcode = crash_ins.instrs;
					}
				}
				// ARM mode
				else {
					instr_len = 4;

					log_entry.Members.Address = crash_pc;
					log_entry.Members.Opcode = crash_ins.instrs;
				}

				fprintf(stdout, "\n[*] CRASH PC : 0x%.8lX\t", crash_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stdout, "%.2X ", crash_ins.instr[cnt]);
				}
				if ( DEBUG_MSG_PRINT > 0 ) {
					fprintf(stderr, "\n\t[*] CRASH PC : 0x%.8lX\t", crash_pc);
					for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
						fprintf(stderr, "%.2X ", crash_ins.instr[cnt]);
					}
				}
				disassem( &mode, instr_len, &crash_ins, &regs );

				if ( DEBUG_MSG_PRINT >= 0 ) {
					fprintf(stderr, "\t\tr00=0x%.8X r01=0x%.8X r02=0x%.8X r03=0x%.8X\n",
						regs.ARM_r0, regs.ARM_r1, regs.ARM_r2, regs.ARM_r3);
					fprintf(stderr, "\t\tr04=0x%.8X r05=0x%.8X r06=0x%.8X r07=0x%.8X\n",
						regs.ARM_r4, regs.ARM_r5, regs.ARM_r6, regs.ARM_r7);
					fprintf(stderr, "\t\tr08=0x%.8X r09=0x%.8X r10=0x%.8X r11=0x%.8X\n",
						regs.ARM_r8, regs.ARM_r9, regs.ARM_r10, regs.ARM_r11);
					fprintf(stderr, "\t\tr12=0x%.8X  sp=0x%.8X  lr=0x%.8X  pc=0x%.8X\n",
						regs.ARM_r12, regs.ARM_sp, regs.ARM_lr, regs.ARM_pc);
					fprintf(stderr, "\t\tcpsr=0x%.8X\n", regs.ARM_cpsr);
				}

				log_entry.Members.Operands[12] = regs.ARM_sp;
				log_entry.Members.Operands[13] = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.ARM_sp, NULL);
				//log_entry.Members.Operands[14] = read_start_addr;
				//log_entry.Members.Operands[15] = read_end_addr;

				fwrite(log_entry.Str, 1, sizeof(log_entry.Str), log_fd);

				return -1;
			}
			else if( WIFSTOPPED(*stat) ) {
				// FORK or BreakPoint
				if( WSTOPSIG(*stat) == SIGTRAP ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGTRAP : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}
					// FORK
					if( (*stat >> 16) == PTRACE_EVENT_FORK ) {
						ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

						if ( DEBUG_MSG_PRINT > 0 ) {
							fprintf(stderr, "\n\t[*] IS THIS CHILD? %d, %d\n", ret, tid);
						}
					}
					// if THREAD
					else if( (*stat >> 16) == PTRACE_EVENT_CLONE ) {
						ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

						if ( DEBUG_MSG_PRINT > 0 ) {
							fprintf(stderr, "\n\t[*] IS THIS THREAD? %d, %d\n", ret, tid);
						}

						attach_thread_list[thread_list_cnt++] = tid;

						thread_cont(pid_wait, 0);
						continue;
					}
					else {
						//------------------------------------------- Precondition Control Start
						//if ( no == 18 && bkup_ins->instrs == 0xe1a0c007 ) {
						if ( no == 18 ) {
							if ( DEBUG_MSG_PRINT > 0 ) {
								fprintf(stderr, "[CHECK 18] %d-%d, %.8x\n", *pid, pid_wait, bkup_ins->instrs);
							}
							if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
								perror("[CRASH] ptrace_getregs");
							}
							if ( regs.ARM_pc == *next_pc ) {
								*pid = pid_wait;
								return pid_wait;
							}
							continue;
						}
						//else if ( no == 19 && bkup_ins->instrs == 0xe3a07005 ) {
						else if ( no == 19 ) {
							if ( DEBUG_MSG_PRINT > 0 ) {
								fprintf(stderr, "[CHECK 19] %d-%d, %.8x\n", *pid, pid_wait, bkup_ins->instrs);
							}
							if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
								perror("[CRASH] ptrace_getregs");
							}
							if ( regs.ARM_pc == *next_pc ) {
								*pid = pid_wait;
								return pid_wait;
							}
							continue;
						}
						//------------------------------------------- Precondition Control End

						/*
						char t_state = thread_state(pid_wait);
						//if ( DEBUG_MSG_PRINT > 0 ) {
							fprintf(stderr, "[!] Other Thread Going~ : 0x%x(%d) - %c\n", pid_wait, pid_wait, t_state);
							for ( cnt = 0 ; cnt < thread_list_cnt ; cnt++ ) {
								fprintf(stderr, "\t[%d] %c\n", attach_thread_list[cnt], thread_state(attach_thread_list[cnt]));
							}
						//}
						t_state = thread_state(pid_wait);
						if ( t_state == 't' || t_state == 'T' ) {
							if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
								perror("[CRASH] ptrace_getregs");
							}
							if ( regs.ARM_pc == *next_pc ) {
								fprintf(stderr, "===> Thread Pass !!! %d\n", pid_wait);
								thread_pass(*pid, pid_wait, next_pc, bkup_ins);
							}
							else {
								fprintf(stderr, "===> Thread No Pass !!! %d\n", pid_wait);
								thread_cont(pid_wait, 0);
							}
						}
						*/
						char t_state = thread_state(*pid);
						if ( t_state == 't' || t_state == 'T' ) {
							return pid_wait;
						}
						else {
							//thread_cont(0, 0);
							thread_pass(*pid, pid_wait, next_pc, bkup_ins);
						}

						continue;
					}
				}
				else if( WSTOPSIG(*stat) == SIGSTOP ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGSTOP : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
						fprintf(stderr, "\t[%d] State : %c\n", pid_wait, thread_state(pid_wait));
					}

					if ( no != 9 ) {
						//fprintf(stderr, "[*] What's going on?\n");
						if (ptrace(PTRACE_GETREGS, pid_wait, 0, &regs) != 0) {
							perror("[SIGSTOP] ptrace_getregs");
						}
						if ( regs.ARM_pc != *next_pc ) {
							thread_cont(pid_wait, 0);
							continue;
						}
						else {
							*pid = pid_wait;
							return pid_wait;
						}
					}

					thread_cont(pid_wait, 0);
					continue;
				}
				// BreakPoint(thumb mode)
				else if( WSTOPSIG(*stat) == SIGILL ) {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] SIGILL : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}

					thread_cont(pid_wait, 0);
					continue;
				}
				else {
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\n<%d> [%d | %d-%d] I Don't Know : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
					}

					thread_cont(pid_wait, 0);
					continue;
				}
			} // END if( WIFSTOPPED(*stat) ) {
			else if ( WIFSIGNALED(*stat) ) {
				tid = 0;
				ret = ptrace(PTRACE_GETEVENTMSG, pid_wait, NULL, (void *)&tid);

				if ( DEBUG_MSG_PRINT > 1 ) {
					fprintf(stderr, "\n<%d> [%d | %d-%d] SIGNALED : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
				}

				for ( cnt = thread_list_cnt-1 ; cnt >= 0 ; cnt-- ) {
					if ( pid_wait == attach_thread_list[cnt] ) {
						attach_thread_list[cnt] = 0;
						for ( cnt++ ; cnt < thread_list_cnt ; cnt++ ) {
							attach_thread_list[cnt-1] = attach_thread_list[cnt];
						}
						thread_list_cnt--;
						cnt = 0;
					}
				}

				continue;
			}
			else if( WIFEXITED(*stat) ) {
				if ( DEBUG_MSG_PRINT > 1 ) {
					fprintf(stderr, "\n<%d> [%d | %d-%d] Exited : (%x=%d) \"%s\" ---\n", no, bkup_pid, *pid, pid_wait, *stat, *stat, signal_name[WSTOPSIG(*stat)]);
				}

				for ( cnt = thread_list_cnt-1 ; cnt >= 0 ; cnt-- ) {
					if ( pid_wait == attach_thread_list[cnt] ) {
						attach_thread_list[cnt] = 0;
						for ( cnt++ ; cnt < thread_list_cnt ; cnt++ ) {
							attach_thread_list[cnt-1] = attach_thread_list[cnt];
						}
						thread_list_cnt--;
						cnt = 0;
					}
				}

				if ( -1 == ptrace(PTRACE_DETACH, pid_wait, NULL, NULL) ) {
					//perror("\t[EXIT] Detach Fail ");
					if ( DEBUG_MSG_PRINT > 1 ) {
						fprintf(stderr, "\t[EXIT] Detach Fail => No : %d / bkup_pid : %d / pid_wait : %d\n", no, bkup_pid, pid_wait);
					}
				}

				continue;
			}
		} // END else
	} // END while ( 1 )

	return pid_wait;
}

// Find The Start Address of Keyword in the maps file
int getMapsAddr(pid_t pid, const char * keyword, mapdump_t * target_map)
{
	char szMapsPath[128];
	char szTemp[256] = {0,};

	char* token;
	char sprt[] = " \t";

	FILE * pFile;

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

// Using the maps file, Find Function Address in Library
unsigned long getLibFuncAddr(pid_t pid, const char * lname, const char * fname)
{
	mapdump_t map_libc_debugger[3], map_libc_debuggee[3];
	int memsize, asdf = 0;

	unsigned long offset;

	void * hLibc;
	unsigned long addr_func_debugger;
	unsigned long addr_func_debuggee;

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

void simple_disassem(int mode, arm_regs * regs, unsigned long instr) {
	csh     handle;
	cs_mode cmode;
	cs_insn *insn;
	size_t  cnt;
	int instr_len;

	// Thumb Mode
	if ( mode == 1 ) {
		cmode = CS_MODE_THUMB;
		unsigned short inst1;
		memcpy(&inst1, &instr, 2);
		instr_len = thumb_insn_size(inst1);
	}
	// ARM Mode
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
	csh		handle;
	cs_mode	cmode;
	cs_insn	*insn;
	size_t	cnt;

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

		/* [THUMB] LDREX,STREX Handler (Branch) in Android */
		if ( handler == 1 ) {
			*next_pc = *curr_pc + (instr_len + 1);

			// Current PC, Instruction Print
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Current Instruction Disassemble
			disassem( mode, instr_len, curr_ins, regs );

			// Next PC, Instruction Print
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

			// Current PC, Instruction Print
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Current Instruction Disassemble
			disassem( mode, instr_len, curr_ins, regs );

			// Next PC, Instruction Print
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

		/* [ARM] LDREX,STREX Handler (Branch) in Android */
		if ( handler == 1 ) {
			*next_pc = *curr_pc + 4;

			instr_len = 4;

			// Current PC, Instruction Print
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, "\tCURRENT : 0x%.8lX\t", *curr_pc);
				for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
					fprintf(stderr, "%.2X ", curr_ins->instr[cnt]);
				}
			}

			// Current Instruction Disassemble
			disassem( mode, instr_len, curr_ins, regs );

			// Next PC, Instruction Print
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

pid_t attach_thread(pid_t pid)
{
	char dirname[128];
	DIR *dir;

	struct dirent *ent;
	int value;
	char dummy;

	char fname[256];
	char state[128];
	FILE *fd;
	char tmp[256], name[256];
	char tmp_str[128];
	int tid, tmp_pid;
	int cnt, i;
	pid_t ret = 0;

	siginfo_t sinfo;
	struct task_struct *task;


	if ( snprintf(dirname, sizeof(dirname), "/proc/%d/task", (int)pid) >= sizeof(dirname) ) {
		perror("snprintf");
		exit(0);
	}

	dir = opendir(dirname);
	if ( !dir ) {
		perror("opendir");
		exit(0);
	}

	fprintf(stdout, "[*] Attaching Thread List - %s\n", dirname);
	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "[*] Attaching Thread List - %s\n", dirname);
	}

	cnt = 0;
	while ( (ent = readdir(dir)) != NULL )	{
		if ( sscanf(ent->d_name, "%d%c", &value, &dummy) != 1 ) {
			continue;
		}

		sprintf(fname, "/proc/%s/status", ent->d_name);
		fd = fopen(fname, "r");
		while( !feof(fd) )
		{
			memset(tmp, 0x00, 256);
			for ( i = 0 ; !feof(fd) && (tmp[i] = fgetc(fd)) != 0x0a ; i++ );

			tid = atoi(ent->d_name);

			if ( strstr(tmp, "Name") != NULL ) {
				memset(name, 0x00, 256);
				strcpy(name, tmp);
			}

			if ( strstr(tmp, "State") != NULL ) {
				fprintf(stdout, "\t[-] %s - %s\t\t%s", ent->d_name, name, tmp);
				if ( DEBUG_MSG_PRINT > 0 ) {
					fprintf(stderr, "\t[-] %s : %s", ent->d_name, tmp);
				}
				memset(state, 0x00, 128);
				strcpy(state, tmp);
			}
			if ( strstr(tmp, "TracerPid") != NULL ) {
				sscanf(tmp, "%s%d", tmp_str, &tmp_pid);
				if ( 0 < tmp_pid ) {
					fprintf(stderr, "\t[!] Is being debugged Already by %d\n", tmp_pid);
				}
				else if ( 0 == tmp_pid ) {
					if ( -1 == ptrace(PTRACE_ATTACH, tid, 0, 0) ) {
						memset(tmp_str, 0x00, 128);
						snprintf(tmp_str, 128, "[attach_thread : %d] %s", tid, state);
						perror(tmp_str);
					}
					else {
						attach_thread_list[thread_list_cnt++] = tid;
					}
				}
			}
		}
		fclose(fd);
	}
	closedir(dir);

	return ret;
}


void thread_stop(pid_t pid, pid_t except)
{
	int i;
	if ( pid == 0 ) {
		if ( DEBUG_MSG_PRINT > 1 ) {
			fprintf(stderr, "[*] Stopping Thread List\n");
		}
		for ( i = 0 ; i < thread_list_cnt ; i++ ) {
			if ( attach_thread_list[i] != except ) {
				if ( 0 != tkill(attach_thread_list[i], SIGSTOP) ) {
					perror("[THREAD_ALL_STOP] ");
				}
			}
		}
	}
	else {
		if ( DEBUG_MSG_PRINT > 1 ) {
			fprintf(stderr, "[*] Stopping Thread %d\n", pid);
		}
		if ( 0 != tkill(pid, SIGSTOP) ) {
			fprintf(stderr, "[THREAD_STOP - %d]", pid);
			perror(" ");
		}
	}
}


void thread_cont(pid_t pid, pid_t except)
{
	int i;
	if ( pid == 0 ) {
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "[*] Continue Thread List\n");
		}
		for ( i = 0 ; i < thread_list_cnt ; i++ ) {
			if ( attach_thread_list[i] != except ) {
				if ( -1 == ptrace(PTRACE_CONT, attach_thread_list[i], 0, 0) ) {
					//perror("[THREAD_ALL_CONT] ");
				}
			}
		}
	}
	else {
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "[*] Continue Thread %d\n", pid);
		}
		if ( -1 == ptrace(PTRACE_CONT, pid, 0, 0) ) {
			fprintf(stderr, "[THREAD_CONT - %d]", pid);
			perror(" ");
		}
	}
}


char thread_state(pid_t pid)
{
	char fname[256];

	FILE *fd;
	char tmp[128];
	char *ptr;
	char state = 'X';

	if ( snprintf(fname, sizeof(fname), "/proc/%d/stat", pid) >= sizeof(fname) ) {
		perror("\t[-] snprintf ERROR ");
		return state;
	}

	if ( (fd = fopen(fname, "r")) == NULL ) {
		perror("\t[-] Open ERROR ");
		return state;
	}

	fread( tmp, 1, 64, fd );
	fclose(fd);

	ptr = strtok( tmp, ")" );
	ptr = strtok( NULL, " " );
	sscanf( ptr, "%c", &state );

	return state;
}

void thread_pass(pid_t target_pid, pid_t pid, unsigned long * next_pc, Instruction * bkup_ins)
{
	//-------------------------------------------------------------------
	//---------------------------------- Other Thread Trap Control Start
	//-------------------------------------------------------------------
	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "\n\t---------------- Other Thread Control Start ----------------\n");
	}

	// 0. Target Thread Stop. We do not need to control the other thread.
	thread_stop(target_pid, 0);

	// 1. Get Register Information of the other thread
	unsigned long stop_pc;
	Instruction stop_ins;
	arm_regs regs;
	unsigned long mode;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) {
		perror("\t[STOPPED] ptrace_getregs ");
		fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
	}
	stop_pc = regs.ARM_pc;
	stop_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)stop_pc, NULL);
	mode = regs.ARM_cpsr&CPSR_T;

	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "\n\t[Other_Trap_Check - PC]\t\tnext_pc =\t\t%.8x, stop_pc =\t\t%.8x\n", *next_pc, stop_pc);
		fprintf(stderr, "\t[Other_Trap_Check - Instr]\tnext_instr =\t%.8x, stop_instr =\t%.8x\n", bkup_ins->instrs, stop_ins.instrs);
	}

	// 2. RESTORE the next_pc(stop_pc)
	int cnt, instr_len;
	// Thumb mode
	if ( mode == CPSR_T ) {
		// NEXT_PC(Break) Disassem, Print
		if ( IS_THUMB_ADDR(*next_pc) == 1 ) {
			unsigned short inst1;
			memcpy(&inst1, &bkup_ins->instrs, 2);
			instr_len = thumb_insn_size(inst1);
		}
		else {
			instr_len = 4;
		}
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] NEXT PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", bkup_ins->instr[cnt]);
			}
			fprintf(stderr, "\n");
		}

		// Stop_PC(Break) Disassem, Print
		unsigned short inst1;
		memcpy(&inst1, &stop_ins.instrs, 2);
		instr_len = thumb_insn_size (inst1);
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\t[*] STOP PC : 0x%.8lX\t", stop_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}

		// Next_PC Restore
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)bkup_ins->instrs) ) {
			perror("[Other_Trap_Restore(T)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
		// Next_PC Disassem, Print
		stop_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)*next_pc, NULL);

		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] RSTR PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}
	}
	// ARM mode
	else {
		// NEXT_PC(Break) Disassem, Print
		if ( IS_THUMB_ADDR(*next_pc) == 1 ) {
			unsigned short inst1;
			memcpy(&inst1, &bkup_ins->instrs, 2);
			instr_len = thumb_insn_size(inst1);
		}
		else {
			instr_len = 4;
		}
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] NEXT PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", bkup_ins->instr[cnt]);
			}
			fprintf(stderr, "\n");
		}

		// Stop_PC(Break) Disassem, Print
		instr_len = 4;
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\t[*] STOP PC : 0x%.8lX\t", stop_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}

		// Next_PC Restore
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)bkup_ins->instrs) ) {
			perror("[Other_Trap_Restore(A)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
		// Next_PC Disassem, Print
		stop_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)*next_pc, NULL);

		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] RSTR PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}
	}

	// 3. Get Next_Next PC, Instruction of Next_Next PC
	unsigned long next_next_pc;
	Instruction next_next_ins;

	if ( mode == CPSR_T ) {
		next_next_pc = thumb_get_next_pc(pid, *next_pc, &regs, &thumb_code_pass);
		thumb_pass_pc = thumb_pass_pc + thumb_code_pass;
	}
	else {
		next_next_pc = arm_get_next_pc(pid, *next_pc, &regs, &arm_code_pass);
		arm_pass_pc = arm_pass_pc + arm_code_pass;
	}

	if ( -1 == (next_next_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)UNMAKE_THUMB_ADDR(next_next_pc), NULL))) {
		perror("[Other_Trap_NextNextPC-Instr]");
		fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
	}

	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "\n\t[*] NEXTNEXT PC : 0x%.8lX\t", next_next_pc);
		for ( cnt = 0 ; cnt < 4 ; cnt++ ) {
			fprintf(stderr, "%.2X ", next_next_ins.instr[cnt]);
		}
		fprintf(stderr, "\n");
	}

	// 4. Set Breakpoint
	if ( IS_THUMB_ADDR(next_next_pc) == 1 ) {
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_next_pc, (void *)((next_next_ins.instrs&0xFFFF0000)|thumb_breakpoint)) ) {
			perror("[Other_Trap_NextNext - SetBreak(T)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}
	else {
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_next_pc, (void *)arm_breakpoint) ) {
			perror("[Other_Trap_NextNext - SetBreak(A)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}

	// 5. Run the other thread
	thread_cont(pid, 0);
	/*
	if ( -1 == ptrace(PTRACE_CONT, pid, 0, 0) ) {
		if ( DEBUG_MSG_PRINT > 0 ) {
			perror("[Other_CONT] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}
	*/

	// 6. Wait the other thread
	pid = waitpid( pid, 0, __WALL );
	if ( pid == -1 ) {
		fprintf(stderr, "[!] Pid Change\n");
		pid = target_pid;
	}
	/*
	char ret;
	do {
		ret = thread_state(pid);
		if ( DEBUG_MSG_PRINT > 1 ) {
			fprintf(stdout, "[%10d] Waiting Other Thread ( %5d : %c )\n", counter, pid, ret);
		}
	} while( ret != 't' && ret != 'T' && ret != 'X' && ret != 'S' && ret != 'Z' );
	*/



	// 7. Re-Breakpoint the Next PC
	if ( IS_THUMB_ADDR(*next_pc) == 1 ) {
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)((bkup_ins->instrs&0xFFFF0000)|thumb_breakpoint)) ) {
			perror("[Other_Trap_ReBreakpoint(T)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}
	else {
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)arm_breakpoint) ) {
			perror("[Other_Trap_ReBreakpoint(A)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}

	// 8. Restore the NextNext PC
	if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_next_pc, (void *)next_next_ins.instrs) ) {
		perror("[Other_Trap_Restore - NextNextPC] ");
		fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
	}

	// 9. Target Threads Go
	/*
	if (ptrace(PTRACE_GETREGS, target_pid, 0, &regs) != 0) {
		perror("\t[STOPPED] ptrace_getregs ");
		fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
	}
	if ( regs.ARM_pc != *next_pc ) {
		//fprintf(stderr, "[SIGSTOP] => %c\n", thread_state(pid_wait));
		thread_cont(target_pid, 0);
	}
	*/
	//thread_cont(target_pid, 0);

	if ( DEBUG_MSG_PRINT > 0 ) {
		fprintf(stderr, "\t---------------- Other Thread Control End ----------------\n");
	}
	//-------------------------------------------------------------------
	//---------------------------------- Other Thread Trap Control End
	//-------------------------------------------------------------------
}
