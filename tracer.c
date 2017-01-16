#include "arm_single.h"
#include "tracer.h"

#ifdef __cplusplus
        extern "C" {
#endif

void __exidx_start() {}
void __exidx_end() {}

#ifdef __cplusplus
        }
#endif

#define THREAD_LIST_NUM 100

int DEBUG_MSG_PRINT = 0;
int arm_code_pass = 0;
int thumb_code_pass = 0;
int thread_list_cnt = 0;

unsigned int counter = 0;
unsigned int arm_pass_pc = 0;
unsigned int thumb_pass_pc = 0;

unsigned long read_start_addr = 0, read_end_addr = 0;

pid_t bkup_pid = 0;
pid_t attach_thread_list[THREAD_LIST_NUM] = {0,};

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
				fprintf(stderr, "\n[?] Unknown Option : %c\n\n", optopt); 
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

		//-------------------------------------------- Check PRE-CONDITION 
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
		// Thumb state
		if ( mode == CPSR_T ) {
			next_pc = thumb_get_next_pc(pid, curr_pc, &regs, &thumb_code_pass);
			thumb_pass_pc = thumb_pass_pc + thumb_code_pass;
			if ( DEBUG_MSG_PRINT > 0 ) {
				fprintf(stderr, " / Code Pass = %d\n", thumb_code_pass);
			}
		}
		// ARM state
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

		//-------------------------------------------------- Check SWI Arg
		// Check SVC
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


		// Check Open, File Descriptor
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
		// Set Breakpoint at the Next PC
		bkup_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)next_pc, NULL);

		long setbreak_ret;
		// if Next PC is ThumbState Address
		if ( IS_THUMB_ADDR(next_pc) == 1 ) {
			setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)((bkup_ins.instrs&0xFFFF0000)|thumb_breakpoint));
		}
		else {
			setbreak_ret = ptrace(PTRACE_POKEDATA, pid, (void *)next_pc, (void *)arm_breakpoint);
		}

		// Check break-set
		if ( setbreak_ret == -1 ) {
			fprintf(stderr, "\n\t[Break Point ISSUE]\n", curr_pc);

			// Print the Current PC
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
			// Thumb state
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

			// Print the Next PC
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

		//------------ Show disassembly of the current PC and the instruction
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

		//---------------- Print the Next PC and the instruction of PC(just 4 byte)
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\tNEXT(4) : 0x%.8lX\t", UNMAKE_THUMB_ADDR(next_pc));
			for ( cnt = 0 ; cnt <= 3 ; cnt++ ) {
				fprintf(stderr, "%.2X ", next_ins.instr[cnt]);
			}
			fprintf(stderr, "\n");
		}
		//--------------------------------------------------------------

		//--------------------------------------- Continue Target Thread
		//thread_cont(pid, 0);
		thread_cont(0, 0);
		//--------------------------------------------------------------

		//-------------------------------------------------- Wait Signal
		pid_wait = waitProcess(9, &pid, &status, &next_pc, &bkup_ins);
		//--------------------------------------------------------------

		//------------------------------------------ Stop Target Process
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

// Wait for user input for program exit
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

// Look like waitpid (Status Check added)
pid_t waitProcess(int no, pid_t * pid, int * stat, unsigned long * next_pc, Instruction * bkup_ins)
{
	
	int ret, cnt, instr_len;
	int wait_opt = WNOHANG|__WALL;
	//int wait_opt = __WALL;

	unsigned long crash_pc, mode;
	
	arm_regs regs;
	Instruction crash_ins;

	pid_t pid_wait, tid;

	while ( 1 ) {
		pid_wait = waitpid( -1, stat, wait_opt );

		if ( pid_wait == -1 )
		{
			perror("waitpid");
			return -1;
		}

		// Nobody gets signal
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

				// Thumb state
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
				// ARM state
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
				// BreakPoint(thumb state)
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

				// Thumb state
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
				// ARM state
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
				// BreakPoint(thumb state)
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

pid_t attach_thread(pid_t pid)
{
	int tid, tmp_pid, cnt, i, value;

	char dummy;
	char fname[256];
	char state[128];
	char dirname[128];
	char tmp[256], name[256];
	char tmp_str[128];

	struct dirent *ent;
	struct task_struct *task;

	pid_t ret = 0;

	siginfo_t sinfo;	
	FILE *fd;
	DIR *dir;	

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
	char tmp[128];

	char state = 'X';
	char *ptr;

	FILE *fd;

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

	// 0. Target Thread Stop. We do not need to control the other threads.
	thread_stop(target_pid, 0);

	// 1. Get Register Information of the other threads
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
	// Thumb state
	if ( mode == CPSR_T ) {
		// Print disassembly of the Next_PC(Break)
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

		// Print disassembly of the Stop_PC(Break)
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

		// Restore the Next_PC
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)bkup_ins->instrs) ) {
			perror("[Other_Trap_Restore(T)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
		// Print disassembly of the Next_PC
		stop_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)*next_pc, NULL);

		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] RSTR PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}
	}
	// ARM state
	else {
		// Print disassembly of the NEXT_PC(Break)
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

		// Print disassembly of the Stop_PC(Break)
		instr_len = 4;
		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\t[*] STOP PC : 0x%.8lX\t", stop_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}

		// Restore the Next_PC
		if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)*next_pc, (void *)bkup_ins->instrs) ) {
			perror("[Other_Trap_Restore(A)] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
		// Print disassembly of the Next_PC
		stop_ins.instrs = ptrace(PTRACE_PEEKDATA, pid, (void *)*next_pc, NULL);

		if ( DEBUG_MSG_PRINT > 0 ) {
			fprintf(stderr, "\n\t[*] RSTR PC : 0x%.8lX\t", *next_pc);
			for ( cnt = 0 ; cnt < instr_len ; cnt++ ) {
				fprintf(stderr, "%.2X ", stop_ins.instr[cnt]);
			}
			disassem( &mode, instr_len, &stop_ins, &regs );
		}
	}

	// 3. Get Next_Next PC and Instruction of Next_Next PC
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

	// 5. Run the other threads
	thread_cont(pid, 0);
	/*
	if ( -1 == ptrace(PTRACE_CONT, pid, 0, 0) ) {
		if ( DEBUG_MSG_PRINT > 0 ) {
			perror("[Other_CONT] ");
			fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
		}
	}
	*/

	// 6. Wait the other threads
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



	// 7. Re-Breakpoint at the Next PC
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

	// 8. Restore the Next_Next PC
	if ( -1 == ptrace(PTRACE_POKEDATA, pid, (void *)next_next_pc, (void *)next_next_ins.instrs) ) {
		perror("[Other_Trap_Restore - NextNextPC] ");
		fprintf(stderr, "\t-(%d) State : %c\n", pid, thread_state(pid));
	}

	// 9. Continue Target Thread
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
