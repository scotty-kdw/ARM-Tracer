void *inputCommand(void *order);
pid_t waitProcess(int no, pid_t *pid, int *stat, unsigned long *next_pc, Instruction *bkup_ins);

pid_t attach_thread(pid_t pid);

void thread_stop(pid_t pid, pid_t except);
void thread_cont(pid_t pid, pid_t except);
char thread_state(pid_t pid);
void thread_pass(pid_t pid, pid_t pid_wait, unsigned long *next_pc, Instruction *bkup_ins);

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

extern LogEntry log_entry;
extern int DEBUG_MSG_PRINT;