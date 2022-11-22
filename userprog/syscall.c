#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
// TODO: Your implementation goes here.
	// f->rsp;
	// f->R.rax;
	// check_address(f->rsp);
	// check_address(f->R.rax);

	int syscall_number = f->R.rax;

	switch (syscall_number){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	fork(f->R.rdi);
		// 	break;
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		// 	break;
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			remove(f->R.rdi);
			break;
		// case SYS_OPEN:
		// 	open(f->R.rdi);
		// 	break;
		// case SYS_FILESIZE:
		// 	filesize(f->R.rdi);
		// 	break;
		// case SYS_READ:
		// 	read(f->R.rdi, f->R.rsi, f->R.rdx);
		// 	break;
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	seek(f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL:
		// 	tell(f->R.rdi);
		// 	break;
		// case SYS_CLOSE:
		// 	close(f->R.rdi);
		// 	break;	
		default:
			break;
	}

// 시스템 콜의 함수의 리턴 값은 인터럽트 프레임의 eax에 저장
	// printf ("system call!\n");
	// thread_exit ();
}

void check_address(void *addr) {
	if((!is_user_vaddr(addr)) || (pml4_get_page(thread_current()->pml4, addr)) == NULL||(addr == NULL)){	
		exit(-1);
	}

/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
/* 잘못된 접근일 경우 프로세스 종료 */
}


void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}

bool 
create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size); // directory:filesys / filesys.c 
}

bool
remove (const char *file) {
	return filesys_remove(file); // directory:filesys / filesys.c
}
// Parent~child struct 구현 

// tid_t exec(const char* cmd_line){

// }
int write (int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
}