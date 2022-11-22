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
	f->rsp;
	f->R.rax;
	check_address(f->rsp);
	check_address(f->R.rax);
	
// 	시스템 콜 핸들러에서 시스템 콜 번호에 해당하는 시스템 콜 호출
// 시스템 콜 핸들러에서 유저 스택 포인터(esp) 주소와 인자가 가리키는 주소(
// 포인터)가 유저 영역인지 확인
// pintos는 유저영역을 벗어난 주소를 참조할 경우 페이지 폴트 발생
// 유저 스택에 있는 인자들을 커널에 저장
// 시스템 콜의 함수의 리턴 값은 인터럽트 프레임의 eax에 저장
	printf ("system call!\n");
	thread_exit ();
}

void check_address(void *addr) {
	if(!is_user_vaddr(addr)){
		process_exit();
	}
/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
/* 잘못된 접근일 경우 프로세스 종료 */
}
