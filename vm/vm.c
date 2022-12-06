/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/uninit.h"
#include "threads/mmu.h"

#include "userprog/process.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// printf("----------vm_alloc_page_with_initializer 시작---------\n");
		struct page *new_page = (struct page *)malloc(sizeof(struct page));
		// printf("----------새 페이지 말록---------\n");
		if (type == VM_ANON)
		{
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
			// printf("----------anon page 초기화---------\n");
		} //[3-1?] ??
		else if (type == VM_FILE)
		{
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
			// printf("----------file page 초기화---------\n");
		}
		// else if (type == VM_MARKER_0){
		// 	uninit_new(new_page, upage, init, type, aux, anon_initializer);
		// }
		else
		{
			printf("유효하지 않은 페이지 타입\n");
			uninit_new(new_page, upage, init, type, aux, NULL);
			goto err;
		}
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, new_page) == false)
		{
			// printf("----------spt insert page 실패---------\n");
			goto err;
		}
	}
	// printf("----------vm_alloc 성공!---------\n");
	return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page *page = NULL;

	/* TODO: Fill this function. */
	// [3-1?] 우리가 원하는 va에 해당하는 페이지를 찾기 위해 가짜 페이지 할당
	// printf("----va: %p-----\n", va);
	struct page *temp = palloc_get_page(PAL_USER);
	temp->va = pg_round_down(va);
	// printf("----temp->va: %p-----\n", temp->va);
	// 가짜 페이지와 같은 hash를 가지는 페이지를 찾아옴
	struct hash_elem *va_hash_elem = hash_find(&spt->spt_hash, &temp->h_elem);
	// printf("----hash_elem: %p-----\n", va_hash_elem);
	// 가짜 페이지 메모리 해제
	palloc_free_page(temp);

	if (va_hash_elem != NULL)
	{
		// printf("----hash elem 찾음!----\n");
		page = hash_entry(va_hash_elem, struct page, h_elem);
		// printf("찾은 페이지 va : %p\n", page->va);
	}
	// printf("----page 찾음!----\n");
	return page;
}

// struct page *spt_find_page(struct supplemental_page_table *spt, void *va){

// 	struct page *temp;
// 	temp->va = pg_round_down(va);
// 	struct hash_elem *va_hash_elem = hash_find(&spt->spt_hash, &temp->elem);
// 	if (va_hash_elem == NULL)
// 		return NULL;
// 	else
// 		return hash_entry(va_hash_elem, struct page, elem);
// }

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
					 struct page *page)
{
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&spt->spt_hash, &page->h_elem) == NULL)
	{
		succ = true;
	}
	return succ;
}

// bool spt_insert_page(struct supplemental_page_table *spt, struct page *page){

// 	if (hash_insert(&spt->spt_hash, &page->elem)==NULL) {
// 		return true;
// 	}
// 	else {
// 		return false;
// 	}
// }

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *new_kva = palloc_get_page(PAL_USER); //유저 풀에서 새로운 물리 페이지를 가져온다
	// printf("--- palloc_get_page: %p -----\n", new_kva);
	if (new_kva == NULL)
	{
		PANIC("todo"); //페이지 할당이 실패하면, 일단 패닉 -> 나중에 수정
	}
	else
	{
		// 프레임 초기화
		frame = (struct frame *)malloc(sizeof(struct frame)); // [3-1?] 프레임 할당은 어디서 해오지????!!@!!@!!@!!@!@malloc을 하라
		// printf("----frame 할당: %p -----\n", frame);
		frame->kva = new_kva;
		frame->page = NULL;
		// printf("----kva	세팅: %p -----\n", frame->kva);
		// 프레임에 매핑된 페이지 초기화
		// struct page *new_page;
		// new_page->frame = new_frame;
		// new_page->va = new_kva;
		// [3-1?] 다른 멤버들 초기화 필요? (operations, union)
	}
	// printf("----frame 할당: %p -----\n", frame);
	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

// static struct frame *vm_get_frame(void){
// 	void *new_kva = palloc_get_page(PAL_USER); //유저 풀에서 새로운 물리 페이지를 가져온다
// 	if (new_kva==NULL){
// 		PANIC("todo"); //페이지 할당이 실패하면, 일단 패닉 -> 나중에 수정
// 	}
// 	else{
// 		// 프레임 초기화
// 	struct frame *new_frame = (struct frame *)malloc(sizeof(struct frame)); // [3-1?] 프레임 할당은 어디서 해오지????!!@!!@!!@!!@!@malloc을 하라
// 		new_frame->kva = new_kva;
// 		// 프레임에 매핑된 페이지 초기화
// 		// struct page *new_page;
// 		// new_page->frame = new_frame;
// 		// new_page->va = new_kva;
// 		// [3-1?] 다른 멤버들 초기화 필요? (operations, union)
// 		return new_frame;
// 	}
// }

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	//printf("VM_TRY_HANDLE_FAULT: %p\n", addr);
	//printf("[vm_try_handle_fault] user: %d\n", user);
	//printf("[vm_try_handle_fault] write: %d\n", write);
	//printf("[vm_try_handle_fault] not_present: %d\n", not_present);
	//printf("[vm_try_handle_fault] tid: %d\n", thread_current()->tid);
	// printf("[1]\n");

	check_address(addr);

	// if (not_present || write || user)
	// { //  유효하지 않은 접근일 때
	// 	// [3-2??] spt_find_page(spt, addr)가 null로 반환하는 경우도 생각해야할까?
	// 	page = spt_find_page(spt, addr);
	// 	// [3-2??] 해당 자원 해제?
	// 	// printf("-----vm_try_handle_fault--------\n");
	// 	exit(-1);
	// }
	/* lazy loading 으로 인한 page fault */
	// printf("[2]\n");
	page = spt_find_page(spt, addr);
	//printf("-----vm_try_handle_fault: spt_find_page--------\n");

	bool doclaim_r = vm_do_claim_page(page);
	//printf("-----vm_try_handle_fault: vm_do_claim_page--------\n");

	return doclaim_r;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	// printf("[vm_claim_page] va: %p ----------\n", va);
	page = spt_find_page(&thread_current()->spt, va);
	// printf("[vm_claim_page] page->va: %p ----------\n", page->va);
	if (page == NULL)
	{
		// printf("page 못찾음~~\n");
		return false;
	}
	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
bool vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();
	int result = false;
	struct thread *t = thread_current();
	// printf("===========vm_do_claim_page: start=============\n");
	// printf("[vm_do_claim_page] tid: %d\n", thread_current()->tid);

	/* Set links */
	// printf("[vm_do_claim_page] frame kva: %p\n", frame->kva);
	frame->page = page;
	// printf("[vm_do_claim_page] page va: %p\n", page->va);
	page->frame = frame;
	// printf("[vm_do_claim_page] set-link 완료\n");

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// [3-1?] wr 세팅을 1로 하는게 맞나?

	if (!install_page(page->va, frame->kva, 1)){
		return false;
	}
	// printf("[vm_do_claim_page] set_page 성공 \n");

	result = swap_in(page, frame->kva);
	// printf("[vm_do_claim_page] swap_in - RESULT: %d \n", result);
	// printf("============vm_do_claim_page: end==============\n");
	return result;
}

// bool vm_do_claim_page(struct page *page){
// 	struct frame *f = vm_get_frame();

// 	// uint64_t *pte = pml4e_walk(&thread_current()->pml4, (uint64_t)page, 0);
// 	// if (pte==NULL)
// 	// 	return false;
// 	// else
// 	// [3-1?] wr 세팅을 1로 하는게 맞나?
// 	return pml4_set_page(&thread_current()->pml4, page, f, 1);
// }

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash, spt_hash_func, spt_less_func, NULL);
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	const struct page *p = hash_entry(e, struct page, h_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct page *ap = hash_entry(a, struct page, h_elem);
	const struct page *bp = hash_entry(b, struct page, h_elem);

	return ap->va < bp->va;
}

/* Project 3-2 Anonymous Page */
/* src에서 dst로 spt를 복사하는 함수
자식이 부모의 execution context를 복사해야 할 때 사용됨 (i.e. fork())
src의 spt에 있는 각 페이지를 순회하면서 각 엔트리와 똑같은 복사본을 dst의 spt에 만든다.
uninit page를 할당하고 즉시 claim 해야함 */
/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED)
{
	// struct hash_iterator i;
	// hash_first(&i, &src->spt_hash);
	// while (hash_next (&i)){
	// 	struct page *p = hash_entry(hash_cur(&i), struct page, h_elem);
	// 	if (p->operations->type == VM_UNINIT)
	// 	{
	// 		vm_alloc_page_with_initializer(p->uninit.type, p->va, 1, lazy_load_segment, NULL);
	// 		//vm_claim_page(p->va);
	// 	}
	// 	else
	// 	{
	// 		vm_alloc_page(p->operations->type, p->va, 1);
	// 		struct page *child_p = spt_find_page(&thread_current()->spt, p->va);

	// 		vm_claim_page(p->va);
	// 		memcpy(child_p->frame->kva, p->frame->kva, PGSIZE);
	// 	}
	// }

	// //hex

	hash_apply(&src->spt_hash, supplemental_copy_entry);

	return true;
}

void supplemental_copy_entry(struct hash_elem *e, void *aux){

	struct page *p = hash_entry(e, struct page, h_elem);
	//printf("---------spt_entry---------\n");
	if (p->operations->type == VM_UNINIT){

		//printf("---------spt_entry: VM_UNINIT---------\n");
		vm_alloc_page_with_initializer(p->uninit.type, p->va, 1, lazy_load_segment, NULL);
		//vm_claim_page(p->va);

		//struct page *child_p = spt_find_page(&thread_current()->spt, p->va);
		//printf("[spt entry] p kva: %p\n", p->frame->kva);
		//printf("[spt entry] p va: %p\n", p->frame->page->va);
		//printf("[spt entry] child_p kva: %p\n", child_p->frame->kva);
		//printf("[spt entry] child_p va: %p\n", child_p->frame->page->va);
		//printf("child_p page: %p\n", pml4_get_page(thread_current()->pml4, p->va));
	}
	else{
		//printf("---------spt_entry: VM_ANON---------\n");
		vm_alloc_page(p->operations->type, p->va, 1);
		struct page *child_p = spt_find_page(&thread_current()->spt, p->va);
		
		vm_claim_page(p->va);
		// printf("[spt entry] p kva: %p\n", p->frame->kva);
		// printf("[spt entry] p va: %p\n", p->frame->page->va);
		// printf("[spt entry] child_p kva: %p\n", child_p->frame->kva);
		// printf("[spt entry] child_p va: %p\n", child_p->frame->page->va);
		memcpy(child_p->frame->kva, p->frame->kva, PGSIZE);
		//printf("parent_p content: %s\n", p->frame->kva);
		//printf("child_p page: %p\n", pml4_get_page(thread_current()->pml4, p->va));
	}
	
}

/* Project 3-2 Anonymous Page */
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	//hash_destroy(&spt->spt_hash, supplemental_destroy_entry);
}

void supplemental_destroy_entry(struct hash_elem *e, void *aux)
{
	struct page *p = hash_entry(e, struct page, h_elem);
	destroy(p);
}