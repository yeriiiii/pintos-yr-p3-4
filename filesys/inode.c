#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/fat.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
{
	disk_sector_t start; /* 디스크 상에서 파일의 시작 섹터 */
	disk_sector_t end; /* 디스크 상에서 파일의 끝 섹터 */
	off_t length;		  /* File size in bytes. */
	unsigned magic;		  /* Magic number. */
	uint32_t unused[124]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
	return DIV_ROUND_UP(size, DISK_SECTOR_SIZE);
}


/* In-memory inode. */
struct inode
{
	struct list_elem elem; /* Element in inode list. */
	disk_sector_t sector;
	int open_cnt;			/* Number of openers. */
	bool removed;			/* True if deleted, false otherwise. */
	int deny_write_cnt;		/* 0: writes ok, >0: deny writes. */
	struct inode_disk data; /* Inode content. */
};

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector(struct inode *inode, off_t pos)
{
	ASSERT(inode != NULL);
	// cluster_t cur;

	// if (inode_length(inode) == 0)
	// {
	// 	cur = fat_create_chain(0);
	// 	inode->data.start = sector_to_cluster(cur);

	// }

	int jump = pos / (int)DISK_SECTOR_SIZE;
	cluster_t cur = sector_to_cluster(inode->data.start);
	for (int i = 0; i < jump; i++)
	{
		cur = fat_get(cur);
		if (cur == EOChain)
		{
			return -1;
		}
	}
	return cluster_to_sector(cur);
}

void extend_file_to_pos(struct inode *inode, off_t pos){

	cluster_t eochain;
	char zeros[DISK_SECTOR_SIZE];

	int add_sectors = ((int)(pos - inode_length(inode)) / (int)DISK_SECTOR_SIZE) + 1;

	/* pos < inode_length 인 경우, 파일을 늘리지 않고 pos이 있는 섹터를 반환 */
	if (add_sectors <= 0)
		return;

	/* pos >= inode_length 인 경우, 파일을 늘려주기 위해 체인을 연장함 */

	if (inode_length(inode) == 0) // 파일 길이가 0인 경우
		eochain = 0; // 체인이 없음
	else // 파일 길이가 0이 아닌 경우
		eochain = inode->data.end; // 체인의 마지막 클러스터를 불러옴

	cluster_t cur = eochain; 
	for (int i = 0; i < add_sectors; i++)
	{
		cur = fat_create_chain(cur);
		if (eochain == 0) {
			inode->data.start = cluster_to_sector(cur);
		}
		disk_write(filesys_disk, cluster_to_sector(cur), zeros);
		inode->data.length += DISK_SECTOR_SIZE; // [TBD] 찐렝스는 이거 아닌데 나중에 고칠까?
	}
	inode->data.end = cluster_to_sector(cur);

	return;
}

// /* fat를 순회하면서 pos이 위치한 섹터의 번호를 반환합니다
// 만약에 순회하다가 체인이 끝날 경우 (EOChain), pos까지 체인을 연장하고 해당 섹터를 0으로 채웁니다*/
// cluster_t fat_byte_to_cluster(struct inode *inode, off_t pos)
// {
// 	ASSERT(inode != NULL);

// 	char zeros[DISK_SECTOR_SIZE];
// 	cluster_t cur;

	
// 	if (inode_length(inode) == 0)
// 	{
// 		cur = fat_create_chain(0);
// 		disk_write(filesys_disk, cluster_to_sector(cur), zeros);
// 		inode->data.start = cluster_to_sector(cur);
		
// 	}
// 	else
// 		cur = sector_to_cluster(inode->data.start);

// 	// printf("[fat_byte_to_cluster] inode->data.start: %d\n", inode->data.start);
// 	// printf("[fat_byte_to_cluster] cur: %d\n", cur);

// 	if (pos==0){
// 		return cur;
// 	}

// 	int jump = pos / (int)DISK_SECTOR_SIZE;
// 	// printf("[fat_byte_to_cluster] jump: %d\n", jump);

// 	for (int i = 0; i < jump; i++)
// 	{

// 		cluster_t old_cur = cur;
// 		cur = fat_get(cur);
// 		// printf("[fat_byte_to_cluster] [1] cur : %d\n", cur);

// 		if (cur == EOChain)
// 		{
// 			// printf("[fat_byte_to_cluster] [1.5]\n");
// 			cur = fat_create_chain(old_cur);
// 			// printf("[fat_byte_to_cluster] [2] cur: %d\n", cur);
// 			disk_write(filesys_disk, cluster_to_sector(cur), zeros);
// 			// printf("[fat_byte_to_cluster] [3]\n");
// 			inode->data.length += DISK_SECTOR_SIZE;
// 			// printf("[fat_byte_to_cluster] [4] length: %d\n", inode->data.length);
// 		}
// 	}
// 	return cur;
// }

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
	list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
/* 데이터의 길이 바이트로 inode를 초기화합니다.
 * 파일 시스템 디스크의 섹터에 새 inode를 씁니다.
 * 성공하면 true를 반환합니다.
 * 메모리 또는 디스크 할당에 실패하면 false를 반환합니다. */
bool inode_create(disk_sector_t sector, off_t length)
{
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT(length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	/* 실패하면, 아이노드 구조는 정확히 한 섹터 크기가 아니며, 당신은 그것을 수정해야 한다.*/
	ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc(1, sizeof *disk_inode);
	if (disk_inode != NULL)
	{
		// size_t sectors = bytes_to_sectors (length);

		if (sector == cluster_to_sector(ROOT_DIR_CLUSTER)){
			disk_inode->length == DISK_SECTOR_SIZE;
		}
		disk_inode->length = 0;
		disk_inode->magic = INODE_MAGIC;
		// if (free_map_allocate (sectors, &disk_inode->start)) {
		disk_write(filesys_disk, sector, disk_inode);
		// if (sectors > 0) {
		// 	static char zeros[DISK_SECTOR_SIZE];
		// 	size_t i;

		// 	for (i = 0; i < sectors; i++)
		// 		disk_write (filesys_disk, disk_inode->start + i, zeros);
		// }
		success = true;
		// }
		free(disk_inode);
	}
	return success;
}

// /* Initializes an inode with LENGTH bytes of data and
//  * writes the new inode to sector SECTOR on the file system
//  * disk.
//  * Returns true if successful.
//  * Returns false if memory or disk allocation fails. */
// bool inode_create(disk_sector_t sector, off_t length)
// {
// 	struct inode_disk *disk_inode = NULL;
// 	bool success = false;

// 	ASSERT(length >= 0);

// 	/* If this assertion fails, the inode structure is not exactly
// 	 * one sector in size, and you should fix that. */
// 	ASSERT(sizeof *disk_inode == DISK_SECTOR_SIZE);

// 	disk_inode = calloc(1, sizeof *disk_inode);
// 	if (disk_inode != NULL)
// 	{
// 		size_t sectors = bytes_to_sectors(length); // 주어진 파일 길이를 위한 섹터 수를 계산
// 		disk_inode->length = length;
// 		disk_inode->magic = INODE_MAGIC;

// 		cluster_t cur = 0;
// 		static char zeros[DISK_SECTOR_SIZE];

// 		for (size_t i = 0; i < sectors; i++)
// 		{
// 			if (cur == 0){
// 				cur = fat_create_chain(0); // 새로운 체인 만들기
// 				disk_inode->start = cluster_to_sector(cur); // 체인의 시작점 저장하기
// 			}
// 			else
// 				cur = fat_create_chain(cur);

// 			disk_write(filesys_disk, cluster_to_sector(cur), zeros);
// 		}
// 		disk_write(filesys_disk, sector, disk_inode); // 디스크에 아이노드 내용 기록하기
// 		success = true;

// 		free(disk_inode);
// 	}
// 	return success;
// }


/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(disk_sector_t sector)
{
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
		 e = list_next(e))
	{
		inode = list_entry(e, struct inode, elem);
		if (inode->sector == sector)
		{
			inode_reopen(inode);
			return inode;
		}
	}

	/* Allocate memory. */
	inode = malloc(sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front(&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read(filesys_disk, inode->sector, &inode->data);

	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber(const struct inode *inode)
{
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0)
	{
		/* Remove from inode list and release lock. */
		list_remove(&inode->elem);
		disk_write(filesys_disk, inode->sector, &inode->data);

		/* Deallocate blocks if removed. */
		if (inode->removed)
		{
			/* remove disk_inode */
			fat_remove_chain(sector_to_cluster(inode->sector), 0);

			/* remove file data */
			fat_remove_chain(sector_to_cluster(inode->data.start), 0);
		}

		free(inode);
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void inode_remove(struct inode *inode)
{
	ASSERT(inode != NULL);
	inode->removed = true;
}

// /* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
//  * Returns the number of bytes actually read, which may be less
//  * than SIZE if an error occurs or end of file is reached. */
// /* 위치 오프셋에서 시작하여 INODE에서 버퍼로 SIZE 바이트를 읽습니다.
//    실제로 읽은 바이트 수를 반환합니다.
//    오류가 발생하거나 파일 끝에 도달한 경우 SIZE보다 작을 수 있습니다. */
// off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
// {
// 	uint8_t *buffer = buffer_;
// 	off_t bytes_read = 0;
// 	uint8_t *bounce = NULL;

// 	// printf("inode read at - offset : %d\n", offset);
// 	// printf("inode read at - length : %d\n", inode_length(inode));
// 	if (offset > inode_length(inode) || inode_length(inode)==0)
// 		return 0;


// 	disk_sector_t sector_idx = byte_to_sector(inode, offset); // 오프셋이 있는 섹터의 인덱스
// 	cluster_t cluster_idx = sector_to_cluster(sector_idx);	  // 오프셋이 있는 클러스터의 인덱스
// 	// printf("[inode_read_at] cluster_idx: %d\n", cluster_idx);

// 	while (size > 0)
// 	{
// 		int sector_ofs = offset % DISK_SECTOR_SIZE;

// 		/* Bytes left in inode, bytes left in sector, lesser of the two. */
// 		off_t inode_left = inode_length(inode) - offset; //
// 		int sector_left = DISK_SECTOR_SIZE - sector_ofs; //
// 		int min_left = inode_left < sector_left ? inode_left : sector_left;

// 		/* Number of bytes to actually copy out of this sector. */
// 		int chunk_size = size < min_left ? size : min_left;
// 		if (chunk_size <= 0)
// 			break;

// 		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
// 		{
// 			/* Read full sector directly into caller's buffer. */
// 			disk_read(filesys_disk, sector_idx, buffer + bytes_read);
// 		}
// 		else
// 		{
// 			/* Read sector into bounce buffer, then partially copy
// 			 * into caller's buffer. */
// 			if (bounce == NULL)
// 			{
// 				bounce = malloc(DISK_SECTOR_SIZE);
// 				if (bounce == NULL)
// 					break;
// 			}
// 			disk_read(filesys_disk, sector_idx, bounce);
// 			memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
// 		}

// 		/* Advance. */
// 		size -= chunk_size;
// 		offset += chunk_size;
// 		bytes_read += chunk_size;
// 		if (fat_get(cluster_idx) != EOChain )
// 		{										// 현 클러스터가 체인의 끝이 아니라면
// 			cluster_idx = fat_get(cluster_idx); // 다음 클러스터로 이동
// 			sector_idx = cluster_to_sector(cluster_idx);
// 		}
// 		else
// 			break;
// 	}
// 	free(bounce);

// 	// printf("bytes_read: %d\n", bytes_read);

// 	return bytes_read;
// }

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	if (inode_length(inode)==0){
		return bytes_read;
	}

	while (size > 0)
	{
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector(inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		if ( (int) sector_idx == -1)
			return bytes_read;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < sector_left ? size : sector_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
		{
			/* Read full sector directly into caller's buffer. */
			disk_read(filesys_disk, sector_idx, buffer + bytes_read);
		}
		else
		{
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL)
			{
				bounce = malloc(DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read(filesys_disk, sector_idx, bounce);
			memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free(bounce);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
					 off_t offset)
{
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	disk_sector_t sector_idx = 0;
	uint8_t *bounce = NULL;
	off_t init_offset = offset;

	// printf("[inode_write_at]\n");

	if (inode->deny_write_cnt)
		return 0;

	// 파일 길이가 오프셋이 있는 위치보다 짧다면, 오프셋이 있는 위치까지 파일 길이를 늘린다
	extend_file_to_pos(inode, offset);

	while (size > 0)
	{
		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector(inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		// offset이 존재하는 섹터를 찾지 못했을 경우, 새로 클러스터를 할당받음
		if ( (int) sector_idx == -1)
			sector_idx = cluster_to_sector(fat_create_chain(inode->data.end));

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		// off_t inode_left = inode_length(inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < sector_left ? size : sector_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
		{
			/* Write full sector directly to disk. */
			disk_write(filesys_disk, sector_idx, buffer + bytes_written);
		}
		else
		{
			/* We need a bounce buffer. */
			if (bounce == NULL)
			{
				bounce = malloc(DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left)
				disk_read(filesys_disk, sector_idx, bounce);
			else
				memset(bounce, 0, DISK_SECTOR_SIZE);
			memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write(filesys_disk, sector_idx, bounce);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	free(bounce);

	if (inode->data.length < init_offset + bytes_written)
		inode->data.length = init_offset + bytes_written;
	
	if (sector_idx !=0)
		inode->data.end = sector_idx;

	return bytes_written;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
/* 버퍼에서 INODE로 오프셋부터 SIZE 바이트 쓰기.
 *  실제로 쓴 바이트 수를 반환합니다. 파일 끝에 도달하거나 오류가 발생할 경우 SIZE보다 작을 수 있습니다.
 * (일반적으로 파일 끝에 쓰기는 아이노드를 확장하지만, 성장은 아직 구현되지 않았다.) */
// off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
// 					 off_t offset)
// {
// 	const uint8_t *buffer = buffer_;
// 	off_t bytes_written = 0;
// 	uint8_t *bounce = NULL;

// 	/* if (offset+size (파일이 늘어나야 하는 길이) < length
// 		쓰려는 섹터 = offset+size
// 		if 쓰려는 섹터 > 파일이 점유하고 있는 섹터 수
// 			섹터를 할당해와야함 -> fat_create_chain
// 		디스크에 쓰기
// 	*/

// 	if (inode->deny_write_cnt)
// 		return 0;

// 	/*
// 	먼저 offset이 존재하는 섹터의 인덱스를 찾습니다
// 	(DIY한 함수 이용 - 만약 offset이 위치한 곳보다 파일 길이가 짧으면 섹터를 할당하여 파일을 연장해줌)
// 	연장이 된 상태!!!
// 	*/

// 	cluster_t cluster_idx = fat_byte_to_cluster(inode, offset); // 오프셋이 있는 섹터의
// 	// printf("[inod_write_at] size %d\n", size);
// 	disk_sector_t sector_idx = cluster_to_sector(cluster_idx);

// 	while (size > 0)
// 	{
// 		/* Sector to write, starting byte offset within sector. */
// 		// 쓸 섹터, 섹터 내 시작 바이트 오프셋
// 		int sector_ofs = offset % DISK_SECTOR_SIZE; // 한섹터 안에서의 오프셋

// 		/* Bytes left in inode, bytes left in sector, lesser of the two. */
// 		// 아이노드에 남은 바이트, 섹터에 남은 바이트, 둘 중 더 작은 바이트.
// 		off_t inode_left = ((int)(inode_length(inode) / DISK_SECTOR_SIZE) + 1) * DISK_SECTOR_SIZE - offset; // 아이노드 (찐렝스) 에 남은 바이트
// 		// printf("[inode_write_at] inode_length %d\n", inode_length(inode));
// 		// printf("[inode_write_at] inode_left %d\n", inode_left);
// 		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
// 		// printf("[inode_write_at] sector_left %d\n", sector_left); // 섹터에서 남은 바이트
// 		// int min_left = inode_left < sector_left ? inode_left : sector_left;
// 		// 이거는 우리가 파일 길이를 섹터의 배수로 할당했기 때문에 같을 수밖에 없을 것 같음 (inode_left = sector_left 이거나 inode_left > sector_left)

// 		/* Number of bytes to actually write into this sector. */
// 		int chunk_size = size < sector_left ? size : sector_left;

// 		if (inode_length(inode) == 0)
// 		{
// 			inode->data.length += chunk_size;
// 			// printf("[inode_write_at] length %d\n", inode->data.length);
// 		}


// 		// 더이상 종이가 없는데 써야하는 데이터는 있는 경우
// 		if (inode_left == 0)
// 		{
// 			// 종이 내놔
// 			cluster_idx = fat_create_chain(cluster_idx); // 새로 받아온 종이 번호
// 			sector_idx = cluster_to_sector(cluster_idx);
// 			inode->data.length += chunk_size; // 파일 길이 늘려주기
// 			// printf("[inode_write_at] data.length %d\n", inode->data.length);
			
// 		}

// 		if (chunk_size <= 0)
// 			break;

// 		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
// 		{
// 			/* Write full sector directly to disk. */
// 			// 전체 섹터를 디스크에 직접 기록
// 			// printf("chunk_size == DISK_SECTOR_SIZE\n");
// 			disk_write(filesys_disk, sector_idx, buffer + bytes_written);
// 		}
// 		else
// 		{
// 			/* We need a bounce buffer. */
// 			if (bounce == NULL)
// 			{
// 				bounce = malloc(DISK_SECTOR_SIZE);
// 				if (bounce == NULL)
// 					break;
// 			}

// 			/* If the sector contains data before or after the chunk
// 			   we're writing, then we need to read in the sector
// 			   first.  Otherwise we start with a sector of all zeros. */
// 			/* 만약 섹터가 우리가 쓰고 있는 청크의 앞이나 뒤에 데이터를 포함하고 있다면, 우리는 먼저 섹터에서 읽을 필요가 있다. 그렇지 않으면 모든 0의 섹터로 시작 */
// 			if (sector_ofs > 0 || chunk_size < sector_left)
// 				disk_read(filesys_disk, sector_idx, bounce);
// 			else
// 				memset(bounce, 0, DISK_SECTOR_SIZE);
// 			memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
// 			// printf("inode_write_at: %d\n", bounce);
// 			disk_write(filesys_disk, sector_idx, bounce);
// 		}

// 		/* Advance. */
// 		size -= chunk_size;
// 		offset += chunk_size;
// 		bytes_written += chunk_size;
// 		if (fat_get(cluster_idx) != -1)
// 		{										// 현 클러스터가 체인의 끝이 아니라면
// 			cluster_idx = fat_get(cluster_idx); // 다음 클러스터로 이동
// 			sector_idx = cluster_to_sector(cluster_idx);
// 		}
// 	}
// 	free(bounce);

// 	// printf("[inode_write_at] bytes_written %d\n", bytes_written);
// 	// disk_write(filesys_disk, inode->sector, inode->data);

// 	return bytes_written;
// }

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
	inode->deny_write_cnt++;
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
	ASSERT(inode->deny_write_cnt > 0);
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
	return inode->data.length;
}