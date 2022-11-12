# NOVA

/*
 * The first block contains super blocks and reserved inodes;
 * The second block contains pointers to journal pages.
 * The third block contains pointers to inode tables.
 */

#define	RESERVED_BLOCKS	3

第一个page是SB+预留的inode空间

```cpp
/* The root inode follows immediately after the redundant super block */
#define NOVA_ROOT_INO		(1)
#define NOVA_INODETABLE_INO	(2)	/* Temporaty inode table */
#define NOVA_BLOCKNODE_INO	(3)
#define NOVA_INODELIST_INO	(4)
#define NOVA_LITEJOURNAL_INO	(5)
#define NOVA_INODELIST1_INO	(6)

/*
 * ROOT_INO: Start from NOVA_SB_SIZE * 2
 */
static inline struct nova_inode *nova_get_basic_inode(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return (struct nova_inode *)(sbi->virt_addr + NOVA_SB_SIZE * 2 +
			 (inode_number - NOVA_ROOT_INO) * NOVA_INODE_SIZE);
}
```

第二个page，每个cacheline存储一个journal的指针。最多存储64个

```cpp
static inline
struct ptr_pair *nova_get_journal_pointers(struct super_block *sb, int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (cpu >= sbi->cpus)
		return NULL;

	return (struct ptr_pair *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K)	+ cpu * CACHELINE_SIZE);
}
```

第3个page保存每个cpu的inode table指针。

```cpp
static inline
struct inode_table *nova_get_inode_table(struct super_block *sb, int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (cpu >= sbi->cpus)
		return NULL;

	return (struct inode_table *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * 2) + cpu * CACHELINE_SIZE);
}
```

## 每个cpu变量

<https://blog.csdn.net/lq19880521/article/details/111606154>

访问每CPU变量的时候，一定要确保关闭进程抢占，否则一个进程被抢占后可能会更换CPU运行，这会导致每CPU变量的引用错误。

## 思考

1. 先测试看看空间分配是否是瓶颈，如果是可以考虑下列优化。

-  空间分配，可以改成多级class（普通或伙伴）。
- 为了实现低class合并到高class，可以用红黑树管理

本class空闲的block达到阈值时，才向上合并block，做一个 low high的水线条

> 感觉没必要伙伴算法，暂时没看到伙伴算法的优势，就简单的free class+红黑树

2. memset_nt替换成pmem2 memset

3. journal，加入版本号，每个cpu一个（cacheline存储）。通过版本号来识别一个entry的长度.(可以通过一个额外的stone，来标志前面的log已经提交，这样就通过空间的小部分浪费来避免同一个cacheline的重复flush) 通过两个journal来减少head的移动频率，更换journal时才改head
