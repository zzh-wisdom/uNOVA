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

## inode 操作

相关的操作都定义在：<nova/namei.c>

```cpp
const struct inode_operations nova_dir_inode_operations = {
	.create		= nova_create,
	.lookup		= nova_lookup,
	.link		= nova_link,
	.unlink		= nova_unlink,
	.symlink	= nova_symlink,
	.mkdir		= nova_mkdir,
	.rmdir		= nova_rmdir,
	.mknod		= nova_mknod,
	.rename		= nova_rename,
	.setattr	= nova_notify_change,
	.get_acl	= NULL,
};
```

ino的分配：

```cpp
*ino = new_ino * sbi->cpus + cpuid;
```

每个cpu的inode map都从16开始分配new_ino，最终的ino为 `new_ino * sbi->cpus + cpuid`。

16 * 32 + 0。

## inode log

4KB page的链表

tail指向 4096-8，或者log最后写上一个结束flag时，表示当前log写结束。（可见nova 的log是依赖于log的清零的，后面验证看有没有清零，新分配的log page好像没有清零）

```cpp
struct nova_inode_page_tail {
	__le64	padding1;
	__le64	padding2;
	__le64	padding3;
	__le64	next_page;
} __attribute((__packed__));

#define	LAST_ENTRY	4064
#define	PAGE_TAIL(p)	(((p) & ~INVALID_MASK) + LAST_ENTRY)

/* Fit in PAGE_SIZE */
struct	nova_inode_log_page {
	char padding[LAST_ENTRY];
	struct nova_inode_page_tail page_tail;
} __attribute((__packed__));
```

> 为什么尾部指针是按照32B对齐


## 思考

1. 先测试看看空间分配是否是瓶颈，如果是可以考虑下列优化。

-  空间分配，可以改成多级class（普通或伙伴）。
- 为了实现低class合并到高class，可以用红黑树管理

本class空闲的block达到阈值时，才向上合并block，做一个 low high的水线条

> 感觉没必要伙伴算法，暂时没看到伙伴算法的优势，就简单的free class+红黑树

2. memset_nt替换成pmem2 memset

3. journal，加入版本号，每个cpu一个（cacheline存储）。通过版本号来识别一个entry的长度.(可以通过一个额外的stone，来标志前面的log已经提交，这样就通过空间的小部分浪费来避免同一个cacheline的重复flush) 通过两个journal来减少head的移动频率，更换journal时才改head

nova的一次简单事务：写entry+flush+fence + 写tail+flush+fence + （提交）写head+flush+fence
三个cacheline的写入flush，三次fence

改进：（去掉tail，去掉head的移动）：写entry（内容+barrier+标记)flush+fence+(提交)ntstore stone+fence
两个cache的写入（并且没有重复cacheline）+ 两次fence（看能不能用redo，这样，提交标记也不用写了）

4. 一些索引新可否搬迁到DRAM，提高查找的效率，比如查找struct inode。比如原始nova，在inode的查找过程中，需要访问NVM，特别是inode table 块的多次跳转，会引入大量的NVM随机读。

5. 对于log page。nova的log entry不超过32B（可以看成是32B对齐）。可以改成cacheline对齐。但through GC后可以进行压缩。压缩成32B对齐？还是严格压缩？待考究(**感觉没必要压缩，64B的cpy_nt有好几倍的带宽提升**)

5. dram中的radix tree好像是索引NVM中的log entry，索引还是会引入大量的NVM随机读

6. 将所有的log_entry进行64B对齐后，fast GC后可以用一个bitmap记录有效的log entry位置这样后台GC可以更快地找到有效entry的位置

6. 关于页索引

```cpp
struct file_data_entry {
    u32 start;
	u32 end;
	u64 ptr;
}
```

log........->........->..............

写到inode，
log弄很大，每个log都在内存中有一个对应的bitmap，标志每个cacheline log的有效性。
当log的数量超过上限/或者有效率低于阈值，进行log回收（将有效率最少的log进行数据搬迁。分配新log，将entry拷贝过去，同时还要修改内存inode和索引的对应信息。为了并发安全，gc时也需要上inode锁，以修改索引。）

崩溃时，全盘扫描
正常关闭时，停止GC，将每个inode对应的有效log entry记录在inode中（一个指针），恢复时便于重新构建。

> 重点问题，修改索引时，如果减少对前台的影响，得探索一下radix tree的并发机制

或者考虑跳表。对啊radix tree只是调整自己的索引，slot指向的内存是不会变得。那就简单对单个slot加个旋转锁。进行前台和后台gc的互斥。或者还得加个引用计数，防止访问已经释放的内存。

> 或许还得考虑skiplist，并发控制更好实现。
> 注意到，file的radix tree是按照block nr进行索引的，也就是说在释放旧数据时，需要逐个block释放（因为需要逐个删除radix tree的key），比较慢

可以测试nova的带宽和裸盘带宽的差距
测试没有sfence的带宽

## 其他

可以通过修改 struct nova_inode_info_header 来添加一些缓存字段

