# FineFS

## 关于log

<!-- log大小适当增大，因为每个log的head需要存储version字段（和log大小字段）。 -->

<!-- 第一个cacheline：存储log头部 -->
最后一个cacheline：存储next指针，log大小和version字段；

由于原始的nova中，log和data的空间分配是混合在一起的，因此新分配的log并不知道是不是来自被回收的log page还是data page，也就无法确定version的正确性。因此为了让新分配的log page尽量复用之前回收的log page，我们在每个线程堆的基础上，再划分为log堆和data堆。默认配置为1:64(即log_entry size:page size = 64 : 4096 = 1:64)。在空间不足时，可以跨不同类别的堆进行空间分配，因此这样的堆划分机制不会降低空间利用率，而且还能大大提高log page的复用率。

由于堆中不总是满足连续若干page的空间分配要求，因此在某些极端情况下，分配出的log大小可能小于预期，为了处理这种特殊情况，我们需要在log中添加大小字段，以区分log的大小。（希望在实际测试中，这种情况几乎没有发生）。这也好理解，一般只会在写入大小不断变化的负载下，才可能出现。

gc的log应该从data heap中分配，防止对version的污染。后台gc生成的log中，tail的version设置为0，表示该log不用检查version，一直时有效的。

为了简化写作，或许setattr_entry可以放在和文件同一个log

### log entry

log entry中包含ino和version等信息，因此entry可以乱序存放。

注意的是finefs中存在四种事务：创建inode（目录或者文件）、删除inode（目录或者文件）、文件写（需要的log entry大于1）、和rename（待实现）

正在执行事务的多个log之间需要保证顺序，它们被存放在active log中，一旦事务提交，log之间的顺序可以被打乱。因为事务的本质是让多个log entry同时存在和同时不存在，未提交时保持顺序是为了方便回滚。提交后，它们已经同时存在了，而不论他们的顺序如何。

rename操作，每个dentry log的version依旧取自它们所属的新inode。实际上，rename就是删除inode和创建inode两个操作的结合。只要保证它们的原子性即可。

> 先把所有的log entry操作和bitmap做适配，提交后，再改变gc方式

一共5种 entry，以及它们的写入地方

TODO: 优化小写和小读

- finefs_file_small_write_entry
  - finefs_dump_small_write_entry
- finefs_file_pages_write_entry
  - finefs_append_file_write_entry
- finefs_dentry
  - finefs_append_dir_inode_entry
  - finefs_append_root_init_entries
  - finefs_append_dir_init_entries
- finefs_setattr_logentry
  - finefs_append_link_change_entry
- finefs_link_change_entry
  - finefs_append_setattr_entry LINK_CHANGE，需要在内存中保存最新的索引，关闭时，flush entry

<!-- 有两类操作会影响inode的link个数：建立/删除硬链接、创建和删除inode（文件或者目录），它们分别用finefs_link_change_entry和finefs_dentry来记录操作。finefs_link_change_entry只有元数据变化的信息，因此我们可以在后台gc时立即应用，并将entry回收。然而如果此时发生崩溃，在恢复时我们无法知道inode中的link值和finefs_dentry中的link值那个时最新的，因此需要在inode中记录一个link_ts，记录当前inode应用的所有finefs_link_change_entry中的最大时间戳ts，所以时间戳比link_ts小的finefs_dentry，都将忽略其link值，大于或者等于才会应用。 行不通，如果setattr也用这个策略的话，元数据的版本信息会很乱，因此我们保留以前的做法，保存最后一个 finefs_link_change_entry 和 finefs_append_setattr_entry -->

对于删除文件/目录的dentry，我们和nova一样，不回收，避免旧的dentry复活。

**兄弟们，重大改动**，所有失效的entry对应bitmap所在的cacheline都需要加入到到set，删除inode后，需要flush set中的所有cacheline，以保证之前的entry全部失效，而不会出现复活的问题，从而影响后续ino的复用。

## 小写slab分配器

分成若干个page链表。不要伙伴算法了，简单的slab

1. 2048
2. 1024
3. 512
4. 256
5. 128
6. 64

每一个级别在内存中一个free page链表。 指数递增的slab大小可能会造成比较严重的空间浪费，但是小数据会在后面和平到page中，

- 头： 保存page的个数page_num，当前分配的page指针page_point
- 链表中的一个节点描述一个nvm page，包括空闲的slab个数，slab_num; 和一个bitmap u64

- 分配时：对cpu对应的slab分配器加锁，到对应级别的free page链表中分配，根据page_point，bitmap分别一个slab，更改bitmap和slab num。
   1. 如果free page链表为空，则从全局的page head中分配一个空闲页（可以搞成批量分配多个page）
   2. 如果page分配完成，从链表中删除，并释放对应的内存结构。更改page_point和page_num
- 释放时：根据page编号得到它所属的cpu，并对该cpu对应的slab分配器加锁。扫描对应的级别的page list。
  - 如果找到对应的page，则更改bitmap和slab_num.
  - 如果没找到，则插入一个新的page到尾部，更新page_num

## 文件索引上

TODO: 推荐使用跳表而不是radix tree。后者需要逐个block处理，比如插入和查找。效率比较低。跳表呢可以范围查找。(会影响文件写、读和gc的各个方面的性能)

### 减少nvm访问上

修改了文件的块索引，但目录索引没有改，因为vfs层已经将目录的查找隐藏了

## 事务流程

任何事务流程，都只需要一个fence，这得益于单个log的连续性。只有在log中连续看到的TX_BEGIN和TX_END。
我们才称一个事务已经完成。

恢复时：按顺序扫描log链表，直到最后一个version不合法的entry为止。我们只会检查log尾部，也就是最后一个事务是否提交成功。

对于没有提交成功的事务，即没有看到TX_END标志，我们会把最后一个包含TX_BEGIN标志以及之后的entry丢弃。

一个inode的生命周期开始于link=1的entry（对于目录而言是"."dentry，对于文件而言是link_change entry 且link=1），并结束于link=0的link_change entry。

### 创建目录

1. 父母inode log中写一个dentry
2. 新建目录的inode log中添加两条dentry，"." 和 ".."
3. 写journal，将新建的inode的valid设置为1

注意：由于我们会在正常关闭时，保存inode number的free list（状态），因此正常启动时可以很快构建inode free list用于提供分配服务。而崩溃时，通过扫描log得到那些inode有效，从而恢复inode free list。因此inode中的valid字段不是必须的。

TODO: 删除inode的valid字段（其实link字段就可以作为是否有效标志，但是这里没有并不会应用任何信息到inode，所有的元数据都以log的方式存放）

三条dentry当成一个事务。父母写的dentry是tx begin。然后写子目录的"."dentry，~~将子目录的inode的valid字段设置为1~~，fence，最后提交事务，写".."dentry tx end。

崩溃恢复时，将全部的inode设置为无效，扫描全部log，每看到一个提交的事务，根据dentry1，将对应的inode设置为有效。

恢复分两步：先多线程扫描目录log，恢复所有有效的inode。
再扫描文件log，恢复所有有效inode的数据。

与nova不同的是，inode的valid标志位在我们这不是保持一致状态的，崩溃恢复后需要恢复valid字段的一致状态。

### 创建文件

1. 父母inode log中写一个dentry
2. journal记录旧的log tail + inode valid标志
3. 执行事务，更新tail和valid标记
4. 提交事务

更改：

父母dentry+孩子link_change entry+flush+fence

### 删除inode（包括目录和）

1. 父母pidir，写删除子inode的log entry，并记录自身的link变化。并将就entry标记为无效
2. 被删除的dir inode中写LINK_CHANGE log，将links置为0，表示删除
3. 进行事务
   1. 记录父母旧的log tail、孩子旧的log tail、 孩子inode记录有效位
   2. 更新父母log tail, 孩子inode的log tail，孩子有效位
   3. 提交事务，journal head  = tail
4. 最后上层调用evict_inode真正删除inode，并回收

> 涉及三个实体，父母、孩子和inode有效位。这个保证一致即可(包括父母inode的link，dentry删除，和孩子inode的link，如果link为0，则还有valid标志位和version)

更改：

1. 父母dentry+孩子link_change entry
2. flush孩子之前无效entry的bitmap

### rename 留给以后实现

但也挺好实现的，就两个dentry。一个删除dentry+增加的dentry

### 导致log失效的操作有

1. inode删除 rmdir和unlink
2. write
3. 删除文件导致的block回收

<!-- setattr 不会失效-->

## 总则

### 注意

目前：

1. log先实现为固定大小。
2. journal为4KB

对于大数据写，可能需要写多个write log entry，此时为了保证原子性，对write entry进行修改，添加三种类似：

- write begin
- write middle
- write end

恢复时，只有检查到完整的一对 write begin 和 write end时写才算成功，否则丢弃。

由于cacheline的乱序，可能出现middle丢失，而begin和end已经持久化的情况，此时顺序扫描在第一次检测到middle的version无效时，就直接丢弃。因此该方法可以保证写的原子性。

### 遗留问题

1. ftruncate的log需要永远保持有效，避免旧的write log又重新生效。因此当操作多时，比较浪费时间。改进：计算ftruncate总次数，当达到阈值时，后台全部log扫描，回收无用的ftruncate的entry。(更简单的方法是，ftruncate单独一个log，当log长度超过阈值时，flush全部log的bitmap区域，最后把所有的ftruncate log回收。即可，因为对于log bitmap, finefs保证：如果log entry对应的bit为1则可能有效也可能无效，但如果log entry对应的bit为0，则肯定无效。这个留给后面的工作实现)
2. 目录的radix-tree依然指向nvm log，这个不是我们工作的重点
3. 带数据的文件删除，有待优化
4. 不考虑线程混合，可以看成每个cpu操作的空间和文件都是固定的（除了rename）。而且测试不会测混合操作的情况。如果需要完这个，注意（FIXME: THREASDD）
5. 不支持ftuncate将文件缩小
6. 文件名定长，最长大约是27。边长文件名留到以后的工作中实现
7. 目前log_heap和data_heap不能相互转化，减少工作量

所以每个cpu需要三个log（文件写、truncate、和目录操作（包括mkdir、 rmdir、create、unlink、rename等）

## 一些宏

LOG_ZERO
LOG_HAS_TAIL

PMEM_MEM_WRITE

## TODO

后台GC：

1. 删除inode时，后台完成block的回收（前台回收好了）
2. 搞一个现成的内存分配器
3. 系统总结，如何保证崩溃一致性的，找出几条不变式，再分元数据和数据两部分来分析。

一致性问题还得再考虑一下：

1. bitmap
2.

读写过程中需要维护的一些状态

// 需要维护的状态
// sih->log_valid_bytes;
// sih->log_pages;  // ok, fast gc需要完善
// sih->h_log_tail; // ok
// pi->log_head;    // ok
// pi->i_blocks;    // ok

支持的操作：

mkdir rmdir create unlink
read write truncate

写log的函数 （都会先调用finefs_get_append_head）

finefs_append_file_write_entry (write)
finefs_add_dentry (对于目录创建，子目录需要预先写两个entry)
finefs_remove_dentry finefs_append_link_change_entry （删除inode）
finefs_append_setattr_entry（ftruncate）

导致log失效的操作

inode删除导致的
finefs_evict_inode

- finefs_delete_file_tree
- finefs_delete_dir_tree
- 旧的dentry无效 finefs_remove_dir_radix_tree

写操作导致的

finefs_assign_write_entry

