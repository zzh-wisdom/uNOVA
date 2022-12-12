# FineFS

## 关于log

<!-- log大小适当增大，因为每个log的head需要存储version字段（和log大小字段）。 -->

<!-- 第一个cacheline：存储log头部 -->
最后一个cacheline：存储next指针，log大小和version字段；

由于原始的nova中，log和data的空间分配是混合在一起的，因此新分配的log并不知道是不是来自被回收的log page还是data page，也就无法确定version的正确性。因此为了让新分配的log page尽量复用之前回收的log page，我们在每个线程堆的基础上，再划分为log堆和data堆。默认配置为1:64(即log_entry size:page size = 64 : 4096 = 1:64)。在空间不足时，可以跨不同类别的堆进行空间分配，因此这样的堆划分机制不会降低空间利用率，而且还能大大提高log page的复用率。

由于堆中不总是满足连续若干page的空间分配要求，因此在某些极端情况下，分配出的log大小可能小于预期，为了处理这种特殊情况，我们需要在log中添加大小字段，以区分log的大小。（希望在实际测试中，这种情况几乎没有发生）。这也好理解，一般只会在写入大小不断变化的负载下，才可能出现。

gc的log应该从data heap中分配，防止对version的污染。后台gc生成的log中，tail的version设置为0，表示该log不用检查version，一直时有效的。

### log entry

log entry中包含ino和version等信息，因此entry可以乱序存放。

注意的是finefs中存在四种事务：创建inode（目录或者文件）、删除inode（目录或者文件）、文件写（需要的log entry大于1）、和rename（待实现）

正在执行事务的多个log之间需要保证顺序，它们被存放在active log中，一旦事务提交，log之间的顺序可以被打乱。因为事务的本质是让多个log entry同时存在和同时不存在，未提交时保持顺序是为了方便回滚。提交后，它们已经同时存在了，而不论他们的顺序如何。

rename操作，每个dentry log的version依旧取自它们所属的新inode。实际上，rename就是删除inode和创建inode两个操作的结合。只要保证它们的原子性即可。

> 先把所有的log entry操作和bitmap做适配，提交后，再改变gc方式

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

### 创建inode

1. 父母inode log中写一个dentry
2. journal记录旧的log tail + inode valid标志
3. 执行事务，更新tail和valid标记
4. 提交事务

### 删除inode

1. 父母pidir，写删除子inode的log entry，并记录自身的link变化。并将就entry标记为无效
2. 被删除的dir inode中写LINK_CHANGE log，将links置为0，表示删除
3. 进行事务
   1. 记录父母旧的log tail、孩子旧的log tail、 孩子inode记录有效位
   2. 更新父母log tail, 孩子inode的log tail，孩子有效位
   3. 提交事务，journal head  = tail
4. 最后上层调用evict_inode真正删除inode，并回收

> 涉及三个实体，父母、孩子和inode有效位。这个保证一致即可(包括父母inode的link，dentry删除，和孩子inode的link，如果link为0，则还有valid标志位和version)

更改后：

inode中受到父母影响的状态有：link，valid，和version。因此redo log中需要包含这些信息。

1. dir log中，写rmdir entry（redo）。记录父母删除的inode、更新后的iversion和link。表示孩子dentry删除。flush fennce
2. 执行事务实际删除 inode（即把inode置为无效，更新iversion） flush fence。将旧的entry标记为无效，方便回收
3. 提交事务写commit entry flush fence（这个不需要吧，就把上面的当做redo log算了，写入就表示事务完成）

恢复时，仅看到rmdir entry，说明事务未完成，将inode标记为有效，完成回滚。否则保留

问题是，崩溃恢复时，删除inode的数据的有效性收到删除log的影响。因此可以通过inode的版本号来直接丢弃

### rename 留给以后实现

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

#define LOG_ENTRY_SIZE 64
LOG_ZERO
LOG_HAS_TAIL
SETATTR_BY_CPY_NT

PMEM_MEM_WRITE

## TODO

后台GC：

1. 删除inode时，后台完成block的回收
2. 搞一个现成的内存分配器

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

