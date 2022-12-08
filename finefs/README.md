# FineFS

## 关于log

<!-- log大小适当增大，因为每个log的head需要存储version字段（和log大小字段）。 -->

<!-- 第一个cacheline：存储log头部 -->
最后一个cacheline：存储next指针，log大小和version字段；

由于原始的nova中，log和data的空间分配是混合在一起的，因此新分配的log并不知道是不是来自被回收的log page还是data page，也就无法确定version的正确性。因此为了让新分配的log page尽量复用之前回收的log page，我们在每个线程堆的基础上，再划分为log堆和data堆。默认配置为1:64(即log_entry size:page size = 64 : 4096 = 1:64)。在空间不足时，可以跨不同类别的堆进行空间分配，因此这样的堆划分机制不会降低空间利用率，而且还能大大提高log page的复用率。

由于堆中不总是满足连续若干page的空间分配要求，因此在某些极端情况下，分配出的log大小可能小于预期，为了处理这种特殊情况，我们需要在log中添加大小字段，以区分log的大小。（希望在实际测试中，这种情况几乎没有发生）。这也好理解，一般只会在写入大小不断变化的负载下，才可能出现。

gc的log应该从data heap中分配，防止对version的污染。后台gc生成的log中，tail的version设置为0，表示该log不用检查version，一直时有效的。

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

### rmdir

1. 父母pidir，写删除子inode的log entry，并记录自身的link变化。并将就entry标记为无效
2. 被删除的dir inode中写LINK_CHANGE log，将links置为0，表示删除
3. 进行事务
   1. 记录父母旧的log tail、孩子旧的log tail、 孩子inode记录有效位
   2. 更新父母log tail, 孩子inode的log tail，孩子有效位
   3. 提交事务，journal head  = tail
4. 最后上层调用evict_inode真正删除inode，并回收

> 涉及三个实体，父母、孩子和inode有效位。其实父母由inode和dentry组成，这个保证一致即可

更改后：

1. dir log中，写rmdir entry。记录父母删除的inode、iversion和link。表示孩子dentry删除。flush fennce
2. 执行事务实际删除 inode（即把inode置为无效） flush fence。将旧的entry标记为无效，方便回收
3. 提交事务写commit entry flush fence

恢复时，仅看到rmdir entry，说明事务未完成，将inode标记为有效，完成回滚。否则保留

问题是，崩溃恢复时，删除inode的数据的有效性收到删除log的影响。因此可以通过inode的版本号来直接丢弃

### rename 留给以后实现

### 导致log失效的操作有

目录删除 rmdir
unlink
setattr
write

## 注意

目前：

1. log先实现为固定大小。
2. journal为4KB

对于大数据写，可能需要写多个write log entry，此时为了保证原子性，对write entry进行修改，添加三种类似：

- write begin
- write middle
- write end

恢复时，只有检查到完整的一对 write begin 和 write end时写才算成功，否则丢弃。

由于cacheline的乱序，可能出现middle丢失，而begin和end已经持久化的情况，此时顺序扫描在第一次检测到middle的version无效时，就直接丢弃。因此该方法可以保证写的原子性。

## 一些宏

#define LOG_ENTRY_SIZE 64
LOG_ZERO
LOG_HAS_TAIL
SETATTR_BY_CPY_NT

PMEM_MEM_WRITE