# FineFS

## 关于log

<!-- log大小适当增大，因为每个log的head需要存储version字段（和log大小字段）。 -->

<!-- 第一个cacheline：存储log头部 -->
最后一个cacheline：存储next指针，log大小和version字段；

由于原始的nova中，log和data的空间分配是混合在一起的，因此新分配的log并不知道是不是来自被回收的log page还是data page，也就无法确定version的正确性。因此为了让新分配的log page尽量复用之前回收的log page，我们在每个线程堆的基础上，再划分为log堆和data堆。默认配置为1:64(即log_entry size:page size = 64 : 4096 = 1:64)。在空间不足时，可以跨不同类别的堆进行空间分配，因此这样的堆划分机制不会降低空间利用率，而且还能大大提高log page的复用率。

由于堆中不总是满足连续若干page的空间分配要求，因此在某些极端情况下，分配出的log大小可能小于预期，为了处理这种特殊情况，我们需要在log中添加大小字段，以区分log的大小。（希望在实际测试中，这种情况几乎没有发生）。这也好理解，一般只会在写入大小不断变化的负载下，才可能出现。

log page从data heap中申请时，需要手动清零。同理被用于data的page 释放到 log heap时也需要清零。

## 注意

目前：

1. log先实现为固定大小。
2. journal为4KB

## 一些宏

#define LOG_ENTRY_SIZE 64
LOG_ZERO
LOG_HAS_TAIL
SETATTR_BY_CPY_NT

PMEM_MEM_WRITE