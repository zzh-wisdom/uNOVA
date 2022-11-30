# uNOVA

user space NOVA file system

## 设计



### 小写问题：

按照64B为粒度进行管理，写入时，小于64B的写，直接copy-on-write。大于64B的，类似nova，分配64B整数倍的连续空间，进行写入。

对于64B连续空间分配问题，有两种方案：slab分配器 / log-structure的方式。

前者不需要垃圾回收，更加稳定。后者需要垃圾回收，但能发挥顺序写的性能（但测试时发现，顺序和随机的ntstore带宽是差别不大的，具体可以继续测试）。因此先选择前者

### 多个log造成的随机写问题

改成每个cpu一个单独的log。
带来的问题是，不同文件的log混合在一起，恢复时间比较久，不能做到只恢复某个文件，为了缓解这个问题，正常关闭时，每个inode都有一个单独的log用来记录所有属于它的log entry的位置。由于我们只用记录log entry的偏移，因此数据量非常少。恢复时，根据log信息，就可以扫描特定位置的log entry进行恢复。

另外考虑到目录和文件的属性不同，io模式也不一样，将它们的操作混合在同一个log中会增加管理成本，参考f2fs的思想，我们将file和dir的操作分别记录到不同的log中。其中dentry log是比较大的，采用类似kv分离的思想，小文件名内嵌到log中，大文件名则额外分配slab/page进行存放，然后log entry中有个指针指向它。

同理，file和dir也分别用不同的slab分配器进行数据隔离。相比nova，我们的方案支持更长的文件名。最长支持4KB，但如果大于4KB其实也可以支持，需要在每个page后面添加一个指针。

因此对于一个具有32core的机器，共需要32x2个slab分配器和32x2个log。

### 对于索引

尽量做到只用一次NVM访问，内存需要保留更多的元信息。

## TODO

1. 测试不对齐写，参考这里的参数 <file:///C:/Users/Mrzho/Desktop/github/%E7%A1%95%E5%A3%AB%E6%AF%95%E8%AE%BE/practice-ssd/fio/html-doc/fio_man.html#i-o-type>
2. 解决多线程扩展性问题，考虑公平信号量。nt cpy时进行互斥
3. 看不同的io engine和io type，应该有其他负载

