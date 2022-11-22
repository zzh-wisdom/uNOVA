#include "nova/vfs_api.h"

#include "nova/nova_cfg.h"
#include "nova/super.h"

typedef int (*init_fs_func_t)(struct super_block*, const std::string&,
                       const std::string&, vfs_cfg*);
std::unordered_map<std::string, init_fs_func_t> fs_init_ops = {
    {"nova", init_nova_fs},
};

const std::string ROOT_PREFIX = "/tmp/";

// 注意需要以 /tmp/<fs-type>/ 开头
// 没有做任何的并发安全管理，用户自己确保在完成操作前不会讲sb释放
std::unordered_map<std::string, struct super_block*> vfs_root_2_sb;

static inline bool register_mounted_fs(const std::string& root, super_block* sb) {
    auto it = vfs_root_2_sb.find(root);
    if(it != vfs_root_2_sb.end()) return false;
    vfs_root_2_sb[root] = sb;
    return true;
}

static inline super_block* unregister_mounted_fs(const std::string& root) {
    auto it = vfs_root_2_sb.find(root);
    if(it == vfs_root_2_sb.end()) return nullptr;
    super_block* sb = it->second;
    vfs_root_2_sb.erase(it);
    return sb;
}

static inline super_block* get_mounted_fs(const std::string& root) {
    auto it = vfs_root_2_sb.find(root);
    if(it == vfs_root_2_sb.end()) return nullptr;
    return it->second;
}

static inline bool fs_root_valid(const std::string root_path) {
    int prefix_len = ROOT_PREFIX.length();
    if(root_path.size() < prefix_len+1) return false;
    if(strncmp(root_path.c_str(), ROOT_PREFIX.c_str(), prefix_len) != 0) return false;
    int pos = root_path.find('/', prefix_len);
    if(pos != std::string::npos) return false;
    return true;
}

void vfs_cfg_print(struct vfs_cfg *cfg) {
    r_info("numa_socket=%d", cfg->numa_socket);
    r_info("cpu_num=%d", cfg->cpu_num);
    std::string cpu_ids_str = std::to_string(cfg->cpu_ids[0]);
    for (int i = 1; i < cfg->cpu_num; ++i) {
        cpu_ids_str += ",";
        cpu_ids_str += std::to_string(cfg->cpu_ids[i]);
    }
    r_info("cpu_ids=%s", cpu_ids_str.c_str());
    r_info("bg_thread_cpu_id=%d", cfg->bg_thread_cpu_id);
    r_info("measure_timing=%d", cfg->measure_timing);
    r_info("start_fd=%d", cfg->start_fd);
    r_info("format=%d", cfg->format);
}

static force_inline std::string path_find_last_compo(const std::string& path) {
	assert(path.size() > 1);
	int end = path.size();
	if(path[end-1] == '/') --end;
	int i = end - 1;
	for( ; i >= 0; --i) {
		if(path[i] == '/') {
			++i;
			break;
		}
	}
	assert(i < end);
	return path.substr(i, end-i);
}

int fs_mount(struct super_block **sb, const std::string &dev_name, const std::string &dir_name,
            vfs_cfg *cfg) {
    int ret = 0;
    bool ret_bool;
    if(fs_root_valid(dir_name) == false) return -1;
    std::string last_part = path_find_last_compo(dir_name);
    auto it = fs_init_ops.find(last_part);
    if(it == fs_init_ops.end()) {
        r_error("file type %s not found!", last_part.c_str());
        return -1;
    }
    r_info("%s: dev_name=%s, dir_name=%s, cfg:", __func__, dev_name.c_str(), dir_name.c_str());
    vfs_cfg_print(cfg);

    // 抽象层初始化
    vfs_init();

    // 创建pmem2 map
    struct pmem2_map *pmap = Pmem2Map(dev_name);
    if (!pmap) return -1;

    // 创建sb
    struct super_block *s;
    s = alloc_super(dev_name, pmap, dir_name);
    if (!s) {
        r_error("%s fail.\n", "alloc_super");
        goto out1;
    }

    ret = ((it->second))(s, dev_name, dir_name, cfg);
    if(ret) {
        r_error("init specify fs fail.");
        goto out2;
    }

    ret_bool = register_mounted_fs(dir_name, s);
    log_assert(ret_bool);
    *sb = s;
    return 0;
out2:
    destroy_super(s);
out1:
    Pmem2UnMap(&pmap);
    return -1;
}

int fs_unmount(struct super_block **sb) {
    struct super_block *s = *sb;
    super_block* tmp = unregister_mounted_fs(s->root_path);
    log_assert(tmp == s);
    rd_info("fs_unmount: %s\n", s->root_path.c_str());
    s->s_op->put_super(s);
    pmem2_map *pmap = s->pmap;
    destroy_super(s);
    Pmem2UnMap(&s->pmap);
    vfs_destroy();
    *sb = nullptr;
    return 0;
}

// -1 表示没找到
static inline int find_next_slash(const char* pathname, int pos) {
    for(int i = pos; pathname[i] != '\0'; ++i) {
        if(pathname[i] == '/') return i;
    }
    return -1;
}

// slash
// 出去root path后剩余部分的起始下标，root path固定只有两个斜杠部分
// 返回-1，表示处理错误，路径不合法
static inline int pathname_deal_root_prefix(const char* pathname) {
    int len = strlen(pathname);
    if(len <= ROOT_PREFIX.size()) return -1;
    int next_pos = find_next_slash(pathname, ROOT_PREFIX.size());
    if(next_pos <= ROOT_PREFIX.size()) return -1;
    return next_pos + 1;
}

/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash(salt)		(unsigned long)(salt)
#define hashlen_hash(hashlen) ((u32)(hashlen))
#define hashlen_len(hashlen)  ((u32)((hashlen) >> 32))
#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

#define GOLDEN_RATIO_32 0x61C88647
static inline u32 __hash_32_generic(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

static inline u32 hash_32_generic(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32_generic(val) >> (32 - bits);
}
/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits).  This also has the property (wanted by the dcache)
 * that the msbits make a good hash table index.
 */
static inline unsigned int end_name_hash(unsigned long hash)
{
	return hash_32_generic(hash, 32);
}

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline u64 hash_name(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	return hashlen_create(end_name_hash(hash), len);
}

// 返回的dentry已经引用
static dentry* get_parent_entry(dentry* parent, const char* name, qstr *last) {
    dentry_ref(parent);
    for(;;) {
        u64 hash_len = hash_name(parent, name);
        u32 hash = hashlen_hash(hash_len);
        u32 len = hashlen_len(hash_len);
        if(len == 0) { // name不合法
            goto err;
        }
        qstr tmp = {
            .hash = hash,
            .len = len,
            .name = name,
        };
        if(*(name+len) == '\0') {
            *last = tmp;
            return parent;
        }
        // go down child
        dentry* child = get_dentry_by_hash(parent, tmp, false);
        if(child == nullptr) {
            r_error("dir %*s not exist.", len, name);
            goto err;
        }
        dentry_unref(parent);
        parent = child;
        name += len;
    }

err:
    dentry_unref(parent);
    return nullptr;
}

// pathname不能以 / 结尾
int vfs_mkdir(const char* pathname, umode_t mode) {
    int name_start = pathname_deal_root_prefix(pathname);
    if(name_start < 0) return -1;
    std::string root_path(pathname, name_start-1);
    super_block* sb = get_mounted_fs(root_path);
    log_assert(sb);
    dentry* root = dentry_get_root(sb);
    dlog_assert(root);
    qstr last;
    dentry* parent = get_parent_entry(root, pathname+name_start, &last);
    dentry_unref(root);
    if(parent == nullptr) {
        return -1;
    }
    int ret = 0;
    struct inode *dir = parent->d_inode;
    struct dentry* new_d = get_dentry_by_hash(parent, last, true);
    log_assert(new_d && new_d->d_inode == nullptr);
    rd_info("fs mkdir: parent %s, child %s", parent->d_name.name, last.name);
    if(dir->i_op->mkdir(dir, new_d, mode)) {
        r_error("%s %s fail.", __func__, pathname);
        ret = -1;
    }

    dentry_unref(parent);
    dentry_unref(new_d);
    return ret;
}