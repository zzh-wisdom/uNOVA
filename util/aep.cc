#include "util/aep.h"

#include <fcntl.h>
#include <stdlib.h>

#include "util/log.h"
#include "util/file.h"

struct pmem2_map* Pmem2MapFromFd(int fd) {
    struct pmem2_config *cfg;
	struct pmem2_map *map;
	struct pmem2_source *src;

	if (pmem2_config_new(&cfg)) {
        r_error("pmem2_config_new fail\n");
		return nullptr;
	}

	if (pmem2_source_from_fd(&src, fd)) {
		r_error("pmem2_source_from_fd fail\n");
		return nullptr;
	}

	if (pmem2_config_set_required_store_granularity(cfg,
			PMEM2_GRANULARITY_CACHE_LINE)) {
        r_error("pmem2_config_set_required_store_granularity fail\n");
		return nullptr;
	}

	if (pmem2_map_new(&map, cfg, src)) {
		r_error("pmem2_map_new fail\n");
		return nullptr;
	}

	pmem2_source_delete(&src);
	pmem2_config_delete(&cfg);

	return map;
}

struct pmem2_map* Pmem2Map(const std::string& dev_file) {
    int fd;
	struct pmem2_map *map;
	if ((fd = OpenSimple(dev_file)) < 0) {
        r_error("OpenSimple %s fail\n", dev_file.c_str());
		return nullptr;
	}
    map = Pmem2MapFromFd(fd);
	close(fd);
	return map;
}

struct pmem2_map* Pmem2MapAndTruncate(const std::string& file, uint64_t size) {
    int fd;
    struct pmem2_map *map;
    if ((fd = OpenAndAllocAtSize(file, size)) < 0) {
        r_error("OpenAndAllocAtSize %s fail\n", file.c_str());
		return nullptr;
	}
    map = Pmem2MapFromFd(fd);
	close(fd);
	return map;
}

void Pmem2UnMap(struct pmem2_map** map) {
    pmem2_map_delete(map);
}
