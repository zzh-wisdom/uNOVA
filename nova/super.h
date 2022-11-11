#ifndef UNOVA_SUPER_H_
#define UNOVA_SUPER_H_

#include "nova/nova_com.h"

#include "util/lock.h"
#include "util/atomic.h"

/*
 * Structure of the NOVA super block in PMEM
 *
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * nova_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and nova_get_block() returns correct
 * pointers even for offset 0.
 */
struct nova_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below
	 */
	__le32		s_sum;			/* checksum of this sb */
	__le32		s_magic;		/* magic signature */
	__le32		s_padding32;
	__le32		s_blocksize;		/* blocksize in bytes */
	__le64		s_size;			/* total size of fs in bytes */
	char		s_volume_name[16];	/* volume name */

	/* all the dynamic fields should go here */
	__le64		s_epoch_id;		/* Epoch ID */

	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically
	 */
	__le32		s_mtime;		/* mount time */
	__le32		s_wtime;		/* write time */

	/* Metadata and data protections */
	u8		s_padding8;
	u8		s_metadata_csum;
	u8		s_data_csum;
	u8		s_data_parity;
} __attribute((__packed__)); // 取消优化对齐

#define NOVA_SB_SIZE 512       /* must be power of two */


#endif
