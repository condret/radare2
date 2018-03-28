#include <r_io.h>
#include <r_util.h>
#include <sdb.h>
#include <string.h>



//not public API, can make a few assumptions about pointers, they all should point to something reasonable
int read_single_block (RIODesc *desc, char *str_buf, ut64 blk_addr, ut64 addr, ut8 *buf, int len) {
	RIO *io = desc->io;
	RIOBlockCache *bcache0, *bcache1;
	ut8 *ptr;

	sprintf (str_buf, "off.%08x.%016"PFMT64x"", desc->block_cache_id, blk_addr);
	bcache0 = sdb_ptr_get (io->block_cache_storage, str_buf, NULL);
	if (bcache0) {
		ptr = bcache0->data + addr - blk_addr;
		memcpy (buf, ptr, len);
		if (bcache0->block_cache_index != desc->top_block) {
			sprintf (str_buf, "idx.%08x.%08x", desc->block_cache_id, bcache0->block_cache_index + 1);
			bcache1 = sdb_ptr_get (io->block_cache_storage, str_buf, NULL);
			bcache1->block_cache_index--;
			bcache0->block_cache_index++;
			sdb_ptr_set (io->block_cache_storage, str_buf, bcache1, NULL);
			sprintf (str_buf, "idx.%08x.%08x", desc->block_cache_id, bcache0->block_cache_index + 1);
			sdb_ptr_set (io->block_cache_storage, str_buf, bcache0, NULL);
		}
		return len;
	}
	sprintf (str_buf, "idx.%08x.%08x", desc->block_cache_id, desc->top_block - io->block_cache_num + 1);
	if ((bcache0 = sdb_ptr_get (io->block_cache_storage, str_buf, NULL))) {
		sdb_unset (io->block_cache_storage, str_buf, NULL);
		sprintf (str_buf, "off.%08x.%016"PFMT64x"", desc->block_cache_id, bcache0->addr);
		sdb_unset (io->block_cache_storage, str_buf, NULL);
	} else {
		//add checks here
		bcache0 = R_NEW(RIOBlockCache);
		bcache0->data = malloc(sizeof(ut8) * io->block_cache_size);
	}
	r_io_desc_seek (desc, blk_addr, R_IO_SEEK_SET);
	desc->plugin->read (io, desc, bcache0->data, io->block_cache_size);
	desc->top_id++;
	bcache0->block_cache_index = desc->top_id;
	bcache0->addr = blk_addr;
	sprintf (str_buf, "off.%08x.%016"PFMT64x"", desc->block_cache_id, blk_addr);
	sdb_ptr_set (io->block_cache_storage, str_buf, bcache0, NULL);
	sprintf (str_buf, "idx.%08x.%08x", desc->block_cache_id, desc->top_block);
	sdb_ptr_set (io->block_cache_storage, str_buf, bcache0, NULL);
	ptr = bcache0->data + addr - blk_addr;
	memcpy (buf, ptr, len);
	return len;
}

R_API int r_io_desc_block_cache_read_at (RIODesc *desc, ut64 addr, ut8 *buf, int len) {
	RIO *io;
	ut64 block_addr;
	ut64 blocks;	//number of potential blocks to read from
//4 char prefix, 8 char cache_id_token, 1 char '.', 16 char addr, 1 char null-byte
	char str_buf[30];	//rename this pls

	if (!desc || !desc->io || !desc->io->block_cache_size
	|| !desc->io->block_cache_num || !desc->plugin->use_block_cache) {
		return 0;
	}
	io = desc->io;
	if (!io->block_cache_storage && !(io->block_cache_storage = sdb_new0())) {
		eprintf ("allocation failed\n");
		r_sys_backtrace();
		return 0;
	}
//0 is invalid cache_id_token
	if (!desc->block_cache_id) {
		if (!io->block_cache_ids) {
//the id pool is used to keep the cache_id_tokens as low as possible
			io->block_cache_ids = r_id_pool_new (1, (ut32)-1);
		}
		if (!r_id_pool_grab_id (io->block_cache_ids, &desc->block_cache_id)) {
			eprintf("allocation failed\n");
			r_sys_backtrace();
			return 0;
		}
	}
//here is where the important stuff happens
//calculate addr of the first block to read from
	block_addr = addr - (addr % io->block_cache_size);
//calculate the number of potential blocks to read from
	blocks = len / io->block_cache_size;
	if ((len + addr - block_addr) >= io->block_cache_size) {
		blocks++;
	}
//it's simple if we only read from 1 block, so let's do this first
	if (blocks == 1) {
		return read_single_block (desc, str_buf, block_addr, addr, buf, len);
