#include <r_types.h>
#include <r_io.h>
#include <sdb.h>

/* internal API, can make assumptions about pointers*/
#define	RIODBCE	RIODescBCacheElement
#define	RIODBC	RIODescBCache

static RIODBCE *_riodbce_new(int size) {
	RIODBCE *ret = R_NEW(RIODBCE);

	if(ret) {
		ret->data = R_NEWS0(size, ut8);
		if(!ret->data) {
			R_FREE(ret);
		}
	}
	return ret;
}

static void _riodbce_free(RIODBCE *bce) {
	if(bce) {
		free(bce->data);
	}
	free(bce);
}

// this assumes a sane idx
static void _riodbc_remove_idx(RIODBC *bcache, ut32 idx) {
	if(bcache->caches[idx]) {
		dict_del(bcache->bce, bcache->caches[idx]->bce_addr);
		_riodbce_free(bcache->caches[idx]);
		bcache->caches[idx] = NULL;
	}
}

static void _riodbc_remove_all(RIODesc *desc) {
	ut32 i;

	if(desc->bcache) {
		for(i = 0; i < desc->io->block_cache_num; i++) {
			_riodbc_remove_idx (desc->bcache, i);
		}
		desc->bcache->base_idx = 0;
	}
}

static bool desc_set_block_cache_size_cb(void *user, void *data, ut32 id) {
	RIODesc *desc = (RIODesc *)data;

	if(desc->plugin && desc->plugin->cacheable) {
		_riodbc_remove_all(desc);
	}
	return true;
}

R_API void r_io_set_block_cache_size(RIO *io, ut32 size) {
	if(io) {
		// anything below 8 seems not to be a reasonable size
		if((size < 9) || (io->block_cache_size == size)) {
			return;
		}
		if(io->files) {
			r_id_storage_foreach(io->files, desc_set_block_cache_size_cb, NULL);
		}
		io->block_cache_size = size;
	}
}

//static bool desc_set_block_cache_num_cb(void *user, void *data, id) {

R_API void r_io_set_block_cache_num(RIO *io, ut32 num) {
	if(io) {
		if((num < 5) || (io->block_cache_num == num)) {
			return;
		}
		if(io->files) {
			r_id_storage_foreach(io->files, desc_set_block_cache_num_cb, NULL);
		}
		io->block_cache_num = num;
	}
}

//make these less bloating
static ut32 _dec_ring_idx(ut32 r_idx, ut32 bc_mod) {
	return (r_idx + (bc_mod - 1)) % bc_mod;
}

static ut32 _inc_ring_idx(ut32 r_idx, ut32 bc_mod) {
	return (r_idx + 1) % bc_idx;
}

/* sacrifices least used block, and assumes the new block will be most used one*/
static RIODBCE *_allocate_or_sacrifice_for_block_at(RIODesc *desc, ut64 addr) {
	ut32 bc_mod = desc->io->block_cache_num;
	RIODBCE *ret;

	desc->bcache->base_idx = _dec_ring_idx(desc->bcache->base_idx, bc_mod);
	ret = desc->bcache->caches[desc->bcache->base_idx];
	//check if this block is already in use
	if (!ret) {
		ret = _riodbce_new (desc->io->block_cache_size);
		if (!ret) {
			//when allocation fails
			desc->bcache->base_idx = _inc_ring_idx(desc->bcache->base_idx, bc_mod);
			goto beach;	//because of reasons
		}
		desc->bcache->caches[desc->bcache->base_idx] = ret;
		ret->real_idx = desc->bcache->base_idx;
	} else {
		dict_del(desc->bcache->bce, ret->bce_addr);
	}
	ret->bce_addr = addr;
	dict_set(desc->bcache->bce, addr, ret, NULL);
beach:
	return ret;
}

static RIODBCE *_next_block(RIODesc *desc, RIODBCE *bce) {
	if (desc->bcache->base_idx == bce->real_idx) {
		return NULL;
	}
	return desc->bcache->caches[_dec_ring_idx(bce->real_idx,
			desc->io->block_cache_num)];
}

static void _xchg_blocks(RIODBC *bc, RIODBCE *bce0, RIODBCE *bce1) {
	ut32 t_idx = bce0->real_idx;
	bc->caches[t_idx] = bce1;
	bc->caches[bce1->real_idx] = bce0;
	bce0->real_idx = bce1->real_idx;
	bce1->real_idx = t_idx;
}

/* fills block with data from file at block_addr, assumes block_addr is in file */
static int _fill_block(RIODesc *desc, RIODBCE *bce) {
	int len = desc->io->block_cache_size;
	if (!desc->plugin || !desc->plugin->lseek || !desc->plugin->read) {
		return -1;
	}
//	if ()	//sanity checks here
	desc->plugin->lseek (desc->io, desc, bce->bce_addr, R_IO_SEEK_SET);
	return desc->plugin->read (desc->io, desc, bce->data, len);
}

/* gets usable block at addr (block-addr)*/
static RIODBCE *_get_block_at(RIODesc *desc, ut64 addr) {
	RIODBCE *ret, *bce;

	ret = (RIODBCE *)dict_get(desc->bcache->bce, addr);
	if(!ret) {
		ret = _allocate_or_sacrifice_for_block_at(desc, addr);
		if(ret) {
			_fill_block(desc, ret);
			//check return value here pls
		}
		goto beach;
	}
	bce = _next_block(desc, ret);
	if(bce) {
		_xchg_blocks(desc->bcache, ret, bce);
	}
beach:
	return ret;
}

static ut64 _get_block_addr(RIO *io, ut64 addr) {
	return addr - (addr % io->block_cache_size);
}

//returns the amount of readen bytes
static int _read_from_single_block (RIODesc *desc, ut64 addr, ut8 *buf, int len) {
	RIODBCE *bce;
	ut64 block_addr = _get_block_addr(desc->io, addr);

	bce = _get_block_at(desc, block_addr);
	if(!bce) {	//we should try to read from plugin in this case
		return 0;
	}
	if(io->block_cache_size < len) {
		len = io->block_cache_size;
	}
	len -= (block_addr - addr);
	memcpy (buf, bce->data, len);
	return len;
}

int _block_read(RIODesc *desc, ut64 addr, ut8 *buf, int len) {
	int clen, rlen = 0;

	while(len > 0) {
		clen = _read_from_single_block(desc, addr, buf, len);
		if(clen < 0) {
			return clen;
		}
		rlen += clen;
		buf += clen;
		addr += clen;
		len -= clen;
	}
	return rlen;
}
