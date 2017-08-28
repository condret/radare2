#include <r_io.h>
#include <r_util.h>
#include <r_rbtree.h>

RIOMap *_map_dup (RIOMap *dupme) {
	RIOMap *dup = R_NEW (RIOMAP);
	if (!dup) {
		return NULL;
	}
	memcpy (dup, dupme, sizeof(RIOMap));
	return dup;
}

static ut32 get_msb(ut32 v) {
	int i;
	for (i = 31; i > (-1); i--) {
		if (v & (0x1U << i)) {
			return (v & (0x1U << i));
		}
	}
	return 0;
}

static int _cmpnhacknslash_insert (RQueue *todo, RIOMap *in, RIOMap *incoming) {
	RIOMap *dup;
	//cmp
	//       ######
	//####
	//below the existing map
	if (incoming->to < in->from) {
		return -1;
	}
	//#######
	//          ########
	//above the existing map
	if (incoming->from > in->to) {
		return 1;
	}
	//hack
	//half overlap from below
	//       #######
	//#########
	if ((incoming->from < in->from) && (incoming->to <= in->to)) {
		incoming->to = in->from - 1;
	}
	//half overlap from above
	//#########
	//      ########
	if ((incoming->to > in->from) && (incoming->from <= in->to)) {
		incoming->delta += in->to - incoming->from + 1;
		incoming->from += in->to + 1;
	}
	//total overlap
	//    ####################
	//      ###########
	if ((incoming->from >= in->from) && (incoming->to <= in->to)) {
		free (incoming);
		return 0;
	} else if (!(dup = _map_dup (incoming))) {
	//when the dup fails, try to enqueue it and try again
	//after inserting and hopefully freeing some memory
	//and hope that enqueue works
		r_queue_enqueue (todo, income);
		return 0;
	}
	//slash
	//bigger then the existing map in both boundaries
	//       #############
	//   ######################
	dup->from = in->to + 1;
	dup->delta += dup->from - incoming->from;
	r_queue_enqueue (todo, dup);
	incoming->to = in->from - 1;
	return -1;
}

static int _cmpfind (void *user, RIOMap *map, ut64 *off) {
	if (*off < map->from) {
		return -1;
	}
	if (*off > map->to) {
		return 1;
	}
	return 0;
}

R_API *RIOShadow r_io_shadow_new () {
	RIOShadow *shadow = R_NEW0 (RIOShadow);
	if (!shadow || !(shadow->seek = R_NEW0 (RBTreeIter))) {
		return NULL;
	}
	shadow->sh_maps = r_rbtree_new (free, (RBTreeComparator)_cmpnhacknslash_insert);
}

R_API void r_io_shadow_init (RIO *io) {
	if (!io) {
		return;
	}
	io->shadows = r_io_shadow_new ();
}

R_API bool r_io_shadow_build (RIO *io) {
	RQueue *todo;
	SdbListIter *iter;
	RIOMap *map, *pam;
	if (!io || !io->maps || !io->shadows) {
		return false;
	}
	if (io->maps->length) {
		return true;
	}
	if (!(todo = r_queue_new (get_msb (io->maps->length + 1)))) {
		return false;
	}
	io->shadows->cmp = (RBTreeComparator)_cmpnhacknslash_insert;
	ls_foreach_prev (io->maps, iter, map) {
		if (!(pam = _map_dup(map))) {
				r_queue_free (todo);
				return false;
		}
		r_rbtree_insert (shadows->sh_maps, pam, todo);
		while (!r_queue_is_empty (todo)) {
			pam = r_queue_dequeue (todo);
			r_rbtree_insert (shadows->sh_maps, pam, todo);
		}
	}
	r_queue_free (todo);
	return true;
}

R_API bool r_io_shadow_map_priorize (RIO *io, ut32 id) {
	RQueue *todo;
	RIOMap *map, *pam, *pma = NULL;
	RBTreeIter ator;
	if (!io || !io->shadows ||!(map = _map_dup (r_io_map_resolve (io, id))) ||
		!(todo = r_queue_new (get_msb (r_rbtree_size (io->shadows->sh_maps) + 1)))) {
		return false;
	}
	io->shadows->sh_maps->cmp = (RBTreeComparator)_cmpfind;
	ator = r_rbtree_upper_bound_forward (io->shadows->sh_maps, map->from, NULL);
	if (!ator.len) {
		ator = r_rbtree_lower_bound_forward (io->shadows->sh_maps, map->from, NULL);
	}
	r_rbtree_iter_while (ator, pam) {
		if ((map->from <= pam->from) (pam->to <= map->to)) {
			r_queue_enqueue (pam);
			continue;
		}
		if ((pam->from < map->from) && (map->from <= pam->to)) {
			if (map->to >= pam->to) {
				pam->to = map->from - 1;
			}
			continue;
		}
		if ((map->from <= pam->from) && (map->to < pam->to)) {
			if (pam->from <= pam->to) {
				pam->delta += map->to - pam->from + 1;
				pam->from = map->to + 1;
			}
			break;
		} else {
			pma = pam;
			break;
		}
	}
	while (!r_queue_is_empty (todo)) {
		pam = r_queue_dequeue (todo);
		r_rbtree_delete (io->shadows->sh_maps, &pam->to, NULL);
	}
	io->shadows->sh_maps->cmp = _cmpnhacknslash_insert;
	r_rbtree_insert (io->shadows->sh_maps, map, todo);
	if (pma) {
		r_rbtree_insert (io->shadows->sh_maps, pma, todo);
		while (!r_queue_is_empty(todo)) {
			pma = r_queue_dequeue (todo);
			r_rbtree_insert (io->shadows->sh_maps, pma, todo);
		}
	}
	r_queue_free (todo);
	return true;
}

//say no to ut64_max for errors
R_API ut64 r_io_shadow_seek (RIO *io, ut64 offset, int whence, bool *success) {
	RIOMap *map;
	if (!io || !io->shadows) {
		if (success) {
			*success = false;
		}
		return 0LL;
	}
	io->shadows->sh_maps->cmp = (RBTreeComparator)_cmpfind;
	if (success) {
		*success = true;
	}
	if (whence == R_IO_SEEK_CUR) {
		if (offset == 0LL) {	//this might be a bad assumption
			return io->off;
		}
		io->off += offset;
	}
	switch (whence) {
		case R_IO_SEEK_SET:
			io->off = offset;
		case R_IO_SEEK_CUR:
			io->shadows.seek = r_rbtree_lower_bound_forward (
					io->shadows->sh_maps, &io->off, NULL);
			break;
		case R_IO_SEEK_END:
			io->shadows.seek = r_rbtree_last (io->shadows->sh_maps);
			map = (RIOMap *)io->shadows.seek.path[io->shadows.seek.len-1]->data;
			io->off = map->to + offset;		//aaaah int overflow
			//we want that, bc the read does not need
			//to check if forwards or backwards
			io->shadows.seek = r_rbtree_upper_bound_forward
					(io->shadows->sh_maps, &map->to, NULL);
			break;
	}
	return io->off;
}
















