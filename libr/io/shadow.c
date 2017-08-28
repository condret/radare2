#include <r_io.h>
#include <r_util.h>
#include <r_rbtree.h>

RIOMap *__map_dup (RIOMap *dupme) {
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
	} else if (!(dup = __map_dup (incoming))) {
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

int _cmp_find (void *user, RIOMap *map, ut64 off) {
	if (off < map->from) {
		return -1;
	}
	if (off > map->to) {
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
	if (!(todo = r_queue_new (get_msb (io->maps->length)))) {
		return false;
	}
	io->shadows->cmp = (RBTreeComparator)_cmpnhacknslash_insert;
	ls_foreach_prev (io->maps, iter, map) {
		if (!(pam = __map_dup(map))) {
				r_queue_free (todo);
				return false;
		}
		r_rbtree_insert (shadows->sh_maps, pam, todo);
		while (!r_queue_is_empty (todo)) {
			pam = r_queue_dequeue (todo);
			r_rbtree_insert (shadows->sh_maps, pam, todo);
		}
	}
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
	io->shadows->sh_maps->cmp = (RBTreeComparator)_cmp_find;
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
					io->shadows->sh_maps, io->off, NULL);
			break;
		case R_IO_SEEK_END:
			io->shadows.seek = r_rbtree_last (io->shadows->sh_maps);
			map = (RIOMap *)io->shadows.seek.path[io->shadows.seek.len-1]->data;
			io->off = map->to;
			//we want that, bc the read does not need
			//to check if forwards or backwards
			io->shadows.seek = r_rbtree_lower_bound_forward
					(io->shadows->sh_maps, io->off, NULL);
			break;
	}
	return io->off;
}


















