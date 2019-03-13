/* radare - LGPL - Copyright 2014 - pancake */

#include <r_anal.h>

static int hook_flag_read(RAnalEsil *esil, const char *flag, ut64 *num) {
	sdb_array_add (esil->stats, "flg.read", flag, 0);
	return 0;
}

static int hook_command(RAnalEsil *esil, const char *op) {
	sdb_array_add (esil->stats, "ops.list", op, 0);
	return 0;
}

static void hook_mem_read(void *user, ut64 addr, ut8 *buf, int len) {
	Sdb *stats = (Sdb *)user;
	sdb_array_add_num (stats, "mem.read", addr, 0);
}

static void hook_mem_write(void *user, ut64 addr, const ut8 *buf, int len) {
	Sdb *stats = (Sdb *)user;
	sdb_array_add_num (stats, "mem.write", addr, 0);
}

static void hook_reg_read(void *user, const char *name) {
	Sdb *stats = (Sdb *)user;
	sdb_array_add (stats, "reg.read", name, 0);
}

static void hook_reg_write(void *user, const char *name, ut64 val) {
	Sdb *stats = (Sdb *)user;
	sdb_array_add (stats, "reg.write", name, 0);
}

#if 0	//this is not how to do this
static int hook_NOP_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	eprintf ("NOP WRITE AT 0x%08"PFMT64x"\n", addr);
	return 1; // override
}

R_API void r_anal_esil_mem_ro(RAnalEsil *esil, int mem_readonly) {
	if (mem_readonly) {
		esil->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		esil->cb.hook_mem_write = NULL;
	}
}
#endif

R_API void r_anal_esil_stats(RAnalEsil *esil, int enable) {
	if (enable) {
		if (esil->stats) {
			sdb_reset (esil->stats);
		} else {
			esil->stats = sdb_new0 ();
		}
		// reset sdb->stats
		// esil->cb.hook_reg_read = hook_reg_read;
		r_anal_esil_add_reg_read_obs(esil, hook_reg_read, esil->stats);
		// esil->cb.hook_mem_read = hook_mem_read;
		r_anal_esil_add_mem_read_obs(esil, hook_mem_read, esil->stats);
		// esil->cb.hook_mem_write = hook_mem_write;
		r_anal_esil_add_mem_write_obs(esil, hook_mem_write, esil->stats);
		// esil->cb.hook_reg_write = hook_reg_write;
		r_anal_esil_add_reg_write_obs(esil, hook_reg_write, esil->stats);
		esil->cb.hook_flag_read = hook_flag_read;
		esil->cb.hook_command = hook_command;
	} else {	//why not 2 functions instead of these blocks?
		esil->cb.hook_mem_write = NULL;
		esil->cb.hook_flag_read = NULL;
		esil->cb.hook_command = NULL;
		sdb_free (esil->stats);
		esil->stats = NULL;
	}
}
