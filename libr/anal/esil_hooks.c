#include <r_anal.h>
#include <r_util.h>

R_API RAnalEsilHooks *r_anal_esil_hooks_new () {
	RAnalEsilHooks *hooks = R_NEW0 (RAnalEsilHooks);
	r_return_val_if_fail (hooks, NULL);
	hooks->mem_read_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->mem_write_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->reg_read_observers = r_id_storage_new (0, UT32_MAX - 1);
	hooks->reg_write_observers = r_id_storage_new (0, UT32_MAX - 1);
	if (!(hooks->mem_read_observers && hooks->mem_write_observers &&
		hooks->reg_read_observers && hooks->reg_write_observers)) {
		r_id_storage_free (hooks->mem_read_observers);
		r_id_storage_free (hooks->mem_write_observers);
		r_id_storage_free (hooks->reg_read_observers);
		r_id_storage_free (hooks->reg_write_observers);
		free (hooks);
		return NULL;
	}
	return hooks;
}

static bool free_hook_cb (void *user, void *data, ut32 id) {
	free (data);
	return true;
}

R_API void r_anal_esil_hooks_free (RAnalEsilHooks *hooks) {
	if (hooks) {
		r_id_storage_foreach (hooks->mem_read_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->mem_write_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->reg_read_observers, free_hook_cb, NULL);
		r_id_storage_foreach (hooks->reg_write_observers, free_hook_cb, NULL);
	}
	free (hooks);
}

R_API bool r_anal_esil_set_mem_read_imp (RAnalEsil *esil, RAnalEsilImpHookMemReadCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_read_implementation) {
		esil->hooks->mem_read_implementation = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->mem_read_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->imr = imp;
	return true;
}

R_API void r_anal_esil_del_mem_read_imp (RAnalEsil *esil) {	//should this return the user?
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_read_implementation);
}

R_API bool r_anal_esil_set_mem_write_imp (RAnalEsil *esil, RAnalEsilImpHookMemWriteCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_write_implementation) {
		esil->hooks->mem_write_implementation = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->mem_write_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->imw = imp;
	return true;
}

R_API void r_anal_esil_del_mem_write_imp (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_write_implementation);
}

R_API bool r_anal_esil_set_reg_read_imp (RAnalEsil *esil, RAnalEsilImpHookRegReadCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_read_implementation) {
		esil->hooks->reg_read_implementation = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->reg_read_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->irr = imp;
	return true;
}

R_API void r_anal_esil_del_reg_read_imp (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_read_implementation);
}

R_API bool r_anal_esil_set_reg_write_imp (RAnalEsil *esil, RAnalEsilImpHookRegWriteCB imp, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_write_implementation) {
		esil->hooks->reg_write_implementation = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->reg_write_implementation;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->irw = imp;
	return true;
}

R_API void r_anal_esil_del_reg_write_imp (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_write_implementation);
}

R_API bool r_anal_esil_set_mem_read_mod (RAnalEsil *esil, RAnalEsilModHookMemReadCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_read_modifier) {
		esil->hooks->mem_read_modifier = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->mem_read_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mmr = mod;
	return true;
}

R_API void r_anal_esil_del_mem_read_mod (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_read_modifier);
}

R_API bool r_anal_esil_set_mem_write_mod (RAnalEsil *esil, RAnalEsilModHookMemWriteCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->mem_write_modifier) {
		esil->hooks->mem_write_modifier = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->mem_write_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mmw = mod;
	return true;
}

R_API void r_anal_esil_del_mem_write_mod (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->mem_write_modifier);
}

R_API bool r_anal_esil_set_reg_read_mod (RAnalEsil *esil, RAnalEsilModHookRegReadCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_read_modifier) {
		esil->hooks->reg_read_modifier = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->reg_read_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mrr = mod;
	return true;
}

R_API void r_anal_esil_del_reg_read_mod (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_read_modifier);
}

R_API bool r_anal_esil_set_reg_write_mod (RAnalEsil *esil, RAnalEsilModHookRegWriteCB mod, void *user) {
	r_return_val_if_fail (esil && esil->hooks, false);
	if (!esil->hooks->reg_write_modifier) {
		esil->hooks->reg_write_modifier = R_NEW (RAnalEsilHook);
	}
	RAnalEsilHook *hook = esil->hooks->reg_write_modifier;
	r_return_val_if_fail (hook, false);
	hook->user = user;
	hook->mrw = mod;
	return true;
}

R_API void r_anal_esil_del_reg_write_mod (RAnalEsil *esil) {
	r_return_if_fail (esil && esil->hooks);
	R_FREE (esil->hooks->reg_write_modifier);
}

static ut32 add_hook_to_idstorage (RIDStorage *st, void *fcn, void *user) {
	r_return_val_if_fail (st && fcn, UT32_MAX);
	RAnalEsilHook *hook = R_NEW (RAnalEsilHook);
	r_return_val_if_fail (hook, UT32_MAX);
	hook->fcn = fcn;
	hook->user = user;
	ut32 ret;
	if (!r_id_storage_add (st, hook, &ret)) {
		free (hook);
		return UT32_MAX;
	}
	return ret;
}

R_API ut32 r_anal_esil_add_mem_read_obs (RAnalEsil *esil, RAnalEsilObsHookMemReadCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_read_observers, obs, user);
}

R_API ut32 r_anal_esil_add_mem_write_obs (RAnalEsil *esil, RAnalEsilObsHookMemWriteCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_write_observers, obs, user);
}

R_API ut32 r_anal_esil_add_reg_read_obs (RAnalEsil *esil, RAnalEsilObsHookRegReadCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->reg_read_observers, obs, user);
}

R_API ut32 r_anal_esil_add_reg_write_obs (RAnalEsil *esil, RAnalEsilObsHookRegWriteCB obs, void *user) {
	r_return_val_if_fail (esil && esil->hooks, UT32_MAX);
	return add_hook_to_idstorage (esil->hooks->mem_read_observers, obs, user);
}

R_API void r_anal_esil_del_mem_read_obs (RAnalEsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_read_observers, id));
}

R_API void r_anal_esil_del_mem_write_obs (RAnalEsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_write_observers, id));
}

R_API void r_anal_esil_del_reg_read_obs (RAnalEsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->reg_read_observers, id));
}

R_API void r_anal_esil_del_reg_write_obs (RAnalEsil *esil, ut32 id) {
	r_return_if_fail (esil && esil->hooks);
	free (r_id_storage_take (esil->hooks->mem_write_observers, id));
}

R_API int r_esil_mem_read_at (RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks && esil->hooks->mem_read_implementation, -1);
	return esil->hooks->mem_read_implementation->imr (esil->hooks->mem_read_implementation->user, addr, buf, len);
}

typedef struct foreach_mem_user_t {
	ut64 addr;
	int len;
	ut8 *buf;
	ut8 *dup;
} MemUser;

static bool mem_read_obsv_wrap (void *user, void *data, ut32 id) {
	MemUser *mu = (MemUser *)user;
	RAnalEsilHook *hook = (RAnalEsilHook *)data;
	memcpy (mu->dup, mu->buf, mu->len);	//this assures the observer cannot modify the buffer
	hook->omr (hook->user, mu->addr, mu->dup, mu->buf);
	return true;
}

R_API int r_anal_esil_mem_read_at2 (RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks, -1);
	if (esil->hooks->mem_read_modifier) {
		if (!esil->hooks->mem_read_modifier->mmr (esil->hooks->mem_read_implementation->user, esil, addr, buf, len)) {
			return len;
		}
	}
	r_return_val_if_fail ((r_esil_mem_read_at (esil, addr, buf, len) == len), -1);
	MemUser mu = { addr, len, buf, R_NEWS (ut8, len)};
	r_return_val_if_fail (mu.dup, len);
	r_id_storage_foreach (esil->hooks->mem_read_observers, mem_read_obsv_wrap, &mu);	//iterate over observers here
	free (mu.dup);
	return len;
}

R_API r_esil_mem_write_at (RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks && esil->hooks->mem_write_implementation, -1);
	return esil->hooks->mem_write_implementation->imw (esil->hooks->mem_write_implementation->user, addr, buf, len);
}

static bool mem_write_obsv_wrap (void *user, void *data, ut32 id) {
	MemUser *mu = (MemUser *)user;
	RAnalEsilHook *hook = (RAnalEsilHook *)data;
	memcpy (mu->dup, mu->buf, mu->len);
	hook->omw (hook->user, mu->addr, mu->dup, mu->buf);
	return true;
}

R_API int r_anal_esil_mem_write_at2 (RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (buf && esil && esil->hooks, -1);
	// iterate first, befor applying modifiers, bc observers might need to read from addr first
	MemUser mu = { addr, len, buf, R_NEWS (ut8, len)};
	r_return_val_if_fail (mu.dup, len);
	r_id_storage_foreach (esil->hooks->mem_write_observers, mem_write_obsv_wrap, &mu);	//iterate over observers here
	free (mu.dup);
	if (esil->hooks->mem_write_modifier) {
		if (!esil->hooks->mem_write_modifier->mmw (esil->hooks->mem_write_implementation->user, esil, addr, buf, len)) {
			return len;
		}
	}
	return r_esil_mem_write_at (esil, addr, buf, len);
}

R_API ut64 r_esil_reg_read (RAnalEsil *esil, const char *regname) {
	r_return_val_if_fail (regname && esil && esil->hooks && esil->hooks->reg_read_implementation, 0LL);	//this kinda sucks
	return esil->hooks->reg_read_implementation->irr (esil->hooks->reg_read_implementation->user, regname);
}

static bool reg_read_obsv_wrap (void *user, void *data, ut32 id) {
	const char *regname = (const char *)user;
	RAnalEsilHook *hook = (RAnalEsilHook *)data;
	hook->orr (hook->user, regname);
	return true;
}

R_API ut64 r_anal_esil_reg_read2 (RAnalEsil *esil, const char *regname) {
	r_return_val_if_fail (regname && esil && esil->hooks, 0LL);
	if (esil->hooks->reg_read_modifier) {
		ut64 v;
		if (!esil->hooks->reg_read_modifier->mrr (esil->hooks->reg_read_modifier->user, esil, regname, &v)) {
			return v;
		}
	}
	r_id_storage_foreach (esil->hooks->reg_read_observers, reg_read_obsv_wrap, regname);	//iterate over observers here
	return r_esil_reg_read (esil, regname);
}

R_API bool r_esil_reg_write (RAnalEsil *esil, const char *regname, ut64 val) {
	r_return_val_if_fail (regname && esil && esil->hooks && esil->hooks->reg_write_implementation, false);
	return esil->hooks->reg_write_implementation->irw (esil->hooks->reg_write_implementation->user, regname, val);
}

typedef struct reg_user_t {
	const char *regname;
	const ut64 val;
} RegUser;

static bool reg_write_obsv_wrap (void *user, void *data, ut32 id) {
	RegUser *ru = (RegUser *)user;
	RAnalEsilHook *hook = (RAnalEsilHook *)data;
	hook->orw (hook->user, ru->regname, ru->val);
	return true;
}

R_API bool r_anal_esil_reg_write2 (RAnalEsil *esil, const char *regname, ut64 val) {
	r_return_val_if_fail (regname && esil && esil->hooks, false);
	RegUser ru = {regname, val};
	r_id_storage_foreach (esil->hooks->reg_write_observers, reg_write_obsv_wrap, &ru);
	if (esil->hooks->reg_write_modifier) {
		if (!esil->hooks->reg_write_modifier->mrw (esil->hooks->reg_write_modifier->user, esil, regname, val)) {
			return true;
		}
	}
	return r_esil_reg_write (esil, regname, val);
}
