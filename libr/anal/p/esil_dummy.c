/* radare2 - LGPL - Copyright 2021 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>


static void *r_esil_dummy_init (RAnalEsil *esil) {
	eprintf ("Dummy: Activated\n");
	return NULL;
}

static void r_esil_dummy_fini (RAnalEsil *esil, void *user) {
	eprintf ("Dummy: Deactivated\n");
}

RAnalEsilPlugin r_esil_plugin_dummy = {
	.name = "dummy",
	.desc = "dummy esil plugin",
	.license = "LGPL3",
	.init = r_esil_dummy_init,
	.fini = r_esil_dummy_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ESIL,
	.data = &r_esil_plugin_dummy,
	.version = R2_VERSION
};
#endif
