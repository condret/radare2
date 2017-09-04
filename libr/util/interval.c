#include <r_util.h>

R_API bool r_interval_init (RInterval *interv, RIntervalType type, ut64 from, ut64 size) {
	if (!size || !interv) {
		return false;
	}
	interv->type = type;
	switch (type) {
		case R_INTERVAL_OPEN_OPEN:
			interv->from = from - 1;
			interv->to = from + size;
			break;
		case R_INTERVAL_OPEN_CLOSED:
			interv->from = from - 1;
			interv->to = interv->from + size;
			break;
		case R_INTERVAL_CLOSED_OPEN:
			interv->from = from;
			interv->to = from + size;
			break;
		case R_INTERVAL_CLOSED_CLOSED:
			interv->from = from;
			interv->to = from + size - 1;
			break;
		default:
			return false;
	}
	return true;
}

R_API ut64 r_interval_first (RInterval interv, bool *err) {
	switch (interv.type) {
		case R_INTERVAL_OPEN_OPEN:
		case R_INTERVAL_OPEN_CLOSED:
			return interv.from + 1;
		case R_INTERVAL_CLOSED_OPEN:
		case R_INTERVAL_CLOSED_CLOSED:
			return interv.from;
	}
	if (err) {
		*err = true;
	}
	return 0LL;
}

R_API ut64 r_interval_last (RInterval interv, bool *err) {
	switch (interv.type) {
		case R_INTERVAL_OPEN_OPEN:
		case R_INTERVAL_CLOSED_OPEN:
			return interv.to - 1;
		case R_INTERVAL_OPEN_CLOSED:
		case R_INTERVAL_CLOSED_CLOSED:
			return interv.to;
	}
	if (err) {
		*err = true;
	}
	return 0LL;
}

R_API ut64 r_interval_size (RInterval interv, bool *err) {
	ut64 from = r_interval_first (interv, err);
	ut64 to = r_interval_last (interv, err);
	if (err && *err) {
		return 0LL;
	}
	return to - from + 1;
}

R_API ut64 r_interval_to_end (RInterval interv, ut64 from, bool *err) {
	ut64 size = r_interval_size (interv, err);
	if (err && *err) {
		return 0LL;
	}
	if (size < (from - r_interval_first (interv, err) + 1)) {
		if (err) {
			*err = true;
		}
		return 0LL;
	}
	return r_interval_last (interv, err) - from + 1;
}
