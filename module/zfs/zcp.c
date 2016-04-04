/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <sys/dsl_prop.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_dataset.h>
#include <sys/zcp.h>
#include <sys/zcp_iter.h>
#include <sys/zcp_prop.h>
#include <sys/zcp_global.h>

uint64_t zfs_lua_check_timeout_instruction_interval = 100;
uint64_t zfs_lua_max_timeout = SEC2NSEC(10);
uint64_t zfs_lua_max_memlimit = 1024 * 1024 * 100;

static int zcp_nvpair_value_to_lua(lua_State *, nvpair_t *, char *, int);

typedef struct zcp_alloc_arg {
	boolean_t	aa_must_succeed;
	int64_t		aa_alloc_remaining;
	int64_t		aa_alloc_limit;
} zcp_alloc_arg_t;

typedef struct zcp_eval_arg {
	lua_State	*ea_state;
	zcp_alloc_arg_t	*ea_allocargs;
	cred_t		*ea_cred;
	nvlist_t	*ea_outnvl;
	int		ea_result;
	uint64_t	ea_timeout;
} zcp_eval_arg_t;

/*ARGSUSED*/
static int
zcp_eval_check(void *arg, dmu_tx_t *tx)
{
	return (0);
}

/*
 * The outer-most error callback handler for use with lua_pcall(). On
 * error Lua will call this callback with a single argument that
 * represents the error value. In most cases this will be a string
 * containing an error message, but channel programs can use Lua's
 * error() function to return arbitrary objects as errors. This callback
 * returns (on the Lua stack) the original error object along with a traceback.
 */
static int
zcp_traceback(lua_State *state)
{
	const char *msg;

	VERIFY3U(1, ==, lua_gettop(state));
	msg = lua_tostring(state, 1);
	luaL_traceback(state, state, msg, 1);
	return (1);
}

int
zcp_argerror(lua_State *state, int narg, const char *msg, ...)
{
	va_list alist;

	va_start(alist, msg);
	const char *buf = lua_pushvfstring(state, msg, alist);
	va_end(alist);

	return (luaL_argerror(state, narg, buf));
}

#define	ZCP_NVLIST_MAX_DEPTH 20

/*
 * Convert a value from the given index into the lua stack to an nvpair, adding
 * it to an nvlist with the given key.
 *
 * Values are converted as follows:
 *
 *   string -> string
 *   number -> int64
 *   boolean -> boolean
 *   nil -> boolean (no value)
 *
 * Lua tables are converted to nvlists and then inserted. The table's keys
 * are converted to strings then used as keys in the nvlist to store each table
 * element.  Keys are converted as follows:
 *
 *   string -> no change
 *   number -> "%lld"
 *   boolean -> "true" | "false"
 *   nil -> error
 *
 * In the case of a key collision, an error is thrown.
 *
 * If an error is encountered, a nonzero error code is returned, and an error
 * string will be pushed onto the Lua stack.
 */
int
zcp_lua_to_nvlist_impl(lua_State *state, int index, nvlist_t *nvl,
    const char *key, int depth)
{
	/*
	 * Verify that we have enough remaining space in the lua stack to parse
	 * a key-value pair and push an error.
	 */
	if (!lua_checkstack(state, 3)) {
		(void) lua_pushstring(state, "Lua stack overflow");
		return (1);
	}

	index = lua_absindex(state, index);

	switch (lua_type(state, index)) {
	case LUA_TNIL:
		fnvlist_add_boolean(nvl, key);
		break;
	case LUA_TBOOLEAN:
		fnvlist_add_boolean_value(nvl, key,
		    lua_toboolean(state, index));
		break;
	case LUA_TNUMBER:
		fnvlist_add_int64(nvl, key, lua_tonumber(state, index));
		break;
	case LUA_TSTRING:
		fnvlist_add_string(nvl, key, lua_tostring(state, index));
		break;
	case LUA_TTABLE: {
		nvlist_t *mynvl = fnvlist_alloc();
		/*
		 * Push an empty stack slot where lua_next() will store each
		 * table key.
		 */
		lua_pushnil(state);
		while (lua_next(state, index) != 0) {
			/*
			 * The next key-value pair from the table at index is
			 * now on the stack, with the key at stack slot -2 and
			 * the value at slot -1.
			 */
			int err = 0;
			char buf[32];
			const char *mykey = NULL;

			switch (lua_type(state, -2)) {
			case LUA_TSTRING:
				mykey = lua_tostring(state, -2);
				break;
			case LUA_TBOOLEAN:
				mykey = (lua_toboolean(state, -2) == B_TRUE ?
				    "true" : "false");
				break;
			case LUA_TNUMBER:
				VERIFY3U(sizeof (buf), >,
				    snprintf(buf, sizeof (buf), "%lld",
				    (longlong_t)lua_tonumber(state, -2)));
				mykey = buf;
				break;
			default:
				fnvlist_free(mynvl);
				(void) lua_pushfstring(state, "Invalid key "
				    "type '%s' in table '%s'",
				    lua_typename(state, lua_type(state, -2)),
				    key);
				return (EINVAL);
			}
			/*
			 * It's possible for string keys to collide
			 * (e.g. the string "1" and the number 1), which should
			 * throw an error.
			 */
			if (nvlist_exists(mynvl, mykey)) {
				fnvlist_free(mynvl);
				(void) lua_pushfstring(state, "Collision of "
				    "key '%s' for table '%s'", mykey, key);
				return (EINVAL);
			}
			/*
			 * Recursively convert the table value and insert into
			 * the new nvlist with the parsed key.  To prevent
			 * stack overflow on circular or heavily nested tables,
			 * we track the current nvlist depth.
			 */
			if (depth >= ZCP_NVLIST_MAX_DEPTH) {
				fnvlist_free(mynvl);
				(void) lua_pushfstring(state, "Maximum table "
				    "depth (%d) exceeded for table '%s'",
				    ZCP_NVLIST_MAX_DEPTH, key);
				return (EINVAL);
			}
			err = zcp_lua_to_nvlist_impl(state, -1, mynvl, mykey,
			    depth + 1);
			if (err != 0) {
				fnvlist_free(mynvl);
				/*
				 * Error message has been pushed to the lua
				 * stack by the recursive call.
				 */
				return (err);
			}
			/*
			 * Pop the value pushed by lua_next().
			 */
			lua_pop(state, 1);
		}
		fnvlist_add_nvlist(nvl, key, mynvl);
		break;
	}
	default:
		(void) lua_pushfstring(state,
		    "Invalid value type '%s' for key '%s'",
		    lua_typename(state, lua_type(state, index)), key);
		return (EINVAL);
	}

	return (0);
}

/*
 * Convert a lua value to an nvpair, adding it to an nvlist with the given key.
 */
void
zcp_lua_to_nvlist(lua_State *state, int index, nvlist_t *nvl, const char *key)
{
	/*
	 * On error, zcp_lua_to_nvlist_impl pushes an error string onto the Lua
	 * stack before returning with a nonzero error code. If an error is
	 * returned, throw a fatal lua error with the given string.
	 */
	if (zcp_lua_to_nvlist_impl(state, index, nvl, key, 0) != 0)
		(void) lua_error(state);
}

int
zcp_lua_to_nvlist_helper(lua_State *state)
{
	nvlist_t *nv = (nvlist_t *)lua_touserdata(state, 2);
	const char *key = (const char *)lua_touserdata(state, 1);
	zcp_lua_to_nvlist(state, 3, nv, key);
	return (0);
}

void
zcp_convert_return_values(lua_State *state, nvlist_t *nvl,
    const char *key, zcp_eval_arg_t *evalargs)
{
	int err;
	lua_pushcfunction(state, zcp_lua_to_nvlist_helper);
	lua_pushlightuserdata(state, (char *)key);
	lua_pushlightuserdata(state, nvl);
	lua_pushvalue(state, 1);
	lua_remove(state, 1);
	err = lua_pcall(state, 3, 0, 0); /* zcp_lua_to_nvlist_helper */
	if (err != 0) {
		zcp_lua_to_nvlist(state, 1, nvl, ZCP_RET_ERROR);
		evalargs->ea_result = SET_ERROR(ECHRNG);
	}
}

/*
 * Push a Lua table representing nvl onto the stack.  If it can't be
 * converted, return EINVAL, fill in errbuf, and push nothing. errbuf may
 * be specified as NULL, in which case no error string will be output.
 *
 * Most nvlists are converted as simple key->value Lua tables, but we make
 * an exception for the case where all nvlist entries are BOOLEANs (a string
 * key without a value). In Lua, a table key pointing to a value of Nil
 * (no value) is equivalent to the key not existing, so a BOOLEAN nvlist
 * entry can't be directly converted to a Lua table entry. Nvlists of entirely
 * BOOLEAN entries are frequently used to pass around lists of datasets, so for
 * convenience we check for this case, and convert it to a simple Lua array of
 * strings.
 */
int
zcp_nvlist_to_lua(lua_State *state, nvlist_t *nvl,
    char *errbuf, int errbuf_len)
{
	nvpair_t *pair;
	lua_newtable(state);
	boolean_t has_values = B_FALSE;
	/*
	 * If the list doesn't have any values, just convert it to a string
	 * array.
	 */
	for (pair = nvlist_next_nvpair(nvl, NULL);
	    pair != NULL; pair = nvlist_next_nvpair(nvl, pair)) {
		if (nvpair_type(pair) != DATA_TYPE_BOOLEAN) {
			has_values = B_TRUE;
			break;
		}
	}
	if (!has_values) {
		int i = 1;
		for (pair = nvlist_next_nvpair(nvl, NULL);
		    pair != NULL; pair = nvlist_next_nvpair(nvl, pair)) {
			(void) lua_pushinteger(state, i);
			(void) lua_pushstring(state, nvpair_name(pair));
			(void) lua_settable(state, -3);
			i++;
		}
	} else {
		for (pair = nvlist_next_nvpair(nvl, NULL);
		    pair != NULL; pair = nvlist_next_nvpair(nvl, pair)) {
			int err = zcp_nvpair_value_to_lua(state, pair,
			    errbuf, errbuf_len);
			if (err != 0) {
				lua_pop(state, 1);
				return (err);
			}
			(void) lua_setfield(state, -2, nvpair_name(pair));
		}
	}
	return (0);
}

/*
 * Push a Lua object representing the value of "pair" onto the stack.
 *
 * Only understands boolean_value, string, int64, nvlist,
 * string_array, and int64_array type values.  For other
 * types, returns EINVAL, fills in errbuf, and pushes nothing.
 */
static int
zcp_nvpair_value_to_lua(lua_State *state, nvpair_t *pair,
    char *errbuf, int errbuf_len)
{
	int err = 0;

	switch (nvpair_type(pair)) {
	case DATA_TYPE_BOOLEAN_VALUE:
		(void) lua_pushboolean(state,
		    fnvpair_value_boolean_value(pair));
		break;
	case DATA_TYPE_STRING:
		(void) lua_pushstring(state, fnvpair_value_string(pair));
		break;
	case DATA_TYPE_INT64:
		(void) lua_pushinteger(state, fnvpair_value_int64(pair));
		break;
	case DATA_TYPE_NVLIST:
		err = zcp_nvlist_to_lua(state,
		    fnvpair_value_nvlist(pair), errbuf, errbuf_len);
		break;
	case DATA_TYPE_STRING_ARRAY: {
		char **strarr;
		uint_t nelem;
		(void) nvpair_value_string_array(pair, &strarr, &nelem);
		lua_newtable(state);
		for (int i = 0; i < nelem; i++) {
			(void) lua_pushinteger(state, i + 1);
			(void) lua_pushstring(state, strarr[i]);
			(void) lua_settable(state, -3);
		}
		break;
	}
	case DATA_TYPE_UINT64_ARRAY: {
		uint64_t *intarr;
		uint_t nelem;
		(void) nvpair_value_uint64_array(pair, &intarr, &nelem);
		lua_newtable(state);
		for (int i = 0; i < nelem; i++) {
			(void) lua_pushinteger(state, i + 1);
			(void) lua_pushinteger(state, intarr[i]);
			(void) lua_settable(state, -3);
		}
		break;
	}
	case DATA_TYPE_INT64_ARRAY: {
		int64_t *intarr;
		uint_t nelem;
		(void) nvpair_value_int64_array(pair, &intarr, &nelem);
		lua_newtable(state);
		for (int i = 0; i < nelem; i++) {
			(void) lua_pushinteger(state, i + 1);
			(void) lua_pushinteger(state, intarr[i]);
			(void) lua_settable(state, -3);
		}
		break;
	}
	default: {
		if (errbuf != NULL) {
			(void) snprintf(errbuf, errbuf_len,
			    "Unhandled nvpair type %d for key '%s'",
			    nvpair_type(pair), nvpair_name(pair));
		}
		return (EINVAL);
	}
	}
	return (err);
}

int
zcp_dataset_hold_error(lua_State *state, dsl_pool_t *dp, const char *dsname,
    int error)
{
	if (error == ENOENT) {
		(void) zcp_argerror(state, 1, "no such dataset '%s'", dsname);
		return (NULL); /* not reached; zcp_argerror will longjmp */
	} else if (error == EXDEV) {
		(void) zcp_argerror(state, 1,
		    "dataset '%s' is not in the target pool '%s'",
		    dsname, spa_name(dp->dp_spa));
		return (NULL); /* not reached; zcp_argerror will longjmp */
	} else if (error == EIO) {
		(void) luaL_error(state,
		    "I/O error while accessing dataset '%s'", dsname);
		return (NULL); /* not reached; luaL_error will longjmp */
	} else if (error != 0) {
		(void) luaL_error(state,
		    "unexpected error %d while accessing dataset '%s'",
		    error, dsname);
		return (NULL); /* not reached; luaL_error will longjmp */
	}
	return (NULL);
}

/*
 * Note: will longjmp (via lua_error()) on error.
 * Assumes that the dsname is argument #1 (for error reporting purposes).
 */
dsl_dataset_t *
zcp_dataset_hold(lua_State *state, dsl_pool_t *dp, const char *dsname,
    void *tag)
{
	dsl_dataset_t *ds;
	int error = dsl_dataset_hold(dp, dsname, tag, &ds);
	(void) zcp_dataset_hold_error(state, dp, dsname, error);
	return (ds);
}

static int zcp_debug(lua_State *);
static zcp_lib_info_t zcp_debug_info = {
	.name = "debug",
	.func = zcp_debug,
	.pargs = {
	    { .za_name = "debug string", .za_lua_type = LUA_TSTRING},
	    {NULL, NULL}
	},
	.kwargs = {
	    {NULL, NULL}
	}
};

static int
zcp_debug(lua_State *state)
{
	const char *dbgstring;
	zcp_run_info_t *ri = zcp_run_info(state);
	zcp_lib_info_t *libinfo = &zcp_debug_info;

	zcp_parse_args(state, libinfo->name, libinfo->pargs, libinfo->kwargs);

	dbgstring = lua_tostring(state, 1);

	zfs_dbgmsg("txg %lld ZCP: %s", ri->zri_tx->tx_txg, dbgstring);

	return (0);
}

static int zcp_exists(lua_State *);
static zcp_lib_info_t zcp_exists_info = {
	.name = "exists",
	.func = zcp_exists,
	.pargs = {
	    { .za_name = "dataset", .za_lua_type = LUA_TSTRING},
	    {NULL, NULL}
	},
	.kwargs = {
	    {NULL, NULL}
	}
};

static int
zcp_exists(lua_State *state)
{
	zcp_run_info_t *ri = zcp_run_info(state);
	dsl_pool_t *dp = ri->zri_pool;
	zcp_lib_info_t *libinfo = &zcp_exists_info;

	zcp_parse_args(state, libinfo->name, libinfo->pargs, libinfo->kwargs);

	const char *dsname = lua_tostring(state, 1);

	dsl_dataset_t *ds;
	int error = dsl_dataset_hold(dp, dsname, FTAG, &ds);
	if (error == 0) {
		dsl_dataset_rele(ds, FTAG);
		lua_pushboolean(state, B_TRUE);
	} else if (error == ENOENT) {
		lua_pushboolean(state, B_FALSE);
	} else if (error == EXDEV) {
		return (luaL_error(state, "dataset '%s' is not in the "
		    "target pool", dsname));
	} else if (error == EIO) {
		return (luaL_error(state, "I/O error opening dataset '%s'",
		    dsname));
	} else if (error != 0) {
		return (luaL_error(state, "unexpected error %d", error));
	}

	return (0);
}

/*
 * Allocate/realloc/free a buffer for the lua interpreter.
 *
 * When nsize is 0, behaves as free() and returns NULL.
 *
 * If ptr is NULL, behaves as malloc() and returns an allocated buffer of size
 * at least nsize.
 *
 * Otherwise, behaves as realloc(), changing the allocation from osize to nsize.
 * Shrinking the buffer size never fails.
 *
 * The original allocated buffer size is stored as a uint64 at the beginning of
 * the buffer to avoid actually reallocating when shrinking a buffer, since lua
 * requires that this operation never fail.
 */
static void *
zcp_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	zcp_alloc_arg_t *allocargs = ud;
	int flags = (allocargs->aa_must_succeed) ?
	    KM_SLEEP : (KM_NOSLEEP | KM_NORMALPRI);

	if (nsize == 0) {
		if (ptr != NULL) {
			int64_t *allocbuf = (int64_t *)ptr - 1;
			int64_t allocsize = *allocbuf;
			ASSERT3S(allocsize, >, 0);
			ASSERT3S(allocsize, <=, SPA_MAXBLOCKSIZE);
			ASSERT3S(allocargs->aa_alloc_remaining + allocsize, <=,
			    allocargs->aa_alloc_limit);
			allocargs->aa_alloc_remaining += allocsize;
			kmem_free(allocbuf, allocsize);
		}
		return (NULL);
	} else if (ptr == NULL) {
		int64_t *allocbuf;
		int64_t allocsize = nsize + sizeof (int64_t);

		if (!allocargs->aa_must_succeed &&
		    (allocsize <= 0 ||
		    allocsize > allocargs->aa_alloc_remaining)) {
			return (NULL);
		}

		if (allocsize > SPA_MAXBLOCKSIZE)
			return (NULL);

		allocbuf = kmem_alloc(allocsize, flags);
		if (allocbuf == NULL) {
			return (NULL);
		}
		allocargs->aa_alloc_remaining -= allocsize;

		*allocbuf = allocsize;
		return (allocbuf + 1);
	} else if (nsize <= osize) {
		/*
		 * If shrinking the buffer, lua requires that the reallocation
		 * never fail.
		 */
		return (ptr);
	} else {
		ASSERT3U(nsize, >, osize);

		uint64_t *luabuf = zcp_lua_alloc(ud, NULL, 0, nsize);
		if (luabuf == NULL) {
			return (NULL);
		}
		(void) memcpy(luabuf, ptr, osize);
		VERIFY3P(zcp_lua_alloc(ud, ptr, osize, 0), ==, NULL);
		return (luabuf);
	}
}

/* ARGSUSED */
static void
zcp_lua_counthook(lua_State *state, lua_Debug *ar)
{
	/*
	 * If we're called, check how long channel program's been running for,
	 * and compare against the end time (stored in runtime info).
	 */
	lua_getfield(state, LUA_REGISTRYINDEX, ZCP_RUN_INFO_KEY);
	zcp_run_info_t *ri = lua_touserdata(state, -1);
	if ((ri->zri_endtime != 0) && (gethrtime() > ri->zri_endtime)) {
		ri->zri_timed_out = B_TRUE;
		(void) lua_pushstring(state,
		    "Channel program timed out.");
		(void) lua_error(state);
	}
}

static int
zcp_panic_cb(lua_State *state)
{
	panic("unprotected error in call to Lua API (%s)\n",
	    lua_tostring(state, -1));
	return (0);
}

static void
zcp_eval_sync(void *arg, dmu_tx_t *tx)
{
	int err;
	zcp_run_info_t ri;
	zcp_eval_arg_t *evalargs = arg;
	lua_State *state = evalargs->ea_state;

	/*
	 * Open context should have setup the stack to contain:
	 * 1: Error handler callback
	 * 2: Script to run (converted to a Lua function)
	 * 3: nvlist input to function (converted to Lua table or nil)
	 */
	VERIFY3U(3, ==, lua_gettop(state));

	/*
	 * Store the zcp_run_info_t struct for this run in the Lua registry.
	 * Registry entries are not directly accessible by the Lua scripts but
	 * can be accessed by our callbacks.
	 */
	ri.zri_space_used = 0;
	ri.zri_pool = dmu_tx_pool(tx);
	ri.zri_cred = evalargs->ea_cred;
	ri.zri_tx = tx;
	ri.zri_timed_out = B_FALSE;
	/*
	 * A timeout or end time value of 0 indicates no time limit.
	 */
	if (evalargs->ea_timeout == 0) {
		ri.zri_endtime = 0;
	} else {
		ri.zri_endtime = gethrtime() + evalargs->ea_timeout;
	}

	lua_pushlightuserdata(state, &ri);
	lua_setfield(state, LUA_REGISTRYINDEX, ZCP_RUN_INFO_KEY);
	VERIFY3U(3, ==, lua_gettop(state));

	/*
	 * Tell the Lua interpreter to call our handler every count
	 * instructions. Channel programs that execute for too long should
	 * die with ETIME.
	 */
	(void) lua_sethook(state, zcp_lua_counthook, LUA_MASKCOUNT,
	    zfs_lua_check_timeout_instruction_interval);

	/*
	 * Tell the Lua memory allocator to stop using KM_SLEEP before handing
	 * off control to the channel program. Channel programs that use too
	 * much memory should die with ENOSPC.
	 */
	evalargs->ea_allocargs->aa_must_succeed = B_FALSE;

	/*
	 * Call the Lua function that open-context passed us. This pops the
	 * function and its input from the stack and pushes any return
	 * or error values.
	 */
	err = lua_pcall(state, 1, LUA_MULTRET, 1);

	/*
	 * Let Lua use KM_SLEEP while we interpret the return values.
	 */
	evalargs->ea_allocargs->aa_must_succeed = B_TRUE;

	/*
	 * Remove the error handler callback from the stack.
	 */
	lua_remove(state, 1);

	switch (err) {
	case LUA_OK: {
		/*
		 * Lua supports returning multiple values in a single return
		 * statement.  Return values will have been pushed onto the
		 * stack:
		 * 1: Return value 1
		 * 2: Return value 2
		 * 3: etc...
		 * To simplify the process of retrieving a return value from a
		 * channel program, we disallow returning more than one value
		 * to ZFS from the Lua script, yielding a singleton return
		 * nvlist of the form { "return": Return value 1 }.
		 */
		int return_count = lua_gettop(state);

		if (return_count == 1) {
			evalargs->ea_result = 0;
			zcp_convert_return_values(state, evalargs->ea_outnvl,
			    ZCP_RET_RETURN, evalargs);
		} else if (return_count > 1) {
			evalargs->ea_result = SET_ERROR(ECHRNG);
			(void) lua_pushfstring(state, "Multiple return "
			    "values not supported");
			zcp_convert_return_values(state, evalargs->ea_outnvl,
			    ZCP_RET_ERROR, evalargs);
		}
		break;
	}
	case LUA_ERRRUN:
	case LUA_ERRGCMM: {
		/*
		 * The channel program encountered a fatal error within the
		 * script, such as failing an assertion, or calling a function
		 * with incompatible arguments. The error value and the
		 * traceback generated by zcp_traceback() should be on the
		 * stack.
		 */
		VERIFY3U(1, ==, lua_gettop(state));
		if (ri.zri_timed_out) {
			evalargs->ea_result = SET_ERROR(ETIME);
		} else {
			evalargs->ea_result = SET_ERROR(ECHRNG);
		}

		zcp_convert_return_values(state, evalargs->ea_outnvl,
		    ZCP_RET_ERROR, evalargs);
		break;
	}
	case LUA_ERRERR: {
		/*
		 * The channel program encountered a fatal error within the
		 * script, and we encountered another error while trying to
		 * compute the traceback in zcp_traceback(). We can only
		 * return the error message.
		 */
		VERIFY3U(1, ==, lua_gettop(state));
		if (ri.zri_timed_out) {
			evalargs->ea_result = SET_ERROR(ETIME);
		} else {
			evalargs->ea_result = SET_ERROR(ECHRNG);
		}

		zcp_convert_return_values(state, evalargs->ea_outnvl,
		    ZCP_RET_ERROR, evalargs);
		break;
	}
	case LUA_ERRMEM:
		/*
		 * Lua ran out of memory while running the channel program.
		 * There's not much we can do.
		 */
		evalargs->ea_result = SET_ERROR(ENOSPC);
		break;
	default:
		VERIFY0(err);
	}
}

int
zcp_eval(const char *poolname, const char *program, uint64_t timeout,
    uint64_t memlimit, nvpair_t *nvarg, nvlist_t *outnvl)
{
	int err;
	lua_State *state;
	zcp_eval_arg_t evalargs;

	if (timeout > ZCP_MAX_TIMEOUT)
		return (SET_ERROR(EINVAL));
	if (memlimit == 0 || memlimit > ZCP_MAX_MEMLIMIT)
		return (SET_ERROR(EINVAL));

	/* User timeout option is in ms */
	timeout = MSEC2NSEC(timeout);
	if (timeout > INT64_MAX || memlimit > INT64_MAX)
		return (SET_ERROR(EINVAL));

	zcp_alloc_arg_t allocargs = {
		.aa_must_succeed = B_TRUE,
		.aa_alloc_remaining = (int64_t)memlimit,
		.aa_alloc_limit = (int64_t)memlimit,
	};

	/*
	 * Creates a Lua state with a memory allocator that uses KM_SLEEP.
	 * This should never fail.
	 */
	state = lua_newstate(zcp_lua_alloc, &allocargs);
	VERIFY(state != NULL);
	(void) lua_atpanic(state, zcp_panic_cb);

	/*
	 * Load core Lua libraries we want access to.
	 */
	VERIFY3U(1, ==, luaopen_base(state));
	lua_pop(state, 1);
	VERIFY3U(1, ==, luaopen_coroutine(state));
	lua_setglobal(state, LUA_COLIBNAME);
	VERIFY0(lua_gettop(state));
	VERIFY3U(1, ==, luaopen_string(state));
	lua_setglobal(state, LUA_STRLIBNAME);
	VERIFY0(lua_gettop(state));
	VERIFY3U(1, ==, luaopen_table(state));
	lua_setglobal(state, LUA_TABLIBNAME);
	VERIFY0(lua_gettop(state));

	/*
	 * Load globally visible variables such as errno aliases.
	 */
	zcp_load_globals(state);
	VERIFY0(lua_gettop(state));

	/*
	 * Load ZFS-specific modules.
	 */
	lua_newtable(state);
	VERIFY3U(1, ==, zcp_load_list_lib(state));
	lua_setfield(state, -2, "list");
	VERIFY3U(1, ==, zcp_load_synctask_lib(state, B_FALSE));
	lua_setfield(state, -2, "check");
	VERIFY3U(1, ==, zcp_load_synctask_lib(state, B_TRUE));
	lua_setfield(state, -2, "sync");
	VERIFY3U(1, ==, zcp_load_get_lib(state));
	lua_pushcclosure(state, zcp_debug_info.func, 0);
	lua_setfield(state, -2, zcp_debug_info.name);
	lua_pushcclosure(state, zcp_exists_info.func, 0);
	lua_setfield(state, -2, zcp_exists_info.name);
	lua_setglobal(state, "zfs");
	VERIFY0(lua_gettop(state));

	/*
	 * Push the error-callback that calculates Lua stack traces on
	 * unexpected failures.
	 */
	lua_pushcfunction(state, zcp_traceback);
	VERIFY3U(1, ==, lua_gettop(state));

	/*
	 * Load the actual script as a function onto the stack as text ("t").
	 * The only valid error condition is a syntax error in the script.
	 * ERRMEM should not be possible because our allocator is using
	 * KM_SLEEP.  ERRGCMM should not be possible because we have not added
	 * any objects with __gc metamethods to the interpreter that could
	 * fail.
	 */
	err = luaL_loadbufferx(state, program, strlen(program),
	    "channel program", "t");
	if (err == LUA_ERRSYNTAX) {
		fnvlist_add_string(outnvl, ZCP_RET_ERROR,
		    lua_tostring(state, -1));
		lua_close(state);
		return (SET_ERROR(EINVAL));
	}
	VERIFY0(err);
	VERIFY3U(2, ==, lua_gettop(state));

	/*
	 * Convert the input nvlist to a Lua object and put it on top of the
	 * stack.
	 */
	if (nvarg == NULL) {
		lua_pushnil(state);
	} else {
		char errmsg[128];
		err = zcp_nvpair_value_to_lua(state, nvarg,
		    errmsg, sizeof (errmsg));
		if (err != 0) {
			fnvlist_add_string(outnvl, ZCP_RET_ERROR, errmsg);
			lua_close(state);
			return (SET_ERROR(EINVAL));
		}
	}
	VERIFY3U(3, ==, lua_gettop(state));

	evalargs.ea_state = state;
	evalargs.ea_allocargs = &allocargs;
	evalargs.ea_timeout = timeout;
	evalargs.ea_cred = CRED();
	evalargs.ea_outnvl = outnvl;
	evalargs.ea_result = 0;

	VERIFY0(dsl_sync_task(poolname, zcp_eval_check,
	    zcp_eval_sync, &evalargs, 0, ZFS_SPACE_CHECK_NONE));

	lua_close(state);

	return (evalargs.ea_result);
}

/*
 * Retrieve metadata about the currently running channel program.
 */
zcp_run_info_t *
zcp_run_info(lua_State *state)
{
	zcp_run_info_t *ri;

	lua_getfield(state, LUA_REGISTRYINDEX, ZCP_RUN_INFO_KEY);
	ri = lua_touserdata(state, -1);
	lua_pop(state, 1);
	return (ri);
}

/*
 * Argument Parsing
 * ================
 *
 * The Lua language allows methods to be called with any number
 * of arguments of any type. When calling back into ZFS we need to sanitize
 * arguments from channel programs to make sure unexpected arguments or
 * arguments of the wrong type result in clear error messages. To do this
 * in a uniform way all callbacks from channel programs should use the
 * zcp_parse_args() function to interpret inputs.
 *
 * Positional vs Keyword Arguments
 * ===============================
 *
 * Every callback function takes a fixed set of required positional arguments
 * and optional keyword arguments. For example, the destroy function takes
 * a single positional string argument (the name of the dataset to destroy)
 * and an optional "defer" keyword boolean argument. When calling lua functions
 * with parentheses, only positional arguments can be used:
 *
 *     zfs.sync.snapshot("rpool@snap")
 *
 * To use keyword arguments functions should be called with a single argument
 * that is a lua table containing mappings of integer -> positional arguments
 * and string -> keyword arguments:
 *
 *     zfs.sync.snapshot({1="rpool@snap", defer=true})
 *
 * The lua language allows curly braces to be used in place of parenthesis as
 * syntactic sugar for this calling convention:
 *
 *     zfs.sync.snapshot{"rpool@snap", defer=true}
 */

/*
 * Throw an error and print the given arguments.  If there are too many
 * arguments to fit in the output buffer, only the error format string is
 * output.
 */
static void
zcp_args_error(lua_State *state, const char *fname, const zcp_arg_t *pargs,
    const zcp_arg_t *kwargs, const char *fmt, ...)
{
	int i;
	char errmsg[512];
	size_t len = sizeof (errmsg);
	size_t msglen = 0;
	va_list argp;

	va_start(argp, fmt);
	VERIFY3U(len, >, vsnprintf(errmsg, len, fmt, argp));
	va_end(argp);

	/*
	 * Calculate the total length of the final string, including extra
	 * formatting characters. If the argument dump would be too large,
	 * only print the error string.
	 */
	msglen = strlen(errmsg);
	msglen += strlen(fname) + 4; /* : + {} + null terminator */
	for (i = 0; pargs[i].za_name != NULL; i++) {
		msglen += strlen(pargs[i].za_name);
		msglen += strlen(lua_typename(state, pargs[i].za_lua_type));
		if (pargs[i + 1].za_name != NULL || kwargs[0].za_name != NULL)
			msglen += 5; /* < + ( + )> + , */
		else
			msglen += 4; /* < + ( + )> */
	}
	for (i = 0; kwargs[i].za_name != NULL; i++) {
		msglen += strlen(kwargs[i].za_name);
		msglen += strlen(lua_typename(state, kwargs[i].za_lua_type));
		if (kwargs[i + 1].za_name != NULL)
			msglen += 4; /* =( + ) + , */
		else
			msglen += 3; /* =( + ) */
	}

	if (msglen >= len)
		(void) luaL_error(state, errmsg);

	VERIFY3U(len, >, strlcat(errmsg, ": ", len));
	VERIFY3U(len, >, strlcat(errmsg, fname, len));
	VERIFY3U(len, >, strlcat(errmsg, "{", len));
	for (i = 0; pargs[i].za_name != NULL; i++) {
		VERIFY3U(len, >, strlcat(errmsg, "<", len));
		VERIFY3U(len, >, strlcat(errmsg, pargs[i].za_name, len));
		VERIFY3U(len, >, strlcat(errmsg, "(", len));
		VERIFY3U(len, >, strlcat(errmsg,
		    lua_typename(state, pargs[i].za_lua_type), len));
		VERIFY3U(len, >, strlcat(errmsg, ")>", len));
		if (pargs[i + 1].za_name != NULL || kwargs[0].za_name != NULL) {
			VERIFY3U(len, >, strlcat(errmsg, ", ", len));
		}
	}
	for (i = 0; kwargs[i].za_name != NULL; i++) {
		VERIFY3U(len, >, strlcat(errmsg, kwargs[i].za_name, len));
		VERIFY3U(len, >, strlcat(errmsg, "=(", len));
		VERIFY3U(len, >, strlcat(errmsg,
		    lua_typename(state, kwargs[i].za_lua_type), len));
		VERIFY3U(len, >, strlcat(errmsg, ")", len));
		if (kwargs[i + 1].za_name != NULL) {
			VERIFY3U(len, >, strlcat(errmsg, ", ", len));
		}
	}
	VERIFY3U(len, >, strlcat(errmsg, "}", len));

	(void) luaL_error(state, errmsg);
	panic("unreachable code");
}

static void
zcp_parse_table_args(lua_State *state, const char *fname,
    const zcp_arg_t *pargs, const zcp_arg_t *kwargs)
{
	int i;
	int type;

	for (i = 0; pargs[i].za_name != NULL; i++) {
		/*
		 * Check the table for this positional argument, leaving it
		 * on the top of the stack once we finish validating it.
		 */
		lua_pushinteger(state, i + 1);
		lua_gettable(state, 1);

		type = lua_type(state, -1);
		if (type == LUA_TNIL) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "too few arguments");
			panic("unreachable code");
		} else if (type != pargs[i].za_lua_type) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "arg %d wrong type (is '%s', expected '%s')",
			    i + 1, lua_typename(state, type),
			    lua_typename(state, pargs[i].za_lua_type));
			panic("unreachable code");
		}

		/*
		 * Remove the positional argument from the table.
		 */
		lua_pushinteger(state, i + 1);
		lua_pushnil(state);
		lua_settable(state, 1);
	}

	for (i = 0; kwargs[i].za_name != NULL; i++) {
		/*
		 * Check the table for this keyword argument, which may be
		 * nil if it was omitted. Leave the value on the top of
		 * the stack after validating it.
		 */
		lua_getfield(state, 1, kwargs[i].za_name);

		type = lua_type(state, -1);
		if (type != LUA_TNIL && type != kwargs[i].za_lua_type) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "kwarg '%s' wrong type (is '%s', expected '%s')",
			    kwargs[i].za_name, lua_typename(state, type),
			    lua_typename(state, kwargs[i].za_lua_type));
			panic("unreachable code");
		}

		/*
		 * Remove the keyword argument from the table.
		 */
		lua_pushnil(state);
		lua_setfield(state, 1, kwargs[i].za_name);
	}

	/*
	 * Any entries remaining in the table are invalid inputs, print
	 * an error message based on what the entry is.
	 */
	lua_pushnil(state);
	if (lua_next(state, 1)) {
		if (lua_isnumber(state, -2) && lua_tointeger(state, -2) > 0) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "too many positional arguments");
		} else if (lua_isstring(state, -2)) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "invalid kwarg '%s'", lua_tostring(state, -2));
		} else {
			zcp_args_error(state, fname, pargs, kwargs,
			    "kwarg keys must be strings");
		}
		panic("unreachable code");
	}

	lua_remove(state, 1);
}

static void
zcp_parse_pos_args(lua_State *state, const char *fname, const zcp_arg_t *pargs,
    const zcp_arg_t *kwargs)
{
	int i;
	int type;

	for (i = 0; pargs[i].za_name != NULL; i++) {
		type = lua_type(state, i + 1);
		if (type == LUA_TNONE) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "too few arguments");
			panic("unreachable code");
		} else if (type != pargs[i].za_lua_type) {
			zcp_args_error(state, fname, pargs, kwargs,
			    "arg %d wrong type (is '%s', expected '%s')",
			    i + 1, lua_typename(state, type),
			    lua_typename(state, pargs[i].za_lua_type));
			panic("unreachable code");
		}
	}
	if (lua_gettop(state) != i) {
		zcp_args_error(state, fname, pargs, kwargs,
		    "too many positional arguments");
		panic("unreachable code");
	}

	for (i = 0; kwargs[i].za_name != NULL; i++) {
		lua_pushnil(state);
	}
}

/*
 * Checks the current Lua stack against an expected set of positional and
 * keyword arguments. If the stack does not match the expected arguments
 * aborts the current channel program with a useful error message, otherwise
 * it re-arranges the stack so that it contains the positional arguments
 * followed by the keyword argument values in declaration order. Any missing
 * keyword argument will be represented by a nil value on the stack.
 *
 * If the stack contains exactly one argument of type LUA_TTABLE the curly
 * braces calling convention is assumed, otherwise the stack is parsed for
 * positional arguments only.
 *
 * This function should be used by every function callback. It should be called
 * before the callback manipulates the Lua stack as it assumes the stack
 * represents the function arguments.
 */
void
zcp_parse_args(lua_State *state, const char *fname, const zcp_arg_t *pargs,
    const zcp_arg_t *kwargs)
{
	if (lua_gettop(state) == 1 && lua_istable(state, 1)) {
		zcp_parse_table_args(state, fname, pargs, kwargs);
	} else {
		zcp_parse_pos_args(state, fname, pargs, kwargs);
	}
}
