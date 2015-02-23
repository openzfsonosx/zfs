/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.2 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/loadable_fs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <priv.h>

#include <sys/zfs_context.h>
#include <libzfs.h>

#ifndef FSUC_GETUUID
#define	FSUC_GETUUID	'k'
#endif

#ifndef FSUC_SETUUID
#define	FSUC_SETUUID	's'
#endif

#define	ZPOOL_IMPORT_ALL_COOKIE		"/var/run/org.openzfsonosx.zpool-import-all.didRun"
#define	INVARIANT_DISKS_IDLE_FILE	"/var/run/disk/invariant.idle"
#define	IS_INVARIANT_DISKS_LOADED_CMD	"/bin/launchctl list -x org.openzfsonosx.InvariantDisks &>/dev/null"
#define	INVARIANT_DISKS_TIMEOUT_SECONDS	60

#ifdef DEBUG
int zfs_util_debug = 1;
#else
int zfs_util_debug = 0;
#endif

#define	printf	zfs_util_log

#define ZFS_AUTOIMPORT_ZPOOL_CACHE_ONLY

const char *progname;
libzfs_handle_t *g_zfs;

static void
zfs_util_log(const char *format, ...)
{
	if (zfs_util_debug == 0)
		return;

	va_list args;
	char buf[1024];

	setlogmask(LOG_UPTO(LOG_NOTICE));

	va_start(args, format);
	(void) vsnprintf(buf, sizeof (buf), format, args);
	fputs(buf, stderr);
	va_end(args);

	if (*(&buf[strlen(buf) - 1]) == '\n')
		*(&buf[strlen(buf) - 1]) = '\0';
	va_start(args, format);
	vsyslog(LOG_NOTICE, format, args);
	va_end(args);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s action_arg device_arg [Flags] \n", progname);
	fprintf(stderr, "action_arg:\n");
	fprintf(stderr, "       -%c (Probe for mounting)\n", FSUC_PROBE);
	fprintf(stderr, "device_arg:\n");
	fprintf(stderr, "       device we are acting upon (for example, "
	    "'disk0s1')\n");
	fprintf(stderr, "Flags:\n");
	fprintf(stderr, "       required for Probe\n");
	fprintf(stderr, "       indicates removable or fixed (for example "
	    "'fixed')\n");
	fprintf(stderr, "       indicates readonly or writable (for example "
	    "'readonly')\n");
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "       %s -p disk0s1 removable readonly\n", progname);
}

/*
 * Perform the import for the given configuration.  This passes the heavy
 * lifting off to zpool_import_props(), and then mounts the datasets contained
 * within the pool.
 */
static int
do_import(nvlist_t *config, const char *newname, const char *mntopts,
    nvlist_t *props, int flags)
{
	zpool_handle_t *zhp;
	char *name;
	uint64_t state;
	uint64_t version;

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);

	verify(nvlist_lookup_uint64(config,
	    ZPOOL_CONFIG_POOL_STATE, &state) == 0);
	verify(nvlist_lookup_uint64(config,
	    ZPOOL_CONFIG_VERSION, &version) == 0);
	if (!SPA_VERSION_IS_SUPPORTED(version)) {
		printf("cannot import '%s': pool is formatted using an "
		    "unsupported ZFS version\n", name);
		return (1);
	} else if (state != POOL_STATE_EXPORTED &&
	    !(flags & ZFS_IMPORT_ANY_HOST)) {
		uint64_t hostid;

		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_HOSTID,
		    &hostid) == 0) {
			unsigned long system_hostid = gethostid() & 0xffffffff;

			if ((unsigned long)hostid != system_hostid) {
				char *hostname;
				uint64_t timestamp;
				time_t t;

				verify(nvlist_lookup_string(config,
				    ZPOOL_CONFIG_HOSTNAME, &hostname) == 0);
				verify(nvlist_lookup_uint64(config,
				    ZPOOL_CONFIG_TIMESTAMP, &timestamp) == 0);
				t = timestamp;
				printf("cannot import " "'%s': pool may be in "
				    "use from other system, it was last "
				    "accessed by %s (hostid: 0x%lx) on %s\n",
				    name, hostname, (unsigned long)hostid,
				    asctime(localtime(&t)));
				printf("use '-f' to import anyway\n");
				return (1);
			}
		} else {
			printf("cannot import '%s': pool may be in use from "
			    "other system\n", name);
			printf("use '-f' to import anyway\n");
			return (1);
		}
	}

	if (zpool_import_props(g_zfs, config, newname, props, flags) != 0)
		return (1);

	if (newname != NULL)
		name = (char *)newname;

	if ((zhp = zpool_open_canfail(g_zfs, name)) == NULL)
		return (1);

	if (zpool_get_state(zhp) != POOL_STATE_UNAVAIL &&
	    !(flags & ZFS_IMPORT_ONLY) &&
	    zpool_enable_datasets(zhp, mntopts, 0) != 0) {
		zpool_close(zhp);
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

static int
zpool_import_by_guid(uint64_t searchguid)
{
	int err = 0;
	nvlist_t *pools = NULL;
	nvpair_t *elem;
	nvlist_t *config;
	nvlist_t *found_config = NULL;
	nvlist_t *policy = NULL;
	boolean_t first;
	int flags = ZFS_IMPORT_NORMAL;
	uint32_t rewind_policy = ZPOOL_NO_REWIND;
	uint64_t pool_state, txg = -1ULL;
	importargs_t idata = { 0 };
#ifdef ZFS_AUTOIMPORT_ZPOOL_STATUS_OK_ONLY
	char *msgid;
	zpool_status_t reason;
	zpool_errata_t errata;
#endif

	if ((g_zfs = libzfs_init()) == NULL)
		return (1);

	idata.unique = B_TRUE;

	/* In the future, we can capture further policy and include it here */
	if (nvlist_alloc(&policy, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_uint64(policy, ZPOOL_REWIND_REQUEST_TXG, txg) != 0 ||
	    nvlist_add_uint32(policy, ZPOOL_REWIND_REQUEST, rewind_policy) != 0)
		goto error;

	if (!priv_ineffect(PRIV_SYS_CONFIG)) {
		printf("cannot discover pools: permission denied\n");
		nvlist_free(policy);
		return (1);
	}

	idata.guid = searchguid;

	pools = zpool_search_import(g_zfs, &idata);

	if (pools == NULL && idata.exists) {
		printf("cannot import '%llu': a pool with that guid is already "
		    "created/imported\n", searchguid);
		err = 1;
	} else if (pools == NULL) {
		printf("cannot import '%llu': no such pool available\n",
		    searchguid);
		err = 1;
	}

	if (err == 1) {
		nvlist_free(policy);
		return (1);
	}

	/*
	 * At this point we have a list of import candidate configs. Even though
	 * we were searching by guid, we still need to post-process the list to
	 * deal with pool state.
	 */
	err = 0;
	elem = NULL;
	first = B_TRUE;
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {

		verify(nvpair_value_nvlist(elem, &config) == 0);

		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
		    &pool_state) == 0);
		if (pool_state == POOL_STATE_DESTROYED)
			continue;

		verify(nvlist_add_nvlist(config, ZPOOL_REWIND_POLICY,
		    policy) == 0);

		uint64_t guid;

		/*
		 * Search for a pool by guid.
		 */
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		if (guid == searchguid)
			found_config = config;
	}

	/*
	 * If we were searching for a specific pool, verify that we found a
	 * pool, and then do the import.
	 */
	if (err == 0) {
		if (found_config == NULL) {
			printf("cannot import '%llu': no such pool available\n",
			    searchguid);
			err = B_TRUE;
		} else {
#ifdef ZFS_AUTOIMPORT_ZPOOL_STATUS_OK_ONLY
			reason = zpool_import_status(config, &msgid, &errata);
			if (reason == ZPOOL_STATUS_OK)
				err |= do_import(found_config, NULL, NULL, NULL,
				    flags);
			else
				err = 1;
#else
			err |= do_import(found_config, NULL, NULL, NULL, flags);
#endif
		}
	}

error:
	nvlist_free(pools);
	nvlist_free(policy);
	libzfs_fini(g_zfs);

	return (err ? 1 : 0);
}

extern int is_optical_media(char *bsdname);


static int
zfs_probe(const char *devpath, uint64_t *outpoolguid)
{
	nvlist_t *config = NULL;
	int ret = FSUR_UNRECOGNIZED;
	int fd;
	uint64_t guid;
	int i;
	struct stat sbuf;

	printf("+zfs_probe : devpath %s\n", devpath);

	if (system(IS_INVARIANT_DISKS_LOADED_CMD) == 0) {
		/* InvariantDisks is loaded */
		i = 0;
		while(i != INVARIANT_DISKS_TIMEOUT_SECONDS) {
			if (stat(INVARIANT_DISKS_IDLE_FILE, &sbuf) == 0) {
				printf("Found %s after %d iterations of "
				    "sleeping 1 second\n",
				    INVARIANT_DISKS_IDLE_FILE, i);
				break;
			}
			sleep(1);
			i++;
		}
		if (i == INVARIANT_DISKS_TIMEOUT_SECONDS) {
			printf("File %s not found within %d seconds\n",
			    INVARIANT_DISKS_IDLE_FILE,
			    INVARIANT_DISKS_TIMEOUT_SECONDS);
		}
	}

	if (outpoolguid == NULL)
		goto out;

	if ((fd = open(devpath, O_RDONLY)) < 0) {
		printf("Could not open devpath %s : fd %d\n", devpath, fd);
		goto out;
	}

	if (zpool_read_label(fd, &config) != 0) {
		(void) close(fd);
		goto out;
	}

	(void) close(fd);

	if (config != NULL) {
		ret = FSUR_RECOGNIZED;
		*outpoolguid = (nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_GUID, &guid) == 0) ? guid : 0;
		nvlist_free(config);
	}
out:
	printf("-zfs_probe : ret %d\n", ret);
	return (ret);
}

#ifdef ZFS_AUTOIMPORT_ZPOOL_CACHE_ONLY
void
zpool_read_cachefile(void)
{
	int fd;
	struct stat stbf;
	void *buf = NULL;
	nvlist_t *nvlist, *child;
	nvpair_t *nvpair;
	uint64_t guid;
	int importrc = 0;

	printf("reading cachefile\n");

	fd = open(ZPOOL_CACHE, O_RDONLY);
	if (fd < 0)
		return;

	if (fstat(fd, &stbf) || !stbf.st_size)
		goto out;

	buf = kmem_alloc(stbf.st_size, 0);
	if (!buf)
		goto out;

	if (read(fd, buf, stbf.st_size) != stbf.st_size)
		goto out;

	if (nvlist_unpack(buf, stbf.st_size, &nvlist, KM_PUSHPAGE) != 0)
		goto out;

	nvpair = NULL;
	while ((nvpair = nvlist_next_nvpair(nvlist, nvpair)) != NULL) {
		if (nvpair_type(nvpair) != DATA_TYPE_NVLIST)
			continue;

		VERIFY(nvpair_value_nvlist(nvpair, &child) == 0);

		printf("Cachefile has pool '%s'\n", nvpair_name(nvpair));

		if (nvlist_lookup_uint64(child, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0) {
			printf("Cachefile has pool '%s' guid %llu\n",
			    nvpair_name(nvpair), guid);

			importrc = zpool_import_by_guid(guid);
			printf("zpool import error %d\n", importrc);
		}

	}
	nvlist_free(nvlist);

out:
	close(fd);
	if (buf)
		kmem_free(buf, stbf.st_size);

}
#endif

int
main(int argc, char **argv)
{
	int argindex;
	for (argindex = 0; argindex < argc; argindex++) {
		printf("argv[%d]: %s\n", argindex, argv[argindex]);
	}

	char blockdevice[MAXPATHLEN];
	char rawdevice[MAXPATHLEN];
	char what;
	char *cp;
	char *devname;
	struct stat sb;
	uint64_t poolguid = 0;
	int ret = FSUR_INVAL;
	int rval;
	ushort_t disknum, partnum;
#ifndef ZFS_AUTOIMPORT_ZPOOL_CACHE_ONLY
	int importrc = 0;
#endif

	/* save & strip off program name */
	progname = argv[0];
	argc--;
	argv++;

	if (argc < 2 || argv[0][0] != '-') {
		usage();
		goto out;
	}

	what = argv[0][1];
	printf("zfs.util called with option %c\n", what);

	devname = argv[1];
	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;

	if (is_optical_media(devname)) {
		printf("zfs.util: is_optical_media(%s)\n", devname);
		goto out;
	}

	(void) snprintf(rawdevice, sizeof (rawdevice), "/dev/r%s", devname);
	(void) snprintf(blockdevice, sizeof (blockdevice), "/dev/%s", devname);
	printf("blockdevice is %s\n", blockdevice);

	if (stat(blockdevice, &sb) != 0) {
		printf("%s: stat %s failed, %s\n", progname, blockdevice,
		    strerror(errno));
		goto out;
	}

	switch (what) {
	case FSUC_PROBE:
		if (stat(ZPOOL_IMPORT_ALL_COOKIE, &sb) != 0) {
			rval = sscanf(blockdevice, "/dev/disk%hus%hu",
			    &disknum,
			    &partnum);
			if (rval == 2)
				ret = FSUR_RECOGNIZED;
			else
				ret = zfs_probe(rawdevice, &poolguid);
			exit(ret);
		} else {
			ret = zfs_probe(rawdevice, &poolguid);
		}
		if (ret == FSUR_RECOGNIZED) {
			printf("FSUC_PROBE %s : FSUR_RECOGNIZED : poolguid "
			    "%llu\n", blockdevice, poolguid);
			if (poolguid != 0) {
#ifndef ZFS_AUTOIMPORT_ZPOOL_CACHE_ONLY
				importrc = zpool_import_by_guid(poolguid);
				printf("zpool import error %d\n", importrc);
#else
				/* Read cachefile and attempt imports */
				zpool_read_cachefile();
#endif
			}
		} else if (ret == FSUR_UNRECOGNIZED) {
			printf("FSUC_PROBE %s : FSUR_UNRECOGNIZED\n",
			    blockdevice);
		} else {
			printf("FSUC_PROBE %s : returned invalid probe status :"
			    " %d\n", blockdevice, ret);
		}
		break;
	case FSUC_GETUUID:
		printf("FSUC_GETUUID\n");
		ret = FSUR_INVAL;
		break;
	case FSUC_SETUUID:
		/* Set a UUID */
		printf("FSUC_SETUUID\n");
		ret = FSUR_INVAL;
		break;
	default:
		ret = FSUR_INVAL;
		usage();
	}
out:
	closelog();
	exit(ret);

	return (ret);	/* ...and make main fit the ANSI spec. */
}
