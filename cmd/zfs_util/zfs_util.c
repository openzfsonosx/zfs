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

#include <libzfs.h>

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

#ifndef FSUC_GETUUID
#define	FSUC_GETUUID	'k'
#endif

#ifndef FSUC_SETUUID
#define	FSUC_SETUUID	's'
#endif

#define	ZPOOL_COMMAND	"/usr/sbin/zpool"
#define	ZFS_UTIL_STDOUT_LOG	"/Library/Logs/zfs_util_stdout.log"
#define	ZFS_UTIL_STDERR_LOG	"/Library/Logs/zfs_util_stderr.log"

#ifdef DEBUG
int zfs_util_debug = 1;
#else
int zfs_util_debug = 0;
#endif

const char *progname;

static void
zfs_util_log(const char *format, ...)
{
	setlogmask(LOG_UPTO(LOG_NOTICE));
	if (zfs_util_debug == 0)
		return;
	va_list args;
	va_start(args, format);
	vsyslog(LOG_NOTICE, format, args);
	va_end(args);
	va_start(args, format);
	char buf[1024];
	(void) vsnprintf(buf, sizeof (buf), format, args);
	(void) strlcat(buf, "\n", sizeof (buf));
	fputs(buf, stderr);
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

static int
run_process(const char *path, char *argv[])
{
        pid_t pid;
        int rc, outfd, errfd;
	char buf[20];
	struct tm *stm;
	time_t now;

        pid = vfork();
        if (pid == 0) {
                outfd = open(ZFS_UTIL_STDOUT_LOG,
		    O_CREAT|O_APPEND|O_WRONLY, 0644);

                if (outfd < 0)
                        _exit(-1);

		errfd = open(ZFS_UTIL_STDERR_LOG,
		    O_CREAT|O_APPEND|O_WRONLY, 0644);

		if (errfd < 0)
			_exit(-1);

		(void) dup2(outfd, STDOUT_FILENO);

		(void) dup2(errfd, STDERR_FILENO);

                close(outfd);
                close(errfd);

		now = time (0);
		stm = localtime(&now);
		strftime (buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", stm);
		fputs(buf, stderr);
		{
		int i;
		fprintf(stderr, "\nRunning process: ");
		for (i = 0; argv[i]; i++)
			fprintf(stderr, "'%s' ", argv[i]);
		fprintf(stderr, "\r\n");
		}
                (void) execvp(path, argv);
                _exit(-1);
        } else if (pid > 0) {
                int status;

                while ((rc = waitpid(pid, &status, 0)) == -1 &&
                        errno == EINTR);
                if (rc < 0 || !WIFEXITED(status))
                        return (-1);

                return (WEXITSTATUS(status));
        }

        return (-1);
}


static int
zpool_import_by_guid(uint64_t poolguid)
{
	int rc;
	char idstr[64];
	char *argv[4] = {
	    ZPOOL_COMMAND,
	    "import",
	    (char *)NULL,
	    (char *)NULL };

	zfs_util_log("+zpool_import_by_guid %llu", poolguid);

	snprintf(idstr, sizeof (idstr), "%llu", poolguid);
	argv[2] = idstr;

	rc = run_process(argv[0], argv);

	zfs_util_log("-zpool_import_by_guid %d", rc);
	return (rc);
}

static int
zfs_probe(const char *devpath, uint64_t *outpoolguid)
{
	nvlist_t *config = NULL;
	int ret = FSUR_UNRECOGNIZED;
	int fd;
	uint64_t guid;

	zfs_util_log("+zfs_probe : devpath %s", devpath);

	if (outpoolguid == NULL)
		goto out;

	if ((fd = open(devpath, O_RDONLY)) < 0) {
		zfs_util_log("Could not open devpath %s : fd %d", devpath, fd);
		goto out;
	}

	if (zpool_read_label(fd, &config) != 0) {
		(void) close(fd);
		goto out;
	}

	(void) close(fd);

	if (config != NULL) {
		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid)== 0) {
			zfs_util_log("guid %llu", guid);
			nvlist_free(config);
			*outpoolguid = guid;
			ret = FSUR_RECOGNIZED;
		} else {
			goto out;
		}
	} else {
		goto out;
	}

out:
	zfs_util_log("-zfs_probe : ret %d", ret);
	return (ret);
}

#include <sys/fs/zfs.h>  // ZPOOL_CACHE
#include <sys/zfs_context.h> // kmem
#include <sys/stat.h>
void zpool_read_cachefile(void)
{
	int fd;
	struct stat stbf;
	void *buf = NULL;
	nvlist_t *nvlist, *child;
	nvpair_t *nvpair;
	uint64_t guid;
	int importrc = 0;

	zfs_util_log("reading cachefile\n");

	fd = open(ZPOOL_CACHE, O_RDONLY);
	if (fd < 0) return;

	if (fstat(fd, &stbf) || !stbf.st_size) goto out;

	buf = kmem_alloc(stbf.st_size, 0);
	if (!buf) goto out;

	if (read(fd, buf, stbf.st_size) != stbf.st_size) goto out;

	rename(ZPOOL_CACHE, ZPOOL_CACHE".importing");

	if (nvlist_unpack(buf, stbf.st_size, &nvlist, KM_PUSHPAGE) != 0)
		goto out;

	nvpair = NULL;
	while ((nvpair = nvlist_next_nvpair(nvlist, nvpair)) != NULL) {
		if (nvpair_type(nvpair) != DATA_TYPE_NVLIST)
			continue;

	  	VERIFY(nvpair_value_nvlist(nvpair, &child) == 0);

		zfs_util_log("Cachefile has pool '%s'\n",
					 nvpair_name(nvpair));

		if (nvlist_lookup_uint64(child, ZPOOL_CONFIG_POOL_GUID,
								 &guid)== 0) {
			zfs_util_log("Cachefile has pool '%s' guid %llu\n",
						 nvpair_name(nvpair),
						 guid);

			if ((importrc = zpool_import_by_guid(guid)) != 0)
				zfs_util_log("zpool import error %d\n",
							 importrc);
		}

	}
	nvlist_free(nvlist);

  out:
	close(fd);
	if (buf) kmem_free(buf, stbf.st_size);

}


int
main(int argc, char **argv)
{
	int argindex;
	for (argindex = 0; argindex < argc; argindex++) {
		zfs_util_log("argv[%d]: %s", argindex, argv[argindex]);
	}

	char blockdevice[MAXPATHLEN];
	char rawdevice[MAXPATHLEN];
	char what;
	char *cp;
	char *devname;
	struct stat sb;
	uint64_t poolguid;
	int ret = FSUR_INVAL;

	/* save & strip off program name */
	progname = argv[0];
	argc--;
	argv++;

	if (argc < 2 || argv[0][0] != '-') {
		usage();
		goto out;
	}

	what = argv[0][1];
	zfs_util_log("zfs.util called with option %c", what);

	devname = argv[1];
	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;
	(void) snprintf(rawdevice, sizeof (rawdevice), "/dev/r%s", devname);
	(void) snprintf(blockdevice, sizeof (blockdevice), "/dev/%s", devname);
	zfs_util_log("blockdevice is %s", blockdevice);

	if (stat(blockdevice, &sb) != 0) {
		zfs_util_log("%s: stat %s failed, %s", progname, blockdevice,
		    strerror(errno));
		goto out;
	}

	switch (what) {
	case FSUC_PROBE:
		ret = zfs_probe(rawdevice, &poolguid);
		if (ret == FSUR_RECOGNIZED) {
			zfs_util_log("FSUC_PROBE %s : FSUR_RECOGNIZED : "
			    "poolguid %llu", blockdevice, poolguid);

			/* Read cachefile and attempt imports */
			zpool_read_cachefile();

		} else if (ret == FSUR_UNRECOGNIZED) {
			zfs_util_log("FSUC_PROBE %s : FSUR_UNRECOGNIZED",
			    blockdevice);
		} else {
			zfs_util_log("FSUC_PROBE %s : returned invalid probe "
			    "status : %d", blockdevice, ret);
		}
		break;
	case FSUC_GETUUID:
		zfs_util_log("FSUC_GETUUID");
		ret = FSUR_INVAL;
		//ret = FSUR_IO_FAIL;
		break;
	case FSUC_SETUUID:
		/* Set a UUID */
		zfs_util_log("FSUC_SETUUID");
		ret = FSUR_INVAL;
		//ret = FSUR_IO_FAIL;
		break;
	default:
		ret = FSUR_INVAL;
		usage();
	}
out:
	closelog();
	exit(ret);

	return ret;	/* ...and make main fit the ANSI spec. */
}
