/*
* Copyright (c) 2007 Apple Inc. All rights reserved.
* Use is subject to license terms stated below.
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License v. 1.0 (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://www.opensolaris.org/os/licensing <http://www.opensolaris.org/os/licensing> .
* See the License for the specific language governing permissions
* and limitations under the License.
*
* THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*THE POSSIBILITY OF SUCH DAMAGE.
*/

/*	@(#)zfsutil.c   (c) 2007 Apple Inc.	*/

#include <syslog.h>

//#define HAVE_IOCTL_IN_SYS_IOCTL_H 1
#include <libzfs.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/loadable_fs.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/nvpair.h>
#include <sys/fs/zfs.h>


#define RAWDEV_PREFIX	"/dev/r"
#define ZFS_COMMAND	"/usr/local/sbin/zfs"
#define ZPOOL_COMMAND	"/usr/local/sbin/zpool"


const char *progname;
libzfs_handle_t *g_zfs;


static void
usage(void)
{
	fprintf(stderr, "usage: %s -p device\n", progname);
        exit(FSUR_INVAL);
}



#ifdef __OLDNEWFSSIMULATION__
static void
zfs_create_pool(const char *poolname, const char *devpath)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		(void) execl(ZPOOL_COMMAND, ZPOOL_COMMAND, "create", poolname, devpath, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}
#endif /* __OLDNEWFSSIMULATION__ */


#ifdef __EXECLOLD__
static void
zpool_import(uint64_t guid)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		char idstr[64];

		sprintf(idstr, "%llu", (u_longlong_t)guid);

		(void) execl(ZPOOL_COMMAND, ZPOOL_COMMAND, "import", "-f", idstr, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}
#endif /* __EXECLOLD__ */


#ifdef __EXECLOLD__
static void
zfs_mount(const char *filesystem)
{
	int pid;
	union wait status;

	pid = fork();
	if (pid == 0) {
		(void) execl(ZFS_COMMAND, ZFS_COMMAND, "mount", filesystem, NULL);
	} else if (pid != -1) {
		(void) wait4(pid, (int *)&status, 0, NULL);
	}
}
#endif /* __EXECLOLD__ */


static int
zfs_probe(const char *devpath)
{
	syslog(LOG_NOTICE, "+zfs_probe : devpath %s", devpath);
	closelog();
	nvlist_t *config = NULL;
	char *poolname;
	uint64_t guid;
	int result = FSUR_UNRECOGNIZED;
	int fd;

	if ((fd = open(devpath, O_RDONLY)) < 0) {
		syslog(LOG_NOTICE, "Could not open devpath %s : fd %d", devpath, fd);
		closelog();
		return (result);
	}
	if (zpool_read_label(fd, &config) != 0) {
		(void) close(fd);
		goto out;
	}
	syslog(LOG_NOTICE, "config %p", config);
        closelog();
	if (config == NULL) {
		goto out;
	}
	if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &poolname) != 0) {
		goto out;
	}

	/* Write the volume name to standard output */
	(void) fwrite(poolname, sizeof(char), strlen(poolname), stdout);
	goto out; //HERE

	result = FSUR_RECOGNIZED;
#if 0
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) == 0) {
		//zpool_import(guid);
		if ((g_zfs = libzfs_init()) == NULL)
	                return (1);
		const char *g ="2877854492215387157";
	        importargs_t idata = { 0 };



	idata.path = searchdirs;
        idata.paths = nsearch;
        idata.poolname = searchname;
        idata.guid = searchguid;
        idata.cachefile = cachefile;

        pools = zpool_search_import(g_zfs, &idata);

        if (pools != NULL && idata.exists &&
            (argc == 1 || strcmp(argv[0], argv[1]) == 0)) {
                (void) fprintf(stderr, gettext("cannot import '%s': "
                    "a pool with that name already exists\n"),
                    argv[0]);
                (void) fprintf(stderr, gettext("use the form '%s "
                    "<pool | id> <newpool>' to give it a new name\n"),
                    "zpool import");
                err = 1;
        } else if (pools == NULL && idata.exists) {
                (void) fprintf(stderr, gettext("cannot import '%s': "
                    "a pool with that name is already created/imported,\n"),
                    argv[0]);
                (void) fprintf(stderr, gettext("and no additional pools "
                    "with that name were found\n"));
                err = 1;
        } else if (pools == NULL) {
                if (argc != 0) {
                        (void) fprintf(stderr, gettext("cannot import '%s': "
                            "no such pool available\n"), argv[0]);
                }
                err = 1;
        }

        if (err == 1) {
                if (searchdirs != NULL)
                        free(searchdirs);
                if (envdup != NULL)
                        free(envdup);
                nvlist_free(policy);
                return (1);
        }

        /*
         * At this point we have a list of import candidate configs. Even if
         * we were searching by pool name or guid, we still need to
         * post-process the list to deal with pool state and possible
         * duplicate names.
         */
        err = 0;
        elem = NULL;
        first = B_TRUE;
        while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {

                verify(nvpair_value_nvlist(elem, &config) == 0);

                verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
                    &pool_state) == 0);
                if (!do_destroyed && pool_state == POOL_STATE_DESTROYED)
                        continue;
                if (do_destroyed && pool_state != POOL_STATE_DESTROYED)
                        continue;

                verify(nvlist_add_nvlist(config, ZPOOL_REWIND_POLICY,
                    policy) == 0);

                if (argc == 0) {
                        if (first)
                                first = B_FALSE;
                        else if (!do_all)
                                (void) printf("\n");

                        if (do_all) {
                                err |= do_import(config, NULL, mntopts,
                                    props, flags);
                        } else {
                                show_import(config);
                        }
                } else if (searchname != NULL) {
                        char *name;

                        /*
                         * We are searching for a pool based on name.
                         */
                        verify(nvlist_lookup_string(config,
                            ZPOOL_CONFIG_POOL_NAME, &name) == 0);

                        if (strcmp(name, searchname) == 0) {
                                if (found_config != NULL) {
                                        (void) fprintf(stderr, gettext(
                                            "cannot import '%s': more than "
                                            "one matching pool\n"), searchname);
                                        (void) fprintf(stderr, gettext(
                                            "import by numeric ID instead\n"));
                                        err = B_TRUE;
                                }
                                found_config = config;
                        }
                } else {
                        uint64_t guid;

                        /*
                         * Search for a pool by guid.
                         */
                        verify(nvlist_lookup_uint64(config,
                            ZPOOL_CONFIG_POOL_GUID, &guid) == 0);

                        if (guid == searchguid)
                                found_config = config;
                }
        }






		nvlist_t config;
		if (zpool_import(gzfs, &config, NULL, NULL) != 0) {
                	return (1);
		}
		if (poolname[0] != '\0') {
			zfs_mount(poolname);
		}
	}
#endif
out:
	(void) close(fd);
	if (config) {
		fnvlist_free(config);
	}
	syslog(LOG_NOTICE, "-zfs_probe : ret %d", result);
	return (result);
}


int
main(int argc, char **argv)
{

	setlogmask(LOG_UPTO(LOG_NOTICE));

        for (int i = 0; i < argc; i++) {
                syslog(LOG_NOTICE, "argv[%d]: %s\n", i, argv[i]);
                closelog();
        }

	char  blkdevice[MAXPATHLEN];
	char  what;
	char  *cp;
	char  *devname;
	char  *poolname;
	struct stat  sb;
	int  ret = FSUR_INVAL;

	/* save & strip off program name */
	progname = argv[0];
	argc--;
	argv++;

	if (argc < 2 || argv[0][0] != '-')
		usage();
 
	what = argv[0][1];
	syslog(LOG_NOTICE, "zfs.util called with option %c", what);
        closelog();	

#ifdef __OLDNEWFSSIMULATION__
	/*
	 * -v is used for our newfs_zfs simulation
	 *
	 * arguments will look like: "-v poolname /dev/rdisk1s2"
	 *
	 * we'll turn around and call "zpool create poolname /dev/disk1s2"
	 */
	if (what == 'v') {
		poolname = argv[1];
		argc--;
		argv++;
	}
#endif /* __OLDNEWFSSIMULATION__ */

	devname = argv[1];
	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;
	(void) sprintf(blkdevice, "%s%s", _PATH_DEV, devname);
	syslog(LOG_NOTICE, "blkdevice is %s", blkdevice);
	closelog();	

	if (stat(blkdevice, &sb) != 0) {
		fprintf(stderr, "%s: stat %s failed, %s\n", progname, blkdevice, strerror(errno));
		exit(FSUR_INVAL);
	}

	switch (what) {
	case FSUC_PROBE:
		ret = zfs_probe(blkdevice);
		ret = FSUR_RECOGNIZED;
		break;
	case 'k':
		fprintf(stdout, "%s", "00112233445566778899AABBCCDDEEFF");
		ret = FSUR_IO_SUCCESS;
		break;
	case 's':
		//Set a UUID
		//return FSUR_IO_SUCCESS
		ret = FSUR_IO_FAIL;
		break;
	case 'q':
		//Verify
		ret = 0;
		break;
	case 'y':
		//Repair
		ret = 0;
		break;	
#ifdef __OLDNEWFSSIMULATION__
	case 'v':
 		zfs_create_pool(poolname, blkdevice);
 		exit(0);
 		break;
#endif /* __OLDNEWFSSIMULATION__ */

	default:
		usage();
	}

	exit(ret);
}

