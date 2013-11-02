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

#include <sys/mount.h>
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


#ifdef __ZFSUTIL__
static void
usage(void)
{
	fprintf(stderr, "usage: %s -p device\n", progname);
	closelog();
        exit(FSUR_INVAL);
}
#endif



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


#ifdef __ZFSUTIL__
static int
zfs_probe(const char *devpath, boolean_t id_only, uint64_t *outguid)
{
	syslog(LOG_NOTICE, "+zfs_probe : devpath %s", devpath);
	nvlist_t *labelconfig = NULL;
	char *searchname = NULL;
	uint64_t searchguid = 0;
	int result = FSUR_UNRECOGNIZED;
	int fd;
	nvlist_t *pools = NULL;
	nvpair_t *elem = NULL;
	nvlist_t *config;
	nvlist_t *found_config = NULL;
	uint64_t pool_state = -1ULL;
	int err = 0;

	if ((fd = open(devpath, O_RDONLY)) < 0) {
		syslog(LOG_NOTICE, "Could not open devpath %s : fd %d", devpath, fd);
                return (result);
	}

	int read_label_error = zpool_read_label(fd, &labelconfig);
	if (read_label_error != 0) {
		(void) close(fd);
		syslog(LOG_NOTICE, "zpool_read_label error : %d", read_label_error);
		goto out;
	}

	(void) close(fd);

	if (labelconfig == NULL) {
		syslog(LOG_NOTICE, "labelconfig was null");
		goto out;
	}

	//dump_nvlist(labelconfig, 0);
	
	int searchguid_error = nvlist_lookup_uint64(labelconfig, ZPOOL_CONFIG_POOL_GUID, &searchguid);
	if (searchguid_error != 0) {
		syslog(LOG_NOTICE, "searchguid lookup error : %d", searchguid_error);
		//goto out;
	}
	syslog(LOG_NOTICE, "searchguid is %llu", searchguid);
	syslog(LOG_NOTICE, "searchguid is %llX", searchguid);
	if (id_only) {
		if (outguid) *outguid = searchguid;
		goto out;
	}

	int searchname_error = nvlist_lookup_string(labelconfig, ZPOOL_CONFIG_POOL_NAME, &searchname);
	if (searchname_error != 0) {
		syslog(LOG_NOTICE, "searchname lookup error : %d", searchname_error);
		//goto out;
	}

	/* Write the volume name to standard output */
	//(void) fwrite(searchname, sizeof(char), strlen(searchname), stdout);
	syslog(LOG_NOTICE, "searchname is %s", searchname);
	
	if (searchname_error != 0 && searchguid_error != 0)
		goto out;
	if ((g_zfs = libzfs_init()) == NULL)
		goto out;

	if (searchguid == 0 && searchname == NULL) {
		goto out;
	}
	importargs_t idata = { 0 };
	idata.unique = B_TRUE;
	//idata.path = searchdirs;
	//idata.paths = nsearch;
	if (searchname_error == 0) {
		idata.poolname = searchname;
		idata.guid = 0;
	} else if (searchguid_error == 0) {
		idata.guid = searchguid;
		idata.poolname = NULL;
	}
	//idata.cachefile = cachefile;

	pools = zpool_search_import(g_zfs, &idata);

	err = 0;

	if (pools != NULL && idata.exists) {
		syslog(LOG_NOTICE, "cannot import '%s': "
		    "a pool with that name already exists",
		    searchname);
		syslog(LOG_NOTICE, "use the form '%s "
		    "<pool | id> <newpool>' to give it a new name",
		    "zpool import");
		err = 1;
	} else if (pools == NULL && idata.exists) {
		syslog(LOG_NOTICE, "cannot import '%s': "
		    "a pool with that name is already created/imported,",
		    searchname);
		syslog(LOG_NOTICE, "and no additional pools "
		    "with that name were found\n");
		err = 1;
	} else if (pools == NULL) {
		syslog(LOG_NOTICE, "idata.poolname %s", idata.poolname);
		if (searchname != NULL) {
			syslog(LOG_NOTICE, "cannot import '%s': "
			    "no such pool available", searchname);
		} else if (searchguid != 0) {
			syslog(LOG_NOTICE, "cannot import '%llu': "
			    "no such pool available", searchguid);
		} else {
			syslog(LOG_NOTICE, "this should not happen");
		}
		err = 1;
	}

	if (err == 1) {
		goto out;
	}

	/*
	 * At this point we have a list of import candidate configs. Even if
	 * we were searching by pool name or guid, we still need to
	 * post-process the list to deal with pool state and possible
	 * duplicate names.
	 */
	err = 0;
	elem = NULL;
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {

		verify(nvpair_value_nvlist(elem, &config) == 0);

		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
		    &pool_state) == 0);
		syslog(LOG_NOTICE, "pool state %llu", pool_state);
		if (pool_state == POOL_STATE_DESTROYED)
			continue;

		//verify(nvlist_add_nvlist(config, ZPOOL_REWIND_POLICY,
		//    policy) == 0);
		if (searchname != NULL) {
			char *name;

			/*
			 * We are searching for a pool based on name. 
			 */
			verify(nvlist_lookup_string(config, 
			    ZPOOL_CONFIG_POOL_NAME, &name) == 0);
		
			if (strcmp(name, searchname) == 0) {
				if (found_config != NULL) {
					syslog(LOG_NOTICE, 	
					    "cannot import '%s': more than " 
					    "one matching pool", searchname);
					syslog(LOG_NOTICE, 	
					    "import by numeric ID instead");
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

	/*
	 * If we were searching for a specific pool, verify that we found a
	 * pool, and then do the import.
	 */
	if (err == 0) {
		if (found_config == NULL) {
			syslog(LOG_NOTICE, "cannot import '%s': "
			    "no such pool available", searchname);
			err = B_TRUE;
		} else {
			//dump_nvlist(found_config, 0);

			//Check vdev
			if ((fd = open(devpath, O_RDONLY)) < 0) {
				syslog(LOG_NOTICE, "Could not open devpath %s : fd %d", devpath, fd);
				goto out;
			}
			pool_state_t inusestate;
			char *name;
			boolean_t inuse = B_FALSE;
			int inuseerr = zpool_in_use(g_zfs, fd, &inusestate, &name, &inuse);
			syslog(LOG_NOTICE, "inuseerr %d : inusestate %d : name %s : inuse %d", 
			    inuseerr, inusestate, name, inuse);
			free(name);

			(void) close(fd);

			if (inuse == B_TRUE)
				result = FSUR_RECOGNIZED;

			
//#ifdef __AUTOIMPORT_ONLY_STATUS_OK__
			int reason;
			char *msgid;
			reason = zpool_import_status(found_config, &msgid);
			if (reason != ZPOOL_STATUS_OK) {
				result = FSUR_UNRECOGNIZED;
				syslog(LOG_NOTICE, "zpool_import_status "
				    "reason not ZPOOL_STATUS_OK, but rather : "
				    "%d", reason);
			}
//#endif /* __AUTOIMPORT_ONLY_STATUS_OK__ */

			if (result == FSUR_RECOGNIZED) {
				zpool_import(g_zfs, found_config, NULL, NULL);
			}

		}
	}

out:
	(void) close(fd);
	if (labelconfig) {
		fnvlist_free(labelconfig);
	}
	if (pools) {
		fnvlist_free(pools);
	}
	if(g_zfs != NULL)
		libzfs_fini(g_zfs);
	syslog(LOG_NOTICE, "-zfs_probe : ret %d", result);
	return (result);
}
#endif


static int
mount_zfs_import(const char *devpath, const char *mountpoint)
{
        syslog(LOG_NOTICE, "+mount_zfs_import : devpath %s", devpath);
        nvlist_t *labelconfig = NULL;
        uint64_t searchguid = 0;
        int ret = 1;
        int fd;
        nvlist_t *pools = NULL;
        nvpair_t *elem = NULL;
        nvlist_t *config;
        nvlist_t *found_config = NULL;
	zpool_handle_t *zhp = NULL;

        if ((fd = open(devpath, O_RDONLY)) < 0) {
                syslog(LOG_NOTICE, "Could not open devpath %s : fd %d", devpath, fd);
		goto out;
        }

        int read_label_error = zpool_read_label(fd, &labelconfig);
        if (read_label_error != 0) {
                (void) close(fd);
                syslog(LOG_NOTICE, "zpool_read_label error : %d", read_label_error);
                goto out;
        }

        (void) close(fd);

        if (labelconfig == NULL) {
                syslog(LOG_NOTICE, "labelconfig was null");
                goto out;
        }

        //dump_nvlist(labelconfig, 0);

        int searchguid_error = nvlist_lookup_uint64(labelconfig, ZPOOL_CONFIG_POOL_GUID, &searchguid);
        if (searchguid_error != 0) {
                syslog(LOG_NOTICE, "searchguid lookup error : %d", searchguid_error);
                goto out;
        }
        syslog(LOG_NOTICE, "searchguid is %llu", searchguid);
        syslog(LOG_NOTICE, "searchguid_hex is %llX", searchguid);

        if (searchguid == 0) {
                goto out;
        }

        if ((g_zfs = libzfs_init()) == NULL) {
                goto out;
	}

	importargs_t idata = { 0 };
	idata.unique = B_TRUE;
	//idata.path = searchdirs;
	//idata.paths = nsearch;
	idata.guid = searchguid;
	idata.poolname = NULL;
	//idata.cachefile = cachefile;

	pools = zpool_search_import(g_zfs, &idata);
	syslog(LOG_NOTICE, "pools %p", pools);

	elem = NULL;
	elem = nvlist_next_nvpair(pools, elem);
	verify(nvpair_value_nvlist(elem, &config) == 0);
	uint64_t guid;

	/*
	 * Search for a pool by guid.
	 */
	verify(nvlist_lookup_uint64(config,
	    ZPOOL_CONFIG_POOL_GUID, &guid) == 0);
	if (guid == searchguid)
		found_config = config;

	syslog(LOG_NOTICE, "found_config %p", found_config);

	//ret = zpool_import(g_zfs, found_config, NULL, NULL);
	ret = zpool_import(g_zfs, found_config, NULL, "/Volumes");

	syslog(LOG_NOTICE, "zpool_import ret %d", ret);

	char *name = NULL;
	verify(nvlist_lookup_string(config,
	    ZPOOL_CONFIG_POOL_NAME, &name) == 0);
        if ((zhp = zpool_open_canfail(g_zfs, name)) == NULL) {
		ret = 1;
		goto out;
	}

//	char  *cp = NULL;
//	char  *mntdir = NULL;
//	cp = strrchr(mountpoint, '/');
//	if (cp != 0)
//	mntdir = cp + 1;
//	syslog(LOG_NOTICE, "mntdir %s", mntdir);
	
	//for now, not passing in diskarbitrationd's nodev,noowners,nosuid
        if (zpool_get_state(zhp) != POOL_STATE_UNAVAIL &&
            zpool_enable_datasets(zhp, NULL, MS_OVERLAY) != 0) {
                ret = 1;
        }
        zpool_close(zhp);
out:
	if(g_zfs != NULL)
		libzfs_fini(g_zfs);

        syslog(LOG_NOTICE, "-mount_zfs_import : ret %d", ret);
	
	return ret;
}


int
main(int argc, char **argv)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char mntopts[MNT_LINE_MAX];
	//char  path[MAXPATHLEN];
	
	
	setlogmask(LOG_UPTO(LOG_NOTICE));
	char  blkdevice[MAXPATHLEN];
	char  *cp = NULL;
	char  *devname = NULL;
	struct stat  sb;
	int ret = -1;
		
	progname = argv[0];
		
	syslog(LOG_NOTICE, "progname %s", progname);
	for (int i = 0; i < argc; i++) {
		syslog(LOG_NOTICE, "argv[%d]: %s\n", i, argv[i]);
	}
		
	int ch;
	//syslog(LOG_NOTICE, "ch %c, argc %d : optind %d : optarg %s : optopt %c : optreset %d", ch, argc, optind, optarg, optopt, optreset);
	
	int first = 1;
	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			if (first) {
				first = 0;
				strlcat(mntopts, optarg, sizeof(mntopts));
			} else {
				strlcat(mntopts, ",", sizeof(mntopts));
				strlcat(mntopts, optarg, sizeof(mntopts));
			}
			
			break;
		case '?':
		default:
			optind += 1;
			//usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argv[0] != NULL) {
		devname = argv[0];
	}
	if (argv[1] != NULL) {
		strlcat(mountpoint, argv[1], sizeof(mountpoint));
	}

	syslog(LOG_NOTICE, "mntopts %s", mntopts);
	syslog(LOG_NOTICE, "devname %s", devname);
	syslog(LOG_NOTICE, "mounpoint %s", mountpoint);

	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;
	(void) sprintf(blkdevice, "%s%s", _PATH_DEV, devname);
	syslog(LOG_NOTICE, "blkdevice is %s", blkdevice);
	if (stat(blkdevice, &sb) != 0) {
		syslog(LOG_NOTICE, "%s: stat %s failed, %s", 
		    progname, blkdevice, strerror(errno));
		ret = 1;
	} else {
		ret = 0;
	}

	closelog();
	ret = mount_zfs_import(blkdevice, mountpoint);
	
	return ret;
#if 0
	setlogmask(LOG_UPTO(LOG_NOTICE));

        for (int i = 0; i < argc; i++) {
                syslog(LOG_NOTICE, "argv[%d]: %s\n", i, argv[i]);
        }

	char  blkdevice[MAXPATHLEN];
	char  what;
	char  *cp;
	char  *devname;
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

#ifdef __OLDNEWFSSIMULATION__
	char  *poolname;
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

	if (stat(blkdevice, &sb) != 0) {
		syslog(LOG_NOTICE, "%s: stat %s failed, %s", progname, blkdevice, strerror(errno));
		closelog();
		exit(FSUR_INVAL);
	}

//HERE
	uint64_t outuuid = 0ULL;
	switch (what) {
	case FSUC_PROBE:
		ret = zfs_probe(blkdevice, B_FALSE, NULL);
		if (ret == -1) syslog(LOG_NOTICE, "FSUC_PROBE %s : FSUR_RECOGNIZED", blkdevice);
		else if (ret == -2) syslog(LOG_NOTICE, "FSUC_PROBE %s : FSUR_UNRECOGNIZED", blkdevice);
		else syslog(LOG_NOTICE, "FSUC_PROBE returned invalid probe status : %d", ret);
		break;
	case 'k':
		ret = zfs_probe(blkdevice, B_TRUE, &outuuid);
		//fprintf(stdout, "%s", "00112233445566778899AABBCCDDEEFF");
		fprintf(stdout, "%llX", outuuid);
		if (outuuid != 0ULL)
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
		closelog();
 		exit(0);
 		break;
#endif /* __OLDNEWFSSIMULATION__ */

	default:
		usage();
	}

	closelog();
	exit(ret);
#endif
}

