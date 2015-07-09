/*
 * ZFS boot utils
 *
 * While loading the kext, check if early boot and zfs-boot
 * kernel flag.
 * XXX Debug by importing a pool by name on every load.
 * Allocate pool_list (and lock).
 * Register matching notification zfs_boot_probe_disk to check
 * IOMediaBSDClient devices as they are published (or matched?),
 * passing pool_list (automatically calls handler for all
 * existing devices).
 * Dispatch zfs_boot_import_thread on system_taskq.
 *
 * In notification handler zfs_boot_probe_disk:
 * Check provider IOMedia for:
 *  - Just leaf nodes, XXX or:
 *  1 Leaf node and whole disk.
 *  2 Leaf node and type ZFS.
 *  3 Leaf node and type FreeBSD-ZFS.
 * Check IOMedia meets minimum size or bail.
 * Allocate char* buffer.
 * Call vdev_disk_read_rootlabel.
 * XXX Alternately:
 * Alloc and prep IOMemoryDescriptor.
 * Open IOMedia device (read-only).
 * Try to read vdev label from device.
 * Close IOMedia device.
 * Release IOMemoryDescriptor (data is in buffer).
 * XXX
 * If label was read, try to generate a config from label.
 * Check pool name matches zfs-boot or bail.
 * Check pool status.
 * Update this vdev's path and set status.
 * Set other vdevs to missing status.
 * Check-in config in thread-safe manner:
 * Take pool_list lock.
 * If config not found, insert new config, or update existing.
 * Unlock pool_list.
 * If found config is complete, wake import thread.
 * XXX Wake thread with lock held or after unlocking?
 *
 * In vdev_disk_read_rootlabel:
 * Use vdev_disk_physio to read label.
 * If label was read, try to unpack.
 * Return label or failure.
 *
 * In vdev_disk_physio:
 * Open device (read-only) using vnop/VOP.
 * Try to read vdev label from device.
 * Close device using vnop/VOP.
 *
 * In zfs_boot_import_thread:
 * Loop checking for work and sleeping on lock between loops.
 * Take pool_list lock and check for work.
 * Attempt to import root pool using spa_import_rootpool.
 * XXX See if there are any early-boot issues with vdev_disk.
 * If successful, remove notification handler (waits for
 * all tasks).
 * Empty and deallocate pool_list (and lock).
 */

#ifdef ZFS_BOOT

#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include <sys/zfs_boot.h>
#include <sys/taskq.h>

#include <sys/param.h>
#include <sys/nvpair.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_disk.h>
#include <sys/spa_impl.h>
#include <sys/spa_boot.h>

#include <sys/zfs_context.h>
#include <sys/mount.h>
#include <sys/fs/zfs.h>
#if 0
#include <sys/zio.h>
#endif
#include <sys/spa.h>

#ifndef verify
#define	verify(EX) (void)((EX) || \
	(printf("%s, %s, %d, %s\n", #EX, __FILE__, __LINE__, __func__), 0))
#endif  /* verify */

/*
 * C functions for boot-time vdev discovery
 */

extern "C" {

/*
 * Intermediate structures used to gather configuration information.
 */
typedef struct config_entry {
	uint64_t		ce_txg;
	nvlist_t		*ce_config;
	struct config_entry	*ce_next;
} config_entry_t;

typedef struct vdev_entry {
	uint64_t		ve_guid;
	config_entry_t		*ve_configs;
	struct vdev_entry	*ve_next;
} vdev_entry_t;

typedef struct pool_entry {
	uint64_t		pe_guid;
	vdev_entry_t		*pe_vdevs;
	struct pool_entry	*pe_next;
	uint64_t		complete;
} pool_entry_t;

typedef struct name_entry {
	char			*ne_name;
	uint64_t		ne_guid;
	uint64_t		ne_order;
	uint64_t		ne_num_labels;
	struct name_entry	*ne_next;
} name_entry_t;

typedef struct pool_list {
	pool_entry_t		*pools;
	name_entry_t		*names;
	uint64_t		pool_guid;
	char			*pool_name;
	OSSet			*new_disks;
	OSSet			*disks;
	IOLock			*lock;
	IOService		*zfs_hl;
	IONotifier		*notifier;
	volatile UInt64		terminating;
} pool_list_t;

#define ZFS_BOOT_ACTIVE		0x1
#define ZFS_BOOT_TERMINATING	0x2
#define ZFS_BOOT_INVALID	0x99

#define ZFS_BOOT_PREALLOC_SET	5

static pool_list_t *zfs_boot_pool_list;

#ifndef DEBUG
static char *
#else
char *
#endif
zfs_boot_get_devid(const char *path)
{
	/*
	 * XXX Unavailable interface
	 *
	 * If we implement one in spl, it could
	 * simplify import when device paths
	 * have changed (e.g. USB pools).
	 */
	return (NULL);
}

/*
 * Go through and fix up any path and/or devid information for the given vdev
 * configuration.
 *
 * Copied from libzfs_import.c
 */
#ifndef DEBUG
static int
#else
int
#endif
zfs_boot_fix_paths(nvlist_t *nv, name_entry_t *names)
{
	nvlist_t **child;
	uint_t c, children;
	uint64_t guid;
	name_entry_t *ne, *best;
	char *path, *devid;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			if (zfs_boot_fix_paths(child[c], names) != 0)
				return (-1);
		return (0);
	}

	/*
	 * This is a leaf (file or disk) vdev.  In either case, go through
	 * the name list and see if we find a matching guid.  If so, replace
	 * the path and see if we can calculate a new devid.
	 *
	 * There may be multiple names associated with a particular guid, in
	 * which case we have overlapping partitions or multiple paths to the
	 * same disk.  In this case we prefer to use the path name which
	 * matches the ZPOOL_CONFIG_PATH.  If no matching entry is found we
	 * use the lowest order device which corresponds to the first match
	 * while traversing the ZPOOL_IMPORT_PATH search path.
	 */
	verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) != 0)
		path = NULL;

	best = NULL;
	for (ne = names; ne != NULL; ne = ne->ne_next) {
		if (ne->ne_guid == guid) {

			if (path == NULL) {
				best = ne;
				break;
			}

			if ((strlen(path) == strlen(ne->ne_name)) &&
			    strncmp(path, ne->ne_name, strlen(path)) == 0) {
				best = ne;
				break;
			}

			if (best == NULL) {
				best = ne;
				continue;
			}

			/* Prefer paths with more vdev labels. */
			if (ne->ne_num_labels > best->ne_num_labels) {
				best = ne;
				continue;
			}

			/* Prefer paths earlier in the search order. */
			if (best->ne_num_labels == best->ne_num_labels &&
			    ne->ne_order < best->ne_order) {
				best = ne;
				continue;
			}
		}
	}

	if (best == NULL)
		return (0);

	if (nvlist_add_string(nv, ZPOOL_CONFIG_PATH, best->ne_name) != 0)
		return (-1);

	if ((devid = zfs_boot_get_devid(best->ne_name)) == NULL) {
		(void) nvlist_remove_all(nv, ZPOOL_CONFIG_DEVID);
	} else {
		if (nvlist_add_string(nv, ZPOOL_CONFIG_DEVID, devid) != 0)
			return (-1);
		spa_strfree(devid);
	}

	return (0);
}

/*
 * Add the given configuration to the list of known devices.
 *
 * Copied from libzfs_import.c
 * diffs: kmem_alloc, kmem_free with size
 */
#ifndef DEBUG
static int
#else
int
#endif
zfs_boot_add_config(pool_list_t *pl, const char *path,
    int order, int num_labels, nvlist_t *config)
{
	uint64_t pool_guid, vdev_guid, top_guid, txg, state;
	pool_entry_t *pe;
	vdev_entry_t *ve;
	config_entry_t *ce;
	name_entry_t *ne;

#ifdef DEBUG
	printf("%s %p %s %d %d %p\n", __func__, pl, path,
	    order, num_labels, config);
#endif
	/*
	 * If this is a hot spare not currently in use or level 2 cache
	 * device, add it to the list of names to translate, but don't do
	 * anything else.
	 */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    &state) == 0 &&
	    (state == POOL_STATE_SPARE || state == POOL_STATE_L2CACHE) &&
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID, &vdev_guid) == 0) {
		if ((ne = (name_entry_t*) kmem_alloc(sizeof
		    (name_entry_t), KM_SLEEP)) == NULL) {
			return (-1);
		}
		bzero(ne, sizeof(name_entry_t));

		if ((ne->ne_name = spa_strdup(path)) == NULL) {
			kmem_free(ne, sizeof (name_entry_t));
			return (-1);
		}
		ne->ne_guid = vdev_guid;
		ne->ne_order = order;
		ne->ne_num_labels = num_labels;
		ne->ne_next = pl->names;
		pl->names = ne;
		return (0);
	}

	/*
	 * If we have a valid config but cannot read any of these fields, then
	 * it means we have a half-initialized label.  In vdev_label_init()
	 * we write a label with txg == 0 so that we can identify the device
	 * in case the user refers to the same disk later on.  If we fail to
	 * create the pool, we'll be left with a label in this state
	 * which should not be considered part of a valid pool.
	 */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &pool_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID,
	    &vdev_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_TOP_GUID,
	    &top_guid) != 0 ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    &txg) != 0 || txg == 0) {
		nvlist_free(config);
		return (0);
	}

	/*
	 * First, see if we know about this pool.  If not, then add it to the
	 * list of known pools.
	 */
	for (pe = pl->pools; pe != NULL; pe = pe->pe_next) {
		if (pe->pe_guid == pool_guid) {
			break;
		}
	}

	if (pe == NULL) {
		if ((pe = (pool_entry_t*) kmem_alloc(sizeof
		    (pool_entry_t), KM_SLEEP)) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		bzero(pe, sizeof(pool_entry_t));
		pe->pe_guid = pool_guid;
		pe->pe_next = pl->pools;
		pl->pools = pe;
	}

	/*
	 * Second, see if we know about this toplevel vdev.  Add it if its
	 * missing.
	 */
	for (ve = pe->pe_vdevs; ve != NULL; ve = ve->ve_next) {
		if (ve->ve_guid == top_guid) {
			break;
		}
	}

	if (ve == NULL) {
		if ((ve = (vdev_entry_t*) kmem_alloc(sizeof
		    (vdev_entry_t), KM_SLEEP)) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		bzero(ve, sizeof(vdev_entry_t));
		ve->ve_guid = top_guid;
		ve->ve_next = pe->pe_vdevs;
		pe->pe_vdevs = ve;
	}

	/*
	 * Third, see if we have a config with a matching transaction group.  If
	 * so, then we do nothing.  Otherwise, add it to the list of known
	 * configs.
	 */
	for (ce = ve->ve_configs; ce != NULL; ce = ce->ce_next) {
		if (ce->ce_txg == txg) {
			break;
		}
	}

	if (ce == NULL) {
		if ((ce = (config_entry_t*) kmem_alloc(sizeof
		    (config_entry_t), KM_SLEEP)) == NULL) {
			nvlist_free(config);
			return (-1);
		}
		bzero(ce, sizeof(config_entry_t));
		ce->ce_txg = txg;
		ce->ce_config = config;
		ce->ce_next = ve->ve_configs;
		ve->ve_configs = ce;
	} else {
		nvlist_free(config);
	}

	/*
	 * At this point we've successfully added our config to the list of
	 * known configs.  The last thing to do is add the vdev guid -> path
	 * mappings so that we can fix up the configuration as necessary before
	 * doing the import.
	 */
	if ((ne = (name_entry_t*) kmem_alloc(sizeof
	    (name_entry_t), KM_SLEEP)) == NULL) {
		return (-1);
	}
	bzero(ne, sizeof(name_entry_t));

	if ((ne->ne_name = spa_strdup(path)) == NULL) {
		kmem_free(ne, sizeof (name_entry_t));
		return (-1);
	}

	ne->ne_guid = vdev_guid;
	ne->ne_order = order;
	ne->ne_num_labels = num_labels;
	ne->ne_next = pl->names;
	pl->names = ne;

	return (0);
}

/*
 * libzfs_import used the libzfs handle and a zfs
 * command to issue tryimport in-kernel via ioctl.
 * This should leave config as-is, and return nvl.
 * Since zfs_boot is already in-kernel, duplicate
 * config into nvl, and call spa_tryimport on it.
 */
#ifndef DEBUG
static nvlist_t *
#else
nvlist_t *
#endif
zfs_boot_refresh_config(nvlist_t *config)
{
	nvlist_t *nvl = 0;

#if 0
	/* Allocate a new nvlist */
	nvl = (nvlist_t**) kmem_alloc(sizeof (nvlist_t *),
	    KM_SLEEP);
	if (nvl == NULL) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_refresh_config",
		    "couldn't allocate nvlist nvl");
#endif
		return (NULL);
	}
#endif

	/* Duplicate config into nvl */
	if (nvlist_dup(config, &nvl, KM_SLEEP) != 0) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_refresh_config",
		    "couldn't nvlist_dup config to nvl");
#endif
		return (NULL);
	}

	/* Call tryimport and return nvl or NULL */
	if (spa_tryimport(nvl) == 0) {
		return (nvl);
	}

	return (NULL);

#if 0
	nvlist_t *nvl;
	int err;
	zfs_cmd_t zc = {"\0"};

	if (zcmd_write_conf_nvlist(hdl, &zc, config) != 0)
		return (NULL);

	if (zcmd_alloc_dst_nvlist(hdl, &zc,
	    zc.zc_nvlist_conf_size * 2) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	while ((err = zfs_ioctl(hdl, ZFS_IOC_POOL_TRYIMPORT,
	    &zc)) != 0 && errno == ENOMEM) {
		if (zcmd_expand_dst_nvlist(hdl, &zc) != 0) {
			zcmd_free_nvlists(&zc);
			return (NULL);
		}
	}

	if (err) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	if (zcmd_read_dst_nvlist(hdl, &zc, &nvl) != 0) {
		zcmd_free_nvlists(&zc);
		return (NULL);
	}

	zcmd_free_nvlists(&zc);
	return (nvl);
#endif
}

/*
 * Determine if the vdev id is a hole in the namespace.
 */
#ifndef DEBUG
static boolean_t
#else
boolean_t
#endif
zfs_boot_vdev_is_hole(uint64_t *hole_array, uint_t holes, uint_t id)
{
	int c;

	for (c = 0; c < holes; c++) {

		/* Top-level is a hole */
		if (hole_array[c] == id)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Convert our list of pools into the definitive set of configurations.  We
 * start by picking the best config for each toplevel vdev.  Once that's done,
 * we assemble the toplevel vdevs into a full config for the pool.  We make a
 * pass to fix up any incorrect paths, and then add it to the main list to
 * return to the user.
 */
#ifndef DEBUG
static nvlist_t *
#else
nvlist_t *
#endif
zfs_boot_get_configs(pool_list_t *pl, boolean_t active_ok)
{
	pool_entry_t *pe;
	vdev_entry_t *ve;
	config_entry_t *ce;
	nvlist_t *ret = NULL, *config = NULL, *tmp = NULL, *nvtop, *nvroot;
	nvlist_t **spares, **l2cache;
	uint_t i, nspares, nl2cache;
	boolean_t config_seen;
	uint64_t best_txg;
	char *name, *hostname = NULL;
	uint64_t guid;
	uint_t children = 0;
	nvlist_t **child = NULL;
	uint_t holes;
	uint64_t *hole_array, max_id;
	uint_t c;
#if 0
	boolean_t isactive;
#endif
	uint64_t hostid;
	nvlist_t *nvl;
	boolean_t valid_top_config = B_FALSE;

	if (nvlist_alloc(&ret, 0, 0) != 0)
		goto nomem;

	for (pe = pl->pools; pe != NULL; pe = pe->pe_next) {
		uint64_t id, max_txg = 0;

		if (nvlist_alloc(&config, NV_UNIQUE_NAME, 0) != 0)
			goto nomem;
		config_seen = B_FALSE;

		/*
		 * Iterate over all toplevel vdevs.  Grab the pool configuration
		 * from the first one we find, and then go through the rest and
		 * add them as necessary to the 'vdevs' member of the config.
		 */
		for (ve = pe->pe_vdevs; ve != NULL; ve = ve->ve_next) {

			/*
			 * Determine the best configuration for this vdev by
			 * selecting the config with the latest transaction
			 * group.
			 */
			best_txg = 0;
			for (ce = ve->ve_configs; ce != NULL;
			    ce = ce->ce_next) {

				if (ce->ce_txg > best_txg) {
					tmp = ce->ce_config;
					best_txg = ce->ce_txg;
				}
			}

			/*
			 * We rely on the fact that the max txg for the
			 * pool will contain the most up-to-date information
			 * about the valid top-levels in the vdev namespace.
			 */
			if (best_txg > max_txg) {
				(void) nvlist_remove(config,
				    ZPOOL_CONFIG_VDEV_CHILDREN,
				    DATA_TYPE_UINT64);
				(void) nvlist_remove(config,
				    ZPOOL_CONFIG_HOLE_ARRAY,
				    DATA_TYPE_UINT64_ARRAY);

				max_txg = best_txg;
				hole_array = NULL;
				holes = 0;
				max_id = 0;
				valid_top_config = B_FALSE;

				if (nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_VDEV_CHILDREN, &max_id) == 0) {
					verify(nvlist_add_uint64(config,
					    ZPOOL_CONFIG_VDEV_CHILDREN,
					    max_id) == 0);
					valid_top_config = B_TRUE;
				}

				if (nvlist_lookup_uint64_array(tmp,
				    ZPOOL_CONFIG_HOLE_ARRAY, &hole_array,
				    &holes) == 0) {
					verify(nvlist_add_uint64_array(config,
					    ZPOOL_CONFIG_HOLE_ARRAY,
					    hole_array, holes) == 0);
				}
			}

			if (!config_seen) {
				/*
				 * Copy the relevant pieces of data to the pool
				 * configuration:
				 *
				 *	version
				 *	pool guid
				 *	name
				 *	pool txg (if available)
				 *	comment (if available)
				 *	pool state
				 *	hostid (if available)
				 *	hostname (if available)
				 */
				uint64_t state, version, pool_txg;
				char *comment = NULL;

				version = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_VERSION);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_VERSION, version);
				guid = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_GUID);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_GUID, guid);
				name = fnvlist_lookup_string(tmp,
				    ZPOOL_CONFIG_POOL_NAME);
				fnvlist_add_string(config,
				    ZPOOL_CONFIG_POOL_NAME, name);
				if (nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_TXG, &pool_txg) == 0)
					fnvlist_add_uint64(config,
					    ZPOOL_CONFIG_POOL_TXG, pool_txg);

				if (nvlist_lookup_string(tmp,
				    ZPOOL_CONFIG_COMMENT, &comment) == 0)
					fnvlist_add_string(config,
					    ZPOOL_CONFIG_COMMENT, comment);

				state = fnvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_POOL_STATE);
				fnvlist_add_uint64(config,
				    ZPOOL_CONFIG_POOL_STATE, state);

				hostid = 0;
				if (nvlist_lookup_uint64(tmp,
				    ZPOOL_CONFIG_HOSTID, &hostid) == 0) {
					fnvlist_add_uint64(config,
					    ZPOOL_CONFIG_HOSTID, hostid);
					hostname = fnvlist_lookup_string(tmp,
					    ZPOOL_CONFIG_HOSTNAME);
					fnvlist_add_string(config,
					    ZPOOL_CONFIG_HOSTNAME, hostname);
				}

				config_seen = B_TRUE;
			}

			/*
			 * Add this top-level vdev to the child array.
			 */
			verify(nvlist_lookup_nvlist(tmp,
			    ZPOOL_CONFIG_VDEV_TREE, &nvtop) == 0);
			verify(nvlist_lookup_uint64(nvtop, ZPOOL_CONFIG_ID,
			    &id) == 0);

			if (id >= children) {
				nvlist_t **newchild;

				newchild = (nvlist_t**) kmem_alloc((id + 1) *
				    sizeof (nvlist_t *), KM_SLEEP);
				if (newchild == NULL)
					goto nomem;

				for (c = 0; c < children; c++)
					newchild[c] = child[c];

				kmem_free(child, children * sizeof (nvlist_t *));
				child = newchild;
				children = id + 1;
			}
			if (nvlist_dup(nvtop, &child[id], 0) != 0)
				goto nomem;

		}

		/*
		 * If we have information about all the top-levels then
		 * clean up the nvlist which we've constructed. This
		 * means removing any extraneous devices that are
		 * beyond the valid range or adding devices to the end
		 * of our array which appear to be missing.
		 */
		if (valid_top_config) {
			if (max_id < children) {
				for (c = max_id; c < children; c++)
					nvlist_free(child[c]);
				children = max_id;
			} else if (max_id > children) {
				nvlist_t **newchild;

				newchild = (nvlist_t**) kmem_alloc((max_id) *
				    sizeof (nvlist_t *), KM_SLEEP);
				if (newchild == NULL)
					goto nomem;

				for (c = 0; c < children; c++)
					newchild[c] = child[c];

				kmem_free(child, children * sizeof (nvlist_t *));
				child = newchild;
				children = max_id;
			}
		}

		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		/*
		 * The vdev namespace may contain holes as a result of
		 * device removal. We must add them back into the vdev
		 * tree before we process any missing devices.
		 */
		if (holes > 0) {
			ASSERT(valid_top_config);

			for (c = 0; c < children; c++) {
				nvlist_t *holey;

				if (child[c] != NULL ||
				    !zfs_boot_vdev_is_hole(hole_array, holes, c))
					continue;

				if (nvlist_alloc(&holey, NV_UNIQUE_NAME,
				    0) != 0)
					goto nomem;

				/*
				 * Holes in the namespace are treated as
				 * "hole" top-level vdevs and have a
				 * special flag set on them.
				 */
				if (nvlist_add_string(holey,
				    ZPOOL_CONFIG_TYPE,
				    VDEV_TYPE_HOLE) != 0 ||
				    nvlist_add_uint64(holey,
				    ZPOOL_CONFIG_ID, c) != 0 ||
				    nvlist_add_uint64(holey,
				    ZPOOL_CONFIG_GUID, 0ULL) != 0)
					goto nomem;
				child[c] = holey;
			}
		}

		/*
		 * Look for any missing top-level vdevs.  If this is the case,
		 * create a faked up 'missing' vdev as a placeholder.  We cannot
		 * simply compress the child array, because the kernel performs
		 * certain checks to make sure the vdev IDs match their location
		 * in the configuration.
		 */
		for (c = 0; c < children; c++) {
			if (child[c] == NULL) {
				nvlist_t *missing;
				if (nvlist_alloc(&missing, NV_UNIQUE_NAME,
				    0) != 0)
					goto nomem;
				if (nvlist_add_string(missing,
				    ZPOOL_CONFIG_TYPE,
				    VDEV_TYPE_MISSING) != 0 ||
				    nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_ID, c) != 0 ||
				    nvlist_add_uint64(missing,
				    ZPOOL_CONFIG_GUID, 0ULL) != 0) {
					nvlist_free(missing);
					goto nomem;
				}
				child[c] = missing;
			}
		}

		/*
		 * Put all of this pool's top-level vdevs into a root vdev.
		 */
		if (nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) != 0)
			goto nomem;
		if (nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE,
		    VDEV_TYPE_ROOT) != 0 ||
		    nvlist_add_uint64(nvroot, ZPOOL_CONFIG_ID, 0ULL) != 0 ||
		    nvlist_add_uint64(nvroot, ZPOOL_CONFIG_GUID, guid) != 0 ||
		    nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
		    child, children) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}

		for (c = 0; c < children; c++)
			nvlist_free(child[c]);
		kmem_free(child, children * sizeof (nvlist_t *));
		children = 0;
		child = NULL;

		/*
		 * Go through and fix up any paths and/or devids based on our
		 * known list of vdev GUID -> path mappings.
		 */
		if (zfs_boot_fix_paths(nvroot, pl->names) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}

		/*
		 * Add the root vdev to this pool's configuration.
		 */
		if (nvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    nvroot) != 0) {
			nvlist_free(nvroot);
			goto nomem;
		}
		nvlist_free(nvroot);

		/*
		 * zdb uses this path to report on active pools that were
		 * imported or created using -R.
		 */
		if (active_ok)
			goto add_pool;

#if 0
/*
 * For root-pool import, no pools are active yet.
 * Pool name and guid were looked up from the config and only used here.
 * (Later we lookup the pool name for a separate test).
 */
		/*
		 * Determine if this pool is currently active, in which case we
		 * can't actually import it.
		 */
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &guid) == 0);

		if (zfs_boot_pool_active(name, guid, &isactive) != 0)
			goto error;

		if (isactive) {
			nvlist_free(config);
			config = NULL;
			continue;
		}
#endif

		if ((nvl = zfs_boot_refresh_config(config)) == NULL) {
			nvlist_free(config);
			config = NULL;
			continue;
		}

		nvlist_free(config);
		config = nvl;

		/*
		 * Go through and update the paths for spares, now that we have
		 * them.
		 */
		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) == 0);
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
		    &spares, &nspares) == 0) {
			for (i = 0; i < nspares; i++) {
				if (zfs_boot_fix_paths(spares[i], pl->names) != 0)
					goto nomem;
			}
		}

		/*
		 * Update the paths for l2cache devices.
		 */
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_L2CACHE,
		    &l2cache, &nl2cache) == 0) {
			for (i = 0; i < nl2cache; i++) {
				if (zfs_boot_fix_paths(l2cache[i], pl->names) != 0)
					goto nomem;
			}
		}

		/*
		 * Restore the original information read from the actual label.
		 */
		(void) nvlist_remove(config, ZPOOL_CONFIG_HOSTID,
		    DATA_TYPE_UINT64);
		(void) nvlist_remove(config, ZPOOL_CONFIG_HOSTNAME,
		    DATA_TYPE_STRING);
		if (hostid != 0) {
			verify(nvlist_add_uint64(config, ZPOOL_CONFIG_HOSTID,
			    hostid) == 0);
			verify(nvlist_add_string(config, ZPOOL_CONFIG_HOSTNAME,
			    hostname) == 0);
		}

add_pool:
		/*
		 * Add this pool to the list of configs.
		 */
		verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
		    &name) == 0);
		if (nvlist_add_nvlist(ret, name, config) != 0)
			goto nomem;

		nvlist_free(config);
		config = NULL;
	}

	return (ret);

nomem:
#ifdef DEBUG
	printf("zfs_boot_get_configs failed to allocate memory\n");
#endif
#if 0
/* Only used by isactive check */
error:
#endif
	if (config) nvlist_free(config);
	if (ret) nvlist_free(ret);
	for (c = 0; c < children; c++)
		nvlist_free(child[c]);
	if (children > 0) {
		kmem_free(child, children * sizeof (nvlist_t *));
	}

	return (NULL);
}

/*
 * Return the offset of the given label.
 */
#ifndef DEBUG
static uint64_t
#else
uint64_t
#endif
zfs_boot_label_offset(uint64_t size, int l)
{
	ASSERT(P2PHASE_TYPED(size, sizeof (vdev_label_t), uint64_t) == 0);
	return (l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : size - VDEV_LABELS * sizeof (vdev_label_t)));
}

/*
 * Given an IOMedia, read the label information and return an nvlist
 * describing the configuration, if there is one.  The number of valid
 * labels found will be returned in num_labels when non-NULL.
 */
#ifndef DEBUG
static int
#else
int
#endif
zfs_boot_read_label(IOService *zfs_hl, IOMedia *media, nvlist_t **config, int *num_labels)
{
	uint64_t mediaSize;
	uint64_t nread = 0;
	int l, count = 0;
	vdev_label_t *label;
	nvlist_t *expected_config = NULL;
	uint64_t expected_guid = 0, size, labelsize;
	IOReturn ret;
	IOMemoryDescriptor *buffer = NULL;
#if 0
#ifdef DEBUG
	boolean_t copyout = B_FALSE;
#endif
#endif

	*config = NULL;

	/* Verify IOMedia pointer and device size */
	if (!media || (mediaSize = media->getSize()) == 0) {
#ifdef DEBUG
		printf("zfs_boot_read_label: couldn't get media or size\n");
#endif
		return (-1);
	}

	/* Determine vdev label size and aligned vdev size */
	labelsize = sizeof (vdev_label_t);
	size = P2ALIGN_TYPED(mediaSize, labelsize, uint64_t);

	/* Allocate a buffer to read labels into */
	label = (vdev_label_t*) kmem_alloc(labelsize, KM_SLEEP);
	if (!label) {
#ifdef DEBUG
		printf("zfs_boot_read_label: couldn't allocate label for read\n");
#endif
		return (-1);
	}

	/* Allocate a memory descriptor with the label pointer */
	buffer = IOMemoryDescriptor::withAddress((void*)label, labelsize,
	    kIODirectionIn);
#if 0
#ifndef DEBUG
#else
	buffer = IOBufferMemoryDescriptor::withCapacity(labelsize,
	    kIODirectionIn, false);
	copyout = B_TRUE;
#endif
#endif

	/* Verify buffer was allocated */
	if (!buffer || (buffer->getLength() != labelsize)) {
#ifdef DEBUG
		printf("zfs_boot_read_label: couldn't allocate buffer for read\n");
#endif
		goto error;
	}

	/* Open the device for reads */
	if (false == media->IOMedia::open(zfs_hl, 0,
	    kIOStorageAccessReader)) {
#ifdef DEBUG
		printf("zfs_boot_read_label: media open failed\n");
#endif
		goto error;
	}

	/* Read all four vdev labels */
	for (l = 0; l < VDEV_LABELS; l++) {
		uint64_t state, guid, txg;

		/* Zero the label buffer */
		bzero(label, labelsize);

		/* Prepare the buffer for IO */
		buffer->prepare(kIODirectionIn);

		/* Read a label from the specified offset */
		ret = media->IOMedia::read(zfs_hl,
		    zfs_boot_label_offset(size, l),
		    buffer, 0, &nread);

		/* Call the buffer completion */
		buffer->complete();

		/* Skip failed reads, try next label */
		if (ret != kIOReturnSuccess) {
#ifdef DEBUG
			printf("%s %s\n", "zfs_boot_read_label",
			    "media->read failed");
#endif
			continue;
		}

		/* Skip incomplete reads, try next label */
		if (nread < labelsize) {
#ifdef DEBUG
			printf("zfs_boot_read_label: nread %llu / %llu\n",
			    nread, labelsize);
#endif
			continue;
		}

#if 0
#ifdef DEBUG
		if (copyout) {
			if (kIOReturnSuccess != (buffer->prepare(kIODirectionOut))) {
				printf("zfs_boot_read_label: prepare (out) failed\n");
			}
			if (labelsize != (buffer->readBytes(0,
			    (void*)label, labelsize))) {
				printf("zfs_boot_read_label: readBytes failed\n");
			}
			buffer->complete(kIODirectionOut);
		}
#endif
#endif

		/* Skip invalid labels that can't be unpacked */
		if (nvlist_unpack(label->vl_vdev_phys.vp_nvlist,
		    sizeof (label->vl_vdev_phys.vp_nvlist), config, 0) != 0) {
			continue;
		}

		/* Verify GUID */
		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_GUID,
		    &guid) != 0 || guid == 0) {
#ifdef DEBUG
			printf("zfs_boot_read_label: nvlist_lookup guid failed %llu\n", guid);
#endif
			nvlist_free(*config);
			continue;
		}

		/* Verify vdev state */
		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_STATE,
		    &state) != 0 || state > POOL_STATE_L2CACHE) {
#ifdef DEBUG
			printf("zfs_boot_read_label: nvlist_lookup state failed %llu\n", state);
#endif
			nvlist_free(*config);
			continue;
		}

		/* Verify txg number */
		if (state != POOL_STATE_SPARE && state != POOL_STATE_L2CACHE &&
		    (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0)) {
#ifdef DEBUG
			printf("zfs_boot_read_label: nvlist_lookup txg failed %llu\n", txg);
#endif
			nvlist_free(*config);
			continue;
		}

		/* Increment count for first match, or if guid matches */
		if (expected_guid) {
			if (expected_guid == guid)
				count++;

			nvlist_free(*config);
		} else {
			expected_config = *config;
			expected_guid = guid;
			count++;
		}
	}

	/* Close IOMedia */
	media->close(zfs_hl);

	/* Copy out the config and number of labels */
	if (num_labels != NULL)
		*num_labels = count;
	*config = expected_config;

	/* Clean up */
	if (buffer) {
		buffer->release();
		buffer = 0;
	}
	if (label) {
		kmem_free(label, labelsize);
		label = 0;
	}

	return (0);

error:
	/* Clean up */
	if (buffer) {
		buffer->release();
		buffer = 0;
	}
	if (label) {
		kmem_free(label, labelsize);
		label = 0;
	}

	return (-1);
}

#ifndef DEBUG
static bool
#else
bool
#endif
zfs_boot_probe_media(void* target, void* refCon,
    IOService* newService, IONotifier* notifier)
{
	IOMedia *media;
	OSObject *isLeaf;
	OSString *ospath;
	uint64_t mediaSize;
	pool_list_t *pools = (pool_list_t*) refCon;

	/* Verify pool list can be cast */
	if (!pools) {
#ifdef DEBUG
		printf("%s %p %s\n", "zfs_boot_probe_media",
		    refCon, "couldn't be cast as pool_list_t*");
#endif
		return (false);
	}

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_media terminating 1");
#endif
		return (false);
	}

	/* Validate pool name */
	if (!pools->pool_name || strlen(pools->pool_name) == 0) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_media",
		    "no pool name specified");
#endif
		return (false);
	}


#ifdef DEBUG
	/* Should never happen */
	if (!newService) {
		printf("%s %s\n", "zfs_boot_probe_media",
		    "called with null newService");
		return (false);
	}

#endif

	/* Get the parent IOMedia device */
	media = OSDynamicCast(IOMedia, newService->getProvider());

	if (!media) {
#ifdef DEBUG
		printf("%s %p->%p %s\n", "zfs_boot_probe_media",
		    newService, newService->getProvider(),
		    "couldn't be cast as IOMedia");
#endif
		return (false);
	}

	isLeaf = media->getProperty(kIOMediaLeafKey);
	if (!isLeaf) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_media",
		    "skipping non-leaf");
#endif
		goto out;
	}

	/*
	 * XXX Alternate
	 *
	mediaSize = media->getProperty(kIOMediaSizeKey);
	 */
	mediaSize = media->getSize();
	if (mediaSize < SPA_MINDEVSIZE) {
#ifdef DEBUG
		printf("%s %s %llu\n", "zfs_boot_probe_media",
		    "skipping device with size", mediaSize);
#endif
		goto out;
	}

	ospath = OSDynamicCast(OSString, media->getProperty(
	    kIOBSDNameKey, gIOServicePlane,
	    kIORegistryIterateRecursively));
	if (!ospath || (ospath->getLength() == 0)) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_media",
		    "skipping device with no bsd disk node");
#endif
		goto out;
	}

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_media terminating 2");
#endif
		goto out;
	}


	/* Take pool_list lock */
	IOLockLock(pools->lock);

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_media terminating 3");
#endif
		/* Unlock the pool list lock */
		IOLockUnlock(pools->lock);
		goto out;
	}

	/* Add this IOMedia to the disk set */
	pools->disks->setObject(media);

	/* Unlock the pool list lock */
	IOLockUnlock(pools->lock);

	/* Wakeup zfs_boot_import_thread */
	IOLockWakeup(pools->lock, (void*)pools, true);

out:
	media = 0;
	return (true);
}

#ifndef DEBUG
static bool
#else
bool
#endif
zfs_boot_probe_disk(pool_list_t *pools, IOMedia *media)
{
	OSString *ospath;
	char *path, *pname;
	uint64_t this_guid;
	int num_labels, err, len = 0;
	nvlist_t *config;
	boolean_t matched = B_FALSE;

#ifdef DEBUG
	/* Should always be valid */
	if (!media) {
		printf("%s %s\n", "zfs_boot_probe_disk",
		    "called with null media");
		return (false);
	}
#endif
	ASSERT3U(media, !=, NULL);

	/* Verify pool list can be cast */
	if (!pools) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_disk",
		    "missing pool_list");
#endif
		return (false);
	}

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_disk terminating 1");
#endif
		return (false);
	}

	/* Validate pool name */
	if (!pools->pool_name || strlen(pools->pool_name) == 0) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_disk",
		    "no pool name specified");
#endif
		return (false);
	}

	/* Get the BSD name as a C string */
	ospath = OSDynamicCast(OSString, media->getProperty(
	    kIOBSDNameKey, gIOServicePlane,
	    kIORegistryIterateRecursively));
	if (!ospath || ospath->getLength() == 0) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_probe_disk",
		    "skipping device with no bsd disk node");
#endif
		ospath = 0;
		return (false);
	}

	/* Allocate room for "/dev/" + "diskNsN" + '\0' */
	len = 6 + ospath->getLength();
	path = (char*) kmem_alloc(len, KM_SLEEP);
	if (!path) {
#ifdef DEBUG
		printf("zfs_boot_probe_disk couldn't allocate path\n");
#endif
		ospath = 0;
		return (false);
	}

	/* "/dev/" is 5 characters, plus null character */
	snprintf(path, len, "/dev/%s", ospath->getCStringNoCopy());
	ospath = 0;
#ifdef DEBUG
	printf("zfs_boot_probe_disk: len %d path %s\n", len, path);
#endif

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_disk terminating 2");
#endif
		kmem_free(path, len);
		return (false);
	}

	/* Read vdev labels, if any */
	err = zfs_boot_read_label(pools->zfs_hl, media,
	    &config, &num_labels);

	/* Skip disks with no labels */
	if (err != 0 || num_labels == 0 || !config) {
		goto out;
	}

	/* Lookup pool name */
	if (pools->pool_name != NULL &&
	    (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &pname) == 0)) {
#ifdef DEBUG
		printf("zfs_boot_probe_disk: found pool %s {%s}?\n",
		    pname, pools->pool_name);
#endif
		/* Compare with pool_name */
		if (strncmp(pools->pool_name, pname,
		    strlen(pools->pool_name)) == 0) {
			matched = B_TRUE;
		}
	/* Compare with pool_guid */
	} else if (pools->pool_guid != 0) {
		matched = nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_GUID,
		    &this_guid) == 0 &&
		    pools->pool_guid == this_guid;
	}

	/* Skip non-matches */
	if (!matched) {
		nvlist_free(config);
		config = NULL;
		goto out;
	}

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_probe_disk terminating 3");
#endif
		goto out;
	}

	/*
	 * Add this config to the pool list.
	 * Always assigns order 1 since all disks are
	 * referenced by /dev/diskNsN
	 */
#ifdef DEBUG
	printf("zfs_boot_probe_disk: add_config %s\n", path);
#endif
	if (zfs_boot_add_config(pools, path, 1,
	    num_labels, config) != 0) {
		printf("%s %s\n", "zfs_boot_probe_disk",
		    "couldn't add config to pool list");
	}

out:
	/* Clean up */
	if (path && len > 0) {
		kmem_free(path, len);
	}
	return (true);
}

#ifndef DEBUG
static void
#else
void
#endif
zfs_boot_free()
{
	pool_entry_t *pe, *penext;
	vdev_entry_t *ve, *venext;
	config_entry_t *ce, *cenext;
	name_entry_t *ne, *nenext;
	pool_list_t *pools = zfs_boot_pool_list;

	/* Verify pool list can be cast */
	if (!pools) {
#ifdef DEBUG
		printf("zfs_boot_free: no pool_list to clear\n");
#endif
		return;
	}

	/* Clear global ptr */
	zfs_boot_pool_list = 0;

	pools->terminating = ZFS_BOOT_TERMINATING;

	/* Remove IONotifier (waits for tasks to complete) */
	if (pools->notifier) {
		pools->notifier->remove();
		pools->notifier = 0;
	}

	/* Release the lock */
	if (pools->lock) {
		IOLockFree(pools->lock);
		pools->lock = 0;
	}

	/* Release the disk set */
	if (pools->disks) {
		pools->disks->flushCollection();
		pools->disks->release();
		pools->disks = 0;
	}

	/* Clear the zfs IOService handle */
	if (pools->zfs_hl) {
		pools->zfs_hl = 0;
	}

	/* Free the pool_name string */
	if (pools->pool_name) {
		kmem_free(pools->pool_name, strlen(pools->pool_name) + 1);
		pools->pool_name = 0;
	}

	/* Clear the pool config list */
	for (pe = pools->pools; pe != NULL; pe = penext) {
		/* Clear the vdev list */
		penext = pe->pe_next;
		for (ve = pe->pe_vdevs; ve != NULL; ve = venext) {
			/* Clear the vdev config list */
			venext = ve->ve_next;
			for (ce = ve->ve_configs; ce != NULL; ce = cenext) {
				cenext = ce->ce_next;
				if (ce->ce_config)
					nvlist_free(ce->ce_config);
				kmem_free(ce, sizeof (config_entry_t));
			}
			kmem_free(ve, sizeof (vdev_entry_t));
		}
		kmem_free(pe, sizeof (pool_entry_t));
	}
	pools->pools = 0;

	/* Clear the vdev name list */
	for (ne = pools->names; ne != NULL; ne = nenext) {
		nenext = ne->ne_next;
		if (ne->ne_name)
			spa_strfree(ne->ne_name);
		kmem_free(ne, sizeof (name_entry_t));
	}
	pools->names = 0;

	/* Finally, free the pool list struct */
	kmem_free(pools, sizeof (pool_list_t));
	pools = 0;
}

void
zfs_boot_fini()
{
	IOLock *lock;
	pool_list_t *pools = zfs_boot_pool_list;

	if (!pools) {
#ifdef DEBUG
		printf("zfs_boot_fini: no pool_list to clear\n");
#endif
		return;
	}

	/* Set terminating flag */
	if (false == OSCompareAndSwap64(ZFS_BOOT_ACTIVE,
	    ZFS_BOOT_TERMINATING, &(pools->terminating))) {
#ifdef DEBUG
		printf("already terminating? %llu\n",
		    pools->terminating);
#endif
	}

	/* Save the pool lock pointer */
	lock = pools->lock;
	if (lock) {
		/* Take pool list lock */
		//IOLockLock(lock);

		/*
		if (false == OSCompareAndSwap64(ZFS_BOOT_ACTIVE,
		    ZFS_BOOT_TERMINATING, &(pools->terminating))) {
		}
		*/

		/* Unlock pool list lock */
		//IOLockUnlock(lock);

		/* Wakeup zfs_boot_import_thread */
		IOLockWakeup(lock, (void*)pools, true);
	}

	/* Clean up */
	lock = 0;
	pools = 0;
}

#ifndef DEBUG
static void
#else
void
#endif
zfs_boot_import_thread(void *arg)
{
	nvlist_t *configs, *nv, *newnv;
	nvpair_t *elem;
	uint64_t pool_state;
	boolean_t pool_imported = B_FALSE;
	OSSet *disks, *new_set = 0;
	OSCollectionIterator *iter = 0;
	OSObject *next;
	IOMedia *media;
	pool_list_t *pools = (pool_list_t*)arg;

	/* Verify pool list coult be cast */
	ASSERT3U(pools, !=, 0);
	if (!pools) {
		printf("%s %p %s\n", "zfs_boot_import_thread",
		    arg, "couldn't be cast as pool_list_t*");
		return;
	}

	/* Abort early */
	if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
		printf("%s\n", "zfs_boot_import_thread terminating 1");
#endif
		goto out_unlocked;
	}

	new_set = OSSet::withCapacity(1);
	/* To swap with pools->disks while locked */
	if (!new_set) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_import_thread",
		    "couldn't allocate new_set");
#endif
		goto out_unlocked;
	}

	/* Take pool list lock */
	IOLockLock(pools->lock);

	/* Check for work, then sleep on the lock */
	do {
		/* Abort early */
		if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
			printf("%s\n", "zfs_boot_import_thread terminating 2");
#endif
			goto out_locked;
		}

		/* Check for work */
		if (pools->disks->getCount() == 0) {
#ifdef DEBUG
			printf("%s %s\n", "zfs_boot_import_thread",
			    "no disks to check");
#endif
			goto next_locked;
		}

		/* Swap full set with a new empty one */
		ASSERT3U(new_set, !=, 0);
		disks = pools->disks;
		pools->disks = new_set;
		new_set = 0;

		/* Release pool list lock */
		IOLockUnlock(pools->lock);

		/* Create an iterator over the objects in the set */
		iter = OSCollectionIterator::withCollection(disks);

		/* couldn't be initialized */
		if (!iter) {
#ifdef DEBUG
			printf("%s %s %d %s\n", "zfs_boot_import_thread",
			    "couldn't get iterator from collection",
			    disks->getCount(), "disks skipped");
#endif
			/* Merge disks back into pools->disks */
			IOLockLock(pools->lock);
			pools->disks->merge(disks);
			IOLockUnlock(pools->lock);

			/* Swap 'disks' back to new_set */
			disks->flushCollection();
			new_set = disks;
			disks = 0;

			continue;
		}

		/* Iterate over all disks */
		while ((next = iter->getNextObject()) != NULL) {
			/* Cast each IOMedia object */
			media = OSDynamicCast(IOMedia, next);

			if (!media) {
#ifdef DEBUG
				printf("%s %s %p\n", "zfs_boot_import_thread",
				    "couldn't cast IOMedia", next);
#endif
				continue;
			}

			/* Check this IOMedia device for a vdev label */
			if (!zfs_boot_probe_disk(pools, media)) {
#ifdef DEBUG
				printf("%s %s %p\n", "zfs_boot_import_thread",
				    "couldn't probe disk", next);
#endif
				continue;
			}
		}

		/* Clean up */
		media = 0;
		iter->release();
		iter = 0;

		/* Swap 'disks' back to new_set */
		disks->flushCollection();
		new_set = disks;
		disks = 0;

		/* Abort early */
		if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
			printf("%s\n", "zfs_boot_import_thread terminating 3");
#endif
			goto out_unlocked;
		}

		/* Generate a list of pool configs to import */
		configs = zfs_boot_get_configs(pools, true);

		/* Abort early */
		if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
			printf("%s\n", "zfs_boot_import_thread terminating 4");
#endif
			goto out_unlocked;
		}

		/* Iterate over the nvlists (stored as nvpairs in an nvlist) */
		elem = NULL;
		while ((elem = nvlist_next_nvpair(configs, elem)) != NULL) {
			/* Cast the nvpair back to nvlist */
			nv = NULL;
			verify(nvpair_value_nvlist(elem, &nv) == 0);

			/* Check vdev state */
			verify(nvlist_lookup_uint64(nv, ZPOOL_CONFIG_POOL_STATE,
			    &pool_state) == 0);
			if (pool_state == POOL_STATE_DESTROYED) {
#ifdef DEBUG
				printf("%s %s\n", "zfs_boot_import_thread",
				    "skipping destroyed pool\n");
#endif
				continue;
			}

			/* Abort early */
			if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
				printf("%s\n", "zfs_boot_import_thread terminating 5");
#endif
				goto out_unlocked;
			}

			/* Try import */
			newnv = NULL;
			newnv = spa_tryimport(nv);
			if (newnv) {
#ifdef DEBUG
				printf("%s newnv: %p\n", __func__, newnv);
#endif
				/* Do import */
				pool_imported = (spa_import(pools->pool_name,
				    newnv, 0, 0) == 0 );
				//pool_imported = spa_import_rootpool(nv);
			} else {
#ifdef DEBUG
				printf("%s no newnv returned\n", __func__);
#endif
			}

#ifdef DEBUG
			printf("%s spa_import returned %d\n", __func__,
			    pool_imported);
#endif
			if (pool_imported) {
#ifdef DEBUG
				printf("%s imported pool\n", __func__);
#endif
				goto out_unlocked;
			}
		}

		/* Retake pool list lock */
		IOLockLock(pools->lock);

next_locked:
		/* Check for work */
		if (pools->disks->getCount() != 0) {
			continue;
		}

		/* Abort early */
		if (pools->terminating != ZFS_BOOT_ACTIVE) {
#ifdef DEBUG
			printf("%s\n", "zfs_boot_import_thread terminating 6");
#endif
			goto out_locked;
		}

#ifdef DEBUG
		printf("zfs_boot_import_thread: sleeping on lock\n");
#endif
		/* Sleep on lock, thread is resumed with lock held */
		IOLockSleep(pools->lock, (void*)pools, 0);

	/* Loop forever */
	} while (true);

out_locked:
	/* Unlock pool list lock */
	IOLockUnlock(pools->lock);

out_unlocked:
	/* Cleanup new_set */
	if (new_set) {
		new_set->flushCollection();
		new_set->release();
		new_set = 0;
	}

	/* Teardown pool list, lock, etc */
	zfs_boot_free();

	return;	/* taskq_dispatch */
#if 0
	thread_exit();	/* thread_create */
#endif
}

#ifndef DEBUG
static bool
#else
bool
#endif
zfs_boot_check_mountroot(char **pool_name, uint64_t *pool_guid)
{
	/*
	 * Check if the kext is loading during early boot
	 * and/or check if root is mounted (IORegistry?)
	 * Use PE Boot Args to determine the root pool name.
	 */
	char *zfs_boot;
	char *split;
	uint64_t len;
	bool result = false;
	uint64_t uptime =   0;


	if (!pool_name || !pool_guid) {
#ifdef DEBUG
		printf("%s %s\n", "zfs_boot_check_mountroot",
		    "invalid pool_name or pool_guid ptr");
#endif
		return (false);
	}

	/* Ugly hack to determine if this is early boot */
	clock_get_uptime(&uptime); /* uptime since boot in nanoseconds */

zfs_boot_log("%s %llu\n", "ZFS: zfs_check_mountroot: uptime:", uptime);

/* XXX Debug build skips early-boot check */
#ifndef DEBUG
	/* 3 billion nanoseconds ~= 3 seconds */
	//if (uptime >= 3LLU<<30) {
	/* 60 billion nanoseconds ~= 60 seconds */
	if (uptime >= 7LLU<<33) {
		zfs_boot_log("%s\n", "ZFS: zfs_check_mountroot: Already booted");

		return (false);
	} else {
		zfs_boot_log("%s\n", "ZFS: zfs_check_mountroot: Boot time");
	}
#endif

	zfs_boot = (char*) kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (!zfs_boot) {
#ifdef DEBUG
		printf("zfs_boot_check_mountroot couldn't allocate zfs_boot\n");
#endif
		return (false);
	}

	result = PE_parse_boot_argn("zfs_boot", zfs_boot, MAXPATHLEN);
	// zfs_boot_log( "Raw zfs_boot: [%llu] {%s}\n",
	//    (uint64_t)strlen(zfs_boot), zfs_boot);

	result = (result && (zfs_boot != 0) && strlen(zfs_boot) > 0);

	if (!result) {
		result = PE_parse_boot_argn("rd", zfs_boot,
		    MAXPATHLEN);
		result = (result && (zfs_boot != 0) &&
		    strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// zfs_boot_log("Raw rd: [%llu] {%s}\n",
		//    (uint64_t)strlen(zfs_boot), zfs_boot );
	}
	if (!result) {
		result = PE_parse_boot_argn("rootdev", zfs_boot,
		    MAXPATHLEN);
		result = (result && (zfs_boot != 0) &&
		    strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// zfs_boot_log("Raw rootdev: [%llu] {%s}\n",
		//    (uint64_t)strlen(zfs_boot), zfs_boot );
	}

/*
 * XXX To Do - parse zpool_guid boot arg
 */
	*pool_guid = 0;

	if (result) {
		/* Check for first slash in zfs_boot */
		split = strchr(zfs_boot, '/');
		if (split) {
			/* copy pool name up to first slash */
			len = (split - zfs_boot + 1);
		} else {
			/* or copy whole string */
			len = (strlen(zfs_boot) + 1);
		}

		*pool_name = (char*) kmem_alloc(len, KM_SLEEP);
		strncpy(*pool_name, zfs_boot, len);

		zfs_boot_log("Got zfs_boot: [%llu] {%s}->{%s}\n",
		    *pool_guid, zfs_boot, *pool_name);
	} else {
		zfs_boot_log("%s\n", "No zfs_boot\n");
		pool_name = 0;
	}

	kmem_free(zfs_boot, MAXPATHLEN);
	zfs_boot = 0;
	return (result);
}

bool
zfs_boot_init(IOService *zfs_hl)
{
	uint64_t pool_guid = 0;
	char *pool_name = 0;
	pool_list_t *pools = 0;
	IONotifier *notifier = 0;

	zfs_boot_pool_list = 0;

	if (!zfs_hl) {
#ifdef DEBUG
		printf("zfs_boot_init: No zfs_hl provided\n");
#endif
		return (false);
	}

	if (!zfs_boot_check_mountroot(&pool_name, &pool_guid) ||
	    (!pool_name && pool_guid == 0)) {
		/*
		 * kext is not being loaded during early-boot,
		 * or no pool is specified for import.
		 */
#ifdef DEBUG
		printf("zfs_boot_init: check failed\n");
#endif
		return (true);
	}

	pools = (pool_list_t*) kmem_alloc(sizeof (pool_list_t),
	    KM_SLEEP);
	if (!pools) {
		goto error;
	}
	bzero(pools, sizeof(pool_list_t));

	if ((pools->lock = IOLockAlloc()) == 0) {
		/* Fail if memory couldn't be allocated */
		goto error;
	}
	if (0 == (pools->disks = OSSet::withCapacity(
				    ZFS_BOOT_PREALLOC_SET))) {
		/* Fail if memory couldn't be allocated */
		goto error;
	}
	pools->terminating = ZFS_BOOT_ACTIVE;
	pools->pools = 0;
	pools->names = 0;
	pools->pool_guid = pool_guid;
	pools->pool_name = pool_name;
	pools->zfs_hl = zfs_hl;

	notifier = IOService::addMatchingNotification(
	    gIOFirstPublishNotification, IOService::serviceMatching(
	    "IOMediaBSDClient"), zfs_boot_probe_media,
	    zfs_hl, pools, 0);

	if (!notifier) {
		/* Fail if memory couldn't be allocated */
		goto error;
	}
	pools->notifier = notifier;

	/* Finally, start the import thread */
	taskq_dispatch(system_taskq, zfs_boot_import_thread,
	    (void*)pools, TQ_SLEEP);
#if 0
/* Alternate method of scheduling the import thread */
	(void) thread_create(NULL, 0, zfs_boot_import_thread,
				 pools, 0, &p0,
				 TS_RUN, minclsyspri);
#endif

	zfs_boot_pool_list = pools;

	return (true);

error:
	if (pools) {
		if (pools->lock) {
			IOLockFree(pools->lock);
			pools->lock = 0;
		}
		if (pools->disks) {
			pools->disks->flushCollection();
			pools->disks->release();
			pools->disks = 0;
		}
		kmem_free(pools, sizeof (pool_list_t));
		pools = 0;
	}
	return (false);
}

#if 0
bool
zfs_boot_mountroot(void)
{
	/* EDITORIAL / README
	 *
	 * The filesystem that we mount as root is defined in the
	 * boot property "zfs_boot" with a format of
	 * "poolname/root-dataset-name".
	 * You may also use the options "rd=zfs:pool/dataset"
	 *  or "rootdev=zfs:pool/dataset"
	 *
	 * Valid entries: "rpool", "tank/fish",
	 *  "sys/ROOT/BootEnvironment", and so on.
	 *
	 *  see /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
	 *  and ${PREFIX}/share/zfs/com.apple.Boot.plist for examples
	 *
	 * Note that initial boot support uses ZVOLs formatted
	 * as (Mac-native) Journaled HFS+
	 * In this case the bootfs will be a ZVOL, which cannot
	 * be set via "zpool set bootfs=pool/zvol"
	 *
	 * Using ZFS datasets as root will require an additional
	 * hack to trick the xnu kernel.
	 *
	 * Candidate is creating a (blank) ramdisk in chosen/RamDisk,
	 * then forcible root-mount, possibly using an overlay.
	 * Other options may include grub2+zfs, Chameleon, Chimera, etc.
	 *
	 *
	 * TO DO -- TO DO -- TO DO
	 *
	 * - Use PE Boot Args to determine the root pool name.
	 *  working basically, but needs to filter zfs: from
	 *  start of argument string. Also testing multiple
	 *  '/'s in the dataset/zvol name, though it doesn't
	 *  use this right now. Of course, need to error check
	 *  for invalid entries (and decide what to do then).
	 *
	 * - Use IORegistry to locate vdevs - DONE
	 *
	 * - Call functions in vdev_disk.c or spa_boot.c
	 * to locate the pool, import it. - DONE
	 *	Cloned these functions into this giant function.
	 *	Needs to be abstracted. - DONE
	 *
	 * - Present single zvol as specified in zfs_boot?
	 *	Currently all zvols are made available on import.
	 *
	 * - Provide sample Boot.plist
	 *	${PREFIX}/share/zfs/com.apple.Boot.plist
	 *	Install to:
	 *	/Library/Preferences/SystemConfiguration/com.apple.Boot.plist
	 *
	 * Case 1: Present zvol for the Root volume - DONE
	 *
	 * Case 2: Similar to meklort's FSRoot method,
	 * register vfs_fsadd, and mount root;
	 * mount the bootfs dataset as a union mount on top
	 * of a ramdisk if necessary.
	 */

	char *strptr = 0;
	vdev_iokit_t *dvd = 0;

#if 0
	char zfs_boot[MAXPATHLEN];
	char zfs_pool[MAXPATHLEN];
	char zfs_root[MAXPATHLEN];
#endif
	char *zfs_boot;
	char *zfs_pool;
	char *zfs_root;
	char *vdev_path;

	int split = 0;
	bool result = false;

	if (mountedRootPool == true)
		return (false);

	zfs_boot = (char*) kmem_alloc(MAXPATHLEN, KM_SLEEP);
	zfs_pool = (char*) kmem_alloc(MAXPATHLEN, KM_SLEEP);
	zfs_root = (char*) kmem_alloc(MAXPATHLEN, KM_SLEEP);

	PE_parse_boot_argn("zfs_boot", zfs_boot, MAXPATHLEN);

	result =	(strlen(zfs_boot) > 0);

	if (!result) {
		PE_parse_boot_argn("rd", zfs_boot, sizeof (zfs_boot));
		result =	(strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// strptr = zfs_boot + 4;
	}
	if (!result) {
		PE_parse_boot_argn("rootdev", zfs_boot, sizeof (zfs_boot));
		result =	(strlen(zfs_boot) > 0 &&
		    strncmp(zfs_boot, "zfs:", 4));
		// strptr = zfs_boot + 4;
	}

	if (!result) {
		zfs_boot_log("Invalid zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		return (false);
	}

	// Error checking, should be longer than 1 character and null terminated
	strptr = strchr(zfs_boot, '\0');
	if (strptr == NULL) {
		zfs_boot_log("Invalid zfs_boot: Not null terminated : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	}

	// Error checking, should be longer than 1 character
	if (strlen(strptr) == 1) {
		zfs_boot_log("Invalid zfs_boot: Only null character : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	} else {
		zfs_boot_log("Valid zfs_boot: [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
	}

	// Find first '/' in the boot arg
	strptr = strchr(zfs_boot, '/');

	// If leading '/', return error
	if (strptr == (zfs_boot)) {
		zfs_boot_log("Invalid zfs_boot: starts with '/' : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		strptr = NULL;
		return (false);
	}

	// If trailing '/', return error
	if (strptr == (zfs_boot + strlen(zfs_boot) - 1)) {
		zfs_boot_log("Invalid zfs_boot: ends with '/' : [%llu] {%s}\n",
		    (uint64_t)strlen(zfs_boot), zfs_boot);
		strptr = NULL;
		return (false);
	}

	//	if (split > 0 && split < strlen(zfs_boot)) {
	if (strptr && strptr > zfs_boot) {
		// strpbrk(search.spa_name, "/@")
		split = strlen(zfs_boot) - strlen(strptr);
		strlcpy(zfs_pool, zfs_boot, split+1);
		strlcpy(zfs_root, strptr+1, strlen(strptr));
	} else {
		strlcpy(zfs_pool, zfs_boot, strlen(zfs_boot)+1);
		strlcpy(zfs_root, "\0", 1);
	}

	// Find last @ in zfs_root ds
	strptr = strrchr(zfs_root, '@');

	//	if (split > 0 && split < strlen(zfs_boot)) {
	if (strptr && strptr > zfs_root) {
		split = strlen(zfs_root) - strlen(strptr);
		strptr += split;
		strlcpy(zfs_root, strptr, split);
	}

#if 0
/*
 * Manually set zfs_pool and zfs_root for debugging.
 *
 * Best to comment out above section, too
 */
//snprintf(zfs_pool, 5, "tank");
//snprintf(zfs_root, 1, "");
#endif

	zfs_boot_log("Will attempt to import zfs_pool: [%llu] %s\n",
	    (uint64_t)strlen(zfs_pool), zfs_pool);

	result = (zfs_pool && strlen(zfs_pool) > 0);

	zfs_boot_log("Will attempt to mount zfs_root:  [%llu] %s\n",
	    (uint64_t)strlen(zfs_root), zfs_root);

	/*
	 * We want to match on all disks or volumes that
	 *  do not contain a partition map / raid / LVM
	 */

	if (vdev_iokit_alloc(&dvd) != 0) {
		zfs_boot_log("Couldn't allocate dvd [%p]\n", dvd);
		return (false);
	}

	zfs_boot_log("Searching for pool by name {%s}\n", zfs_pool);

	if (vdev_iokit_find_pool(dvd, zfs_pool) == 0 &&
	    dvd != 0 && dvd->vd_iokit_hl != 0) {

		zfs_boot_log("\nFound pool {%s}, importing handle: [%p]\n",
		    zfs_pool, dvd->vd_iokit_hl);

/*
		vdev_path = vdev_iokit_get_path(dvd);

		if (vdev_path) {
			zfs_boot_log("Disk path: %s\n", vdev_path);

			vdev_iokit_open_devvp(vdev_path);

			strfree(vdev_path);
		}
*/

		if (spa_import_rootpool(dvd) == 0) {
			zfs_boot_log("Imported pool {%s}\n", zfs_pool);
			result = mountedRootPool = true;
		} else {
			zfs_boot_log("Couldn't import pool by handle [%p]\n", dvd);
			result = false;
		}
	}

out:
	if (!result) {
		zfs_boot_log("Couldn't locate pool by name {%s}\n", zfs_pool);
	}

	vdev_iokit_free(&dvd);
	dvd = 0;

	strptr = 0;
	kmem_free(zfs_boot, MAXPATHLEN);
	kmem_free(zfs_pool, MAXPATHLEN);
	kmem_free(zfs_root, MAXPATHLEN);

	return (result);
}
#endif

#if 0
bool
isRootMounted(void)
{
	return (mountedRootPool);
}

void
mountTimerFired(OSObject* owner, IOTimerEventSource* sender)
{
	bool result = false;
#if 0
	net_lundman_zfs_zvol *driver =	0;
#endif

mount_attempts++;

#if 0
	if (!owner) {
		zfs_boot_log("%s\n", "ZFS: mountTimerFired: Called without owner");
		return;
	}

	driver = OSDynamicCast(net_lundman_zfs_zvol, owner);

	if (!driver) {
		zfs_boot_log("%s\n", "ZFS: mountTimerFired: Couldn't cast driver object");
		return;
	}

	result = driver->isRootMounted();
#endif

	result = isRootMounted();

	if (result == true) {
		zfs_boot_log("%s\n", "ZFS: mountTimerFired: Root pool already mounted");
#if 0
		driver->clearMountTimer();
#endif
		clearMountTimer();
		return;
	}

#if 0
	result = driver->zfs_mountroot();
#endif
	result = zfs_mountroot();

	if (result == true) {
		zfs_boot_log("%s\n", "ZFS: mountTimerFired: Successfully mounted root pool");
#if 0
		driver->clearMountTimer();
#endif
		clearMountTimer();
		return;
	}

	if (mount_attempts < ZFS_MOUNTROOT_RETRIES) {
		zfs_boot_log("%s\n", "ZFS: mountTimerFired: root pool not found, retrying...");
		sender->setTimeoutMS(ZFS_BOOT_POLL_MS);
		//sender->setTimeoutMS(3000);
	} else {
		zfs_boot_log("%s %d/%d %s\n", "ZFS: mountTimerFired: root pool not found after",
		    mount_attempts, ZFS_MOUNTROOT_RETRIES, "giving up.");
#if 0
		driver->clearMountTimer();
#endif
		clearMountTimer();
	}
}

void
clearMountTimer(void)
{
	if (!mountTimer)
		return;

	zfs_boot_log("%s\n", "ZFS: clearMountTimer: Resetting and removing timer");
	mountTimer->cancelTimeout();
	mountTimer->release();
	mountTimer = 0;

	if (disksInUse) {
		disksInUse->flushCollection();
		disksInUse->release();
		disksInUse = 0;
	}
}
#endif

} /* extern "C" */

#endif /* ZFS_BOOT */
