
/*
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOMemoryDescriptor.h>
/* #include <IOKit/IOBufferMemoryDescriptor.h> */
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOPlatformExpert.h>

#include <sys/vdev_impl.h>
#include <sys/vdev_iokit.h>
#include <sys/vdev_iokit_context.h>

/*
 * XXX To do -
 * Determine best value
 * First used value was 8
 * #define	VDEV_IOKIT_PREALLOCATE_CONTEXTS		16
 */

/*
 * IOKit C++ functions
 */

extern void vdev_iokit_log(const char *logString)
{
	IOLog("ZFS: vdev: %s\n", logString);
}

extern void vdev_iokit_log_str(const char *logString1, const char *logString2)
{
	IOLog("ZFS: vdev: %s {%s}\n", logString1, logString2);
}

extern void vdev_iokit_log_ptr(const char *logString, const void *logPtr)
{
	IOLog("ZFS: vdev: %s [%p]\n", logString, logPtr);
}

extern void vdev_iokit_log_num(const char *logString, const uint64_t logNum)
{
	IOLog("ZFS: vdev: %s (%llu)\n", logString, logNum);
}

static inline void vdev_iokit_context_free(vdev_iokit_context_t *io_context);

static inline vdev_iokit_context_t *vdev_iokit_context_alloc(zio_t *zio)
{
	vdev_iokit_context_t *io_context = 0;
	IOMemoryDescriptor *newBuffer = 0;


	if (!zio || !zio->io_data || zio->io_size == 0)
		return (0);

	/* KM_PUSHPAGE for IO context */
	io_context = (vdev_iokit_context_t *)kmem_alloc(
	    sizeof (vdev_iokit_context_t), KM_PUSHPAGE);

	if (!io_context)
		return (0);

	newBuffer = IOBufferMemoryDescriptor::withAddress(
	    zio->io_data, zio->io_size,
	    (zio->io_type == ZIO_TYPE_WRITE ?
	    kIODirectionOut : kIODirectionIn));

	if (!newBuffer)
		goto error;

	io_context->buffer = newBuffer;

	newBuffer = 0;

	io_context->completion.target = io_context;
	io_context->completion.parameter = zio;
	io_context->completion.action = (IOStorageCompletionAction)
	    &vdev_iokit_io_intr;

	return (io_context);

error:
	vdev_iokit_context_free(io_context);
	io_context = 0;

	return (0);
}

static inline void vdev_iokit_context_free(vdev_iokit_context_t *io_context)
{
	if (!io_context) {
		return;
	}

	if (io_context->buffer) {
		io_context->buffer->release();
		io_context->buffer = 0;
	}

	io_context->completion.target = 0;
	io_context->completion.parameter = 0;
	io_context->completion.action = 0;

	kmem_free(io_context, sizeof (vdev_iokit_context_t));
	io_context = 0;
}

#if 0 /* Disabled */
extern inline void *vdev_iokit_get_context(vdev_iokit_t *dvd, zio_t *zio)
{
	bool blocking = false;
	IOCommandPool * command_pool = 0;

	if (!zio || !dvd)
		return (0);

	if (zio->io_type == ZIO_TYPE_WRITE) {
		command_pool = (OSDynamicCast(IOCommandPool,
		    (OSObject *)dvd->out_command_pool));
	} else {
		command_pool = (OSDynamicCast(IOCommandPool,
		    (OSObject *)dvd->in_command_pool));
	}

	if (!command_pool) {
		vdev_iokit_log("vdev_iokit_get_context: invalid command_pools");
		return (0);
	}

	/*
	 * Negate the value of failfast in
	 *  zio->io_flags
	 *
	 * For fail-fast, get a context
	 *  without blocking - can return 0.
	 * Otherwise block and guarantee a
	 *  returned IOCommand.
	 */

	blocking = ~(zio->io_flags & ZIO_FLAG_FAILFAST);

	return (void *)(command_pool->getCommand(blocking));
}

extern inline void vdev_iokit_return_context(zio_t *zio, void *io_context)
{
	vdev_iokit_t *dvd = 0;
	IOCommandPool *command_pool = 0;

	if (!zio || !zio->io_vd || !zio->io_vd->vdev_tsd)
		return;

	dvd = static_cast <vdev_iokit_t *> (zio->io_vd->vdev_tsd);

	if (!dvd)
		return;

	if (zio->io_type == ZIO_TYPE_WRITE) {
		command_pool = (OSDynamicCast(IOCommandPool,
		    (OSObject *)dvd->out_command_pool));
	} else {
		command_pool = (OSDynamicCast(IOCommandPool,
		    (OSObject *)dvd->in_command_pool));
	}

	if (!command_pool) {
		return;
	}

	command_pool->returnCommand((IOCommand *)io_context);
}

extern int vdev_iokit_context_pool_alloc(vdev_iokit_t *dvd)
{
	OSSet * new_set = 0;
	IOWorkLoop * work_loop = 0;
	IOCommandPool * new_in_pool = 0;
	IOCommandPool * new_out_pool = 0;
	net_lundman_vdev_io_context * new_context = 0;
	int preallocate = VDEV_IOKIT_PREALLOCATE_CONTEXTS;
	int error = EINVAL;

	/* Only allocate if dvd avail and command pools are not */
	if (!dvd || (dvd->in_command_pool && dvd->out_command_pool)) {
		return (EINVAL);
	}

	/* Allocate command set if needed */
	if (dvd->command_set) {
		new_set = (OSSet *)dvd->command_set;
	} else {
		new_set = OSSet::withCapacity(preallocate);
		if (!new_set) {
			error = ENOMEM;
			goto error;
		}
	}

	if (!dvd->in_command_pool) {
		/* Allocate read work loop */
		work_loop = IOWorkLoop::workLoopWithOptions(
		    IOWorkLoop::kPreciousStack);
		if (!work_loop) {
			error = ENOMEM;
			goto error;
		}

		/* Allocate read command pool */
		new_in_pool = IOCommandPool::withWorkLoop(work_loop);
		if (!new_in_pool) {
			error = ENOMEM;

			work_loop->release();
			work_loop = 0;

			goto error;
		}

		/* IOCommandPool holds a reference to work_loop now */
		work_loop = 0;

		/* Pre-allocate contexts for reads */
		for (int i = 0; i < preallocate; i++) {
			new_context = (net_lundman_vdev_io_context *)
			    net_lundman_vdev_io_context::withDirection(
			    kIODirectionIn);

			if (!new_context) {
				error = ENOMEM;
				goto error;
			}

			new_set->setObject(new_context);

			new_in_pool->returnCommand(new_context);

			new_context->release();
			new_context = 0;
		}
	}

	if (!dvd->out_command_pool) {
		/* Allocate write work loop */
		work_loop = IOWorkLoop::workLoopWithOptions(
		    IOWorkLoop::kPreciousStack);
		if (!work_loop) {
			error = ENOMEM;
			goto error;
		}

		new_out_pool = IOCommandPool::withWorkLoop(work_loop);
		if (!new_out_pool) {
			error = ENOMEM;

			work_loop->release();
			work_loop = 0;

			new_in_pool->release();
			new_in_pool = 0;

			goto error;
		}

		/* IOCommandPool holds a reference to work_loop now */
		work_loop = 0;

		/* Pre-allocate contexts for writes */
		for (int i = 0; i < preallocate; i++) {
			new_context = (net_lundman_vdev_io_context *)
			    net_lundman_vdev_io_context::withDirection(
			    kIODirectionOut);

			if (!new_context) {
				error = ENOMEM;
				goto error;
			}

			new_set->setObject(new_context);

			new_out_pool->returnCommand(new_context);

			new_context->release();
			new_context = 0;
		}
	}

	dvd->command_set = new_set;
	new_set = 0;

	if (new_in_pool) {
		dvd->in_command_pool = new_in_pool;
		new_in_pool = 0;
	}

	if (new_out_pool) {
		dvd->out_command_pool = new_out_pool;
		new_out_pool = 0;
	}

	return (0);

error:
	vdev_iokit_context_pool_free(dvd);

	return (error);
}

extern int vdev_iokit_context_pool_free(vdev_iokit_t *dvd)
{
	IOCommandPool * command_pool = 0;
	OSSet * command_set = 0;

	if (!dvd)
		return (EINVAL);

	if (dvd->in_command_pool) {
		command_pool = (IOCommandPool *)dvd->in_command_pool;

		dvd->in_command_pool = 0;

		command_pool->release();
		command_pool = 0;
	}
	if (dvd->out_command_pool) {
		command_pool = (IOCommandPool *)dvd->out_command_pool;

		dvd->out_command_pool = 0;

		command_pool->release();
		command_pool = 0;
	}

	if (dvd->command_set) {
		command_set = (OSSet *)dvd->command_set;

		dvd->command_set = 0;

		/* This will release all of the contained IOCommands */
		command_set->flushCollection();

		command_set->release();
		command_set = 0;
	}

	return (0);
}
#endif /* Disabled */

extern void *
vdev_iokit_get_service()
{
	IORegistryIterator * registryIterator = 0;
	OSIterator * newIterator = 0;
	IORegistryEntry * currentEntry = 0;
	OSDictionary * matchDict = 0;
	OSOrderedSet * allServices = 0;
	OSString * entryName = 0;
	IOService * zfs_hl = 0;

	currentEntry = IORegistryEntry::fromPath(
	    "IOService:/IOResources/net_lundman_zfs_zvol",
	    0, 0, 0, 0);

	if (currentEntry) {
		zfs_hl = OSDynamicCast(IOService, currentEntry);

		currentEntry->release();
		currentEntry = 0;

		if (zfs_hl) {
			return ((void *)zfs_hl);
		}
	}

	/* If not matched, go to plan B */
	matchDict = IOService::resourceMatching("net_lundman_zfs_zvol", 0);

	if (matchDict) {
		newIterator = IOService::getMatchingServices(matchDict);
		matchDict->release();
		matchDict = 0;

		if (newIterator) {
			registryIterator = OSDynamicCast(IORegistryIterator,
			    newIterator);
			if (registryIterator) {

				zfs_hl = OSDynamicCast(IOService,
				    registryIterator->getCurrentEntry());

				if (zfs_hl)
					zfs_hl->retain();

				registryIterator->release();
				registryIterator = 0;
			}
		}
	}

	if (zfs_hl) {
		zfs_hl->release();
		return ((void *)zfs_hl);
	}

	/* If not matched, go to plan C */
	registryIterator = IORegistryIterator::iterateOver(
	    gIOServicePlane, kIORegistryIterateRecursively);
	if (registryIterator) {
		do {
			if (allServices)
				allServices->release();

			allServices = registryIterator->iterateAll();
		} while (! registryIterator->isValid());

		registryIterator->release();
		registryIterator = 0;
	}

	if (!allServices) {
		return (0);
	}

	while ((currentEntry = OSDynamicCast(IORegistryEntry,
	    allServices->getFirstObject()))) {
		if (currentEntry) {

			entryName = OSDynamicCast(OSString,
			    currentEntry->copyName());

			if (entryName) {
				if (entryName->isEqualTo(
				    "net_lundman_zfs_zvol")) {
					zfs_hl = OSDynamicCast(
					    IOService,
					    currentEntry);
					zfs_hl->retain();
				}
				entryName->release();
				entryName = 0;
			}

			// Remove from the set
			allServices->removeObject(currentEntry);
			currentEntry = 0;

			if (zfs_hl) {
				/* Found service */
				break;
			}
		}
	}

	allServices->release();
	allServices = 0;

	if (zfs_hl) {
		zfs_hl->release();
	}

	return ((void *)zfs_hl);

} /* vdev_iokit_get_service */

/*
 * We want to match on all disks or volumes that
 * do not contain a partition map / raid / LVM
 * - Caller must release the returned object
 */
extern OSSet *
vdev_iokit_get_disks()
{
	const OSBoolean * matchBool = OSBoolean::withBoolean(true);
	OSSet * allMatches = 0;
	IORegistryIterator * registryIterator = 0;
	IORegistryEntry * currentEntry = 0;
	OSOrderedSet * allEntries = 0;
	boolean_t result = false;

	registryIterator = IORegistryIterator::iterateOver(gIOServicePlane,
	    kIORegistryIterateRecursively);

	if (!registryIterator) {
		registryIterator = 0;
		return (0);
	}

	/*
	 * The registry iterator may be invalid by the time
	 * we've copied all the records. If so, try again
	 */
	do {
		/* Reset allEntries if needed */
		if (allEntries) {
			allEntries->release();
			allEntries = 0;
		}

		/* Grab all records */
		allEntries = registryIterator->iterateAll();

	} while (! registryIterator->isValid());

	if (registryIterator) {
		/* clean up */
		registryIterator->release();
		registryIterator = 0;
	}

	if (allEntries && allEntries->getCount() > 0) {
		/*
		 * Pre-allocate a few records
		 *  Most systems will have at least
		 *  2 or 3 'leaf' IOMedia objects-
		 *  and the set will allocate more
		 */
		allMatches = OSSet::withCapacity(3);
	}

	/* Loop through all the items in allEntries */
	while (allEntries->getCount() > 0) {

		/*
		 * Grab the first object in the set.
		 * (could just as well be the last object)
		 */
		currentEntry = OSDynamicCast(IORegistryEntry,
		    allEntries->getFirstObject());

		if (!currentEntry) {
			/* clean up */
			allEntries->flushCollection();
			allEntries->release();
			allEntries = 0;
			break;
		}

		/*
		 * XXX - TO DO
		 *
		 *  Also filter out CoreStorage PVs but not LVMs?
		 */

		/* Check 'Leaf' property */
		matchBool = OSDynamicCast(OSBoolean,
		    currentEntry->getProperty(kIOMediaLeafKey));

		result = (matchBool && matchBool->getValue() == true);

		matchBool = 0;

		if (result) {
			allMatches->setObject(currentEntry);
		}

		/* Remove current item from ordered set */
		allEntries->removeObject(currentEntry);
		currentEntry = 0;
	}

	if (allEntries) {
		allEntries->flushCollection();
		allEntries->release();
	}
	allEntries = 0;

	return (allMatches);

}

/* Returned object will have a reference count and should be released */
int
vdev_iokit_find_by_path(vdev_iokit_t *dvd, char *diskPath, uint64_t guid = 0)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IOMedia * currentDisk = 0;
	IOMedia * matchedDisk = 0;
	OSObject * bsdnameosobj = 0;
	OSString * bsdnameosstr = 0;
	char *diskName = 0;
	nvlist_t *config = 0;

	uint64_t min_size = SPA_MINDEVSIZE; /* 64 Mb */
	uint64_t current_guid = 0;

	if (!dvd || !diskPath) {
		return (EINVAL);
	}

	allDisks = vdev_iokit_get_disks();

	if (!allDisks) {
		return (EINVAL);
	}

	/*
	 * XXX - TO DO
	 *	We may need to rework libzpool
	 *	to resolve symlinks to /dev/diskNsN
	 */
	if (strncmp(diskPath, "/dev/", 5) == 0)
		diskName = diskPath + 5;
	else
		diskName = diskPath;

#if 0
	diskName = strrchr(diskPath, '/');

	if (diskName) {
		/* /dev/disk0s2 -> /disk0s2 */
		/* Start after the last path divider */
		diskName++;
		/* /disk0s2 -> disk0s2 */
	} else {
		/*
		 * XXX To do - check that diskName
		 * is in the form diskNsN
		 */
		diskName = diskPath;
	}
#endif

	while (allDisks->getCount() > 0) {

		/* Get next object */
		currentEntry = allDisks->getAnyObject();

		if (!currentEntry) {
			break;
		}

		currentDisk = OSDynamicCast(IOMedia, currentEntry);

		/* Couldn't cast? */
		if (!currentDisk) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			continue;
		}

		if (currentDisk->getSize() < min_size) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		bsdnameosobj = currentDisk->getProperty(kIOBSDNameKey,
		    gIOServicePlane, kIORegistryIterateRecursively);

		if (bsdnameosobj) {
			bsdnameosstr = OSDynamicCast(OSString, bsdnameosobj);
			bsdnameosobj = 0;
		}

		if (!bsdnameosstr) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Check if the name matches */
		if (bsdnameosstr->isEqualTo(diskName)) {
			/* Success - save match */
			matchedDisk = currentDisk;
			matchedDisk->retain();
		}

		/* Pop from list */
		allDisks->removeObject(currentEntry);
		currentEntry = 0;
		currentDisk = 0;

		/* Find by path breaks on the first match */
		if (matchedDisk) {
			break;
		}
	}

	/* Check GUID */
	if (guid > 0 && matchedDisk) {
		/* Temporarily assign currentDisk to the dvd */
		dvd->vd_iokit_hl = (void *)matchedDisk;

		/* Try to read a config label from this disk */
		if (vdev_iokit_read_label(dvd, &config) != 0 ||
		    nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_GUID, &current_guid) != 0 ||
		    current_guid != guid) {

			/* Clear matchedDisk */
			matchedDisk->release();
			matchedDisk = 0;
		}

		/* Clear the vd_iokit_hl */
		dvd->vd_iokit_hl = 0;

		/* Clear the config */
		if (config)
			nvlist_free(config);
		config = 0;
	}

	if (allDisks) {
		allDisks->flushCollection();
		allDisks->release();
		allDisks = 0;
	}

	if (matchedDisk) {
		/* Already retained */
		dvd->vd_iokit_hl = (void *)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return (0);
	} else {
		return (ENOENT);
	}

}

/*
 * Check all disks for matching guid
 * Assign vd_iokit_t -> vd_iokit_hl
 * Returned object will have a reference count and should be released
 */
int
vdev_iokit_find_by_guid(vdev_iokit_t *dvd, uint64_t guid)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IOMedia * currentDisk = 0;
	IOMedia * matchedDisk = 0;
	nvlist_t *config = 0;

	uint64_t min_size = SPA_MINDEVSIZE; /* 64 Mb */
	uint64_t state = 0, txg = 0;
	uint64_t current_guid = 0;

	if (!dvd || guid == 0)
		return (EINVAL);

	allDisks = vdev_iokit_get_disks();

	if (!allDisks || allDisks->getCount() == 0) {
		return (ENOENT);
	}

	while (allDisks->getCount() > 0) {
		/* Get next object */
		currentEntry = allDisks->getAnyObject();

		if (!currentEntry) {
			break;
		}

		currentDisk = OSDynamicCast(IOMedia, currentEntry);

		/* Couldn't cast? */
		if (!currentDisk) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			continue;
		}

		if (currentDisk->getSize() < min_size) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Temporarily assign currentDisk to the dvd */
		dvd->vd_iokit_hl = (void *)currentDisk;

		/* Try to read a config label from this disk */
		if (vdev_iokit_read_label(dvd, &config) != 0) {
			/* Failed to read config */
			if (config) {
				nvlist_free(config);
				config = 0;
			}

			/* No config found - clear the vd_iokit_hl */
			dvd->vd_iokit_hl = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Checking config - clear the vd_iokit_hl meanwhile */
		dvd->vd_iokit_hl = 0;

		/*
		 * Check that a valid config was loaded
		 *	skip devices that are unavailable,
		 *	uninitialized, or potentially active
		 */
		if (nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_STATE, &state) != 0 ||
		    state > POOL_STATE_L2CACHE) {

			nvlist_free(config);
			config = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/*
		 * Fetch txg number unless spare or l2cache
		 */
		if (state != POOL_STATE_SPARE &&
		    state != POOL_STATE_L2CACHE &&
		    (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0)) {

			nvlist_free(config);
			config = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Get and check guid */
		if (nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_GUID, &current_guid) != 0 ||
		    current_guid != guid) {

			current_guid = 0;

			nvlist_free(config);
			config = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Save it and up the retain count */
		matchedDisk = currentDisk;
		matchedDisk->retain();

		/* Pop from list */
		allDisks->removeObject(currentEntry);
		currentEntry = 0;
		currentDisk = 0;

		/* Find by guid breaks on the first match */
		if (matchedDisk) {
			break;
		}
	}

	if (config) {
		nvlist_free(config);
		config = 0;
	}

	if (allDisks) {
		allDisks->flushCollection();
		allDisks->release();
		allDisks = 0;
	}

	/* Found a match? Save it in dvd as vd_iokit_hl */
	if (matchedDisk) {
		dvd->vd_iokit_hl = (void *)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return (0);
	} else {
		return (ENOENT);
	}
}

/* Returned nvlist should be freed */
extern int
vdev_iokit_find_pool(vdev_iokit_t *dvd, char *pool_name)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IOMedia * currentDisk = 0;
	IOMedia * matchedDisk = 0;
	nvlist_t *config = 0;
	char *cur_pool_name = 0;

	uint64_t min_size = SPA_MINDEVSIZE; /* 64 Mb */
	uint64_t txg = 0, besttxg = 0;

	if (!pool_name)
		return (EINVAL);

	allDisks = vdev_iokit_get_disks();

	if (!allDisks || allDisks->getCount() == 0) {
		return (ENOENT);
	}

	while (allDisks->getCount() > 0) {
		/* Get next object */
		currentEntry = allDisks->getAnyObject();

		if (!currentEntry) {
			break;
		}

		currentDisk = OSDynamicCast(IOMedia, currentEntry);

		/* Couldn't cast? */
		if (!currentDisk) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			continue;
		}

		if (currentDisk->getSize() < min_size) {
			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Temporarily assign currentDisk to the dvd */
		dvd->vd_iokit_hl = (void *)currentDisk;

		/* Try to read a config label from this disk */
		if (vdev_iokit_read_label(dvd, &config) != 0) {
			/* Failed to read config */
			if (config)
				nvlist_free(config);

			/* No config found - clear the vd_iokit_hl */
			dvd->vd_iokit_hl = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		/* Checking config - clear the vd_iokit_hl meanwhile */
		dvd->vd_iokit_hl = 0;

		/* Get and check txg and pool name */
		if (nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_TXG, &txg) != 0 ||
		    nvlist_lookup_string(config,
		    ZPOOL_CONFIG_POOL_NAME, &cur_pool_name) != 0 ||
		    txg < besttxg || strlen(cur_pool_name) == 0 ||
		    strncmp(cur_pool_name, pool_name,
		    strlen(cur_pool_name)) != 0) {

			txg = 0;
			cur_pool_name = 0;

			nvlist_free(config);
			config = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		besttxg = txg;

		if (matchedDisk) {
			matchedDisk->release();
			matchedDisk = 0;
		}

		matchedDisk = currentDisk;
		matchedDisk->retain();

		/* Pop from list */
		allDisks->removeObject(currentEntry);
		currentEntry = 0;
		currentDisk = 0;

		/* Loop in case there is a better match */
	}

	if (config) {
		nvlist_free(config);
		config = 0;
	}

	if (allDisks) {
		allDisks->flushCollection();
		allDisks->release();
		allDisks = 0;
	}

	if (matchedDisk) {
		dvd->vd_iokit_hl = (void *)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return (0);
	} else {
		return (ENOENT);
	}
}

/* If path is valid, copy into physpath */
extern int
vdev_iokit_physpath(vdev_t *vd)
{
	vdev_iokit_t *dvd = 0;
	char *physpath = 0;
	int err;

	/* presume failure */
	err = EINVAL;

	if (!vd)
		return (err);

	dvd = static_cast <vdev_iokit_t *> (vd->vdev_tsd);

	if (!dvd || !dvd->vd_iokit_hl)
		return (err);

	physpath = vdev_iokit_get_path(dvd);

	/* If physpath arg is provided */
	if (physpath && strlen(physpath) > 0) {

		if (vd->vdev_physpath)
			spa_strfree(vd->vdev_physpath);

		/* Save the physpath arg into physpath */
		vd->vdev_physpath = spa_strdup(physpath);

		err = 0;
	} else if (vd->vdev_path && strlen(vd->vdev_path) > 0) {

		if (vd->vdev_physpath)
			spa_strfree(vd->vdev_physpath);

		/* Save the current path into physpath */
		vd->vdev_physpath = spa_strdup(vd->vdev_path);

		err = 0;
	}

	if (physpath) {
//		kmem_free(physpath, strlen(physpath)+1);
		spa_strfree(physpath);
		physpath = 0;
	}

	return (err);
}

/*
 *  ZFS internal
 */

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * C language interfaces
	 */

extern int
vdev_iokit_handle_open(vdev_iokit_t *dvd, int fmode = 0)
{
	IOMedia * iokit_hl = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl)
		return (EINVAL);

	iokit_hl = (IOMedia *)dvd->vd_iokit_hl;

	if (!iokit_hl)
		return (EINVAL);

	/* Check if device is already open (by any clients, including ZFS) */
	if (iokit_hl->isOpen(0) == true) {
		iokit_hl = 0;
		return (EBUSY);
	}

	/*
	 * If read/write mode is requested, check that
	 * the device is actually writeable
	 */
	if (fmode > FREAD &&
	    iokit_hl->isWritable() == false) {

		iokit_hl = 0;
		return (ENODEV);
	}

	if (iokit_hl->IOMedia::open((IOService *)dvd->vd_zfs_hl,
	    0, (fmode == FREAD ?
	    kIOStorageAccessReader :
	    kIOStorageAccessReaderWriter)) == false) {

		iokit_hl = 0;
		return (EIO);
	}

	/* Success */
	return (0);
}

extern int
vdev_iokit_handle_close(vdev_iokit_t *dvd, int fmode = 0)
{
	IOMedia * iokit_hl	= 0;
	IOService * zfs_hl = 0;

	if (!dvd || !dvd->vd_zfs_hl || !dvd->vd_iokit_hl)
		return (EINVAL);

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl) {
		return (EINVAL);
	}

	zfs_hl = OSDynamicCast(IOService,
	    static_cast<OSObject *>(dvd->vd_zfs_hl));

	if (!zfs_hl) {
		iokit_hl = 0;
		return (EINVAL);
	}

	iokit_hl->close(zfs_hl, (fmode == FREAD ?
	    kIOStorageAccessReader :
	    kIOStorageAccessReaderWriter));

	zfs_hl = 0;
	iokit_hl = 0;

	return (0);
}

extern void
vdev_iokit_hold(vdev_t * vd)
{
	vdev_iokit_t *dvd = 0;
	IOMedia * iokit_hl = 0;

	dvd = static_cast <vdev_iokit_t *> (vd->vdev_tsd);

	if (!dvd || !dvd->vd_iokit_hl)
		return;

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl) {
		return;
	}

	iokit_hl->retain();
}

extern void
vdev_iokit_rele(vdev_t * vd)
{
	vdev_iokit_t *dvd = 0;
	IOMedia * iokit_hl = 0;

	dvd = static_cast <vdev_iokit_t *> (vd->vdev_tsd);

	if (!dvd || !dvd->vd_iokit_hl)
		return;

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl) {
		return;
	}

	iokit_hl->release();
}

extern int
vdev_iokit_open_by_path(vdev_iokit_t *dvd, char *path, uint64_t guid = 0)
{
	if (!dvd || !path) {
		return (EINVAL);
	}

	if (vdev_iokit_find_by_path(dvd, path, guid) != 0 ||
	    !dvd->vd_iokit_hl) {

		return (ENOENT);
	}

	/* Open the device handle */
	if (vdev_iokit_handle_open(dvd) == 0) {
		return (0);
	} else {
		return (EIO);
	}
}

extern int
vdev_iokit_open_by_guid(vdev_iokit_t *dvd, uint64_t guid)
{
	if (!dvd || guid == 0) {
		return (EINVAL);
	}

	if (vdev_iokit_find_by_guid(dvd, guid) != 0 ||
	    !dvd->vd_iokit_hl) {

		return (ENOENT);
	}

	/* Open the device handle */
	if (vdev_iokit_handle_open(dvd) == 0) {
		return (0);
	} else {
		return (EIO);
	}
}

/*
 * Caller should free the returned char pointer
 *	kmem_free(ptr, MAXPATHLEN);
 */
extern char *
vdev_iokit_get_path(vdev_iokit_t *dvd)
{
	IOMedia * iokit_hl = 0;
	OSObject * bsdnameosobj = 0;
	OSString * bsdnameosstr = 0;
	char *diskpath = 0;
	char *newpath = 0;
	size_t len = 0;

	if (!dvd || !dvd->vd_iokit_hl)
		return (0);

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl)
		return (0);

	bsdnameosobj = iokit_hl->getProperty(kIOBSDNameKey,
	    gIOServicePlane, kIORegistryIterateRecursively);

	if (bsdnameosobj) {
		bsdnameosstr = OSDynamicCast(OSString, bsdnameosobj);
		bsdnameosobj = 0;
	}

	if (!bsdnameosstr) {
		return (0);
	}

	diskpath = (char *)bsdnameosstr->getCStringNoCopy();

	/* Save the disk path into newpath */
	if (diskpath && strlen(diskpath) > 0) {

//		newpath = spa_strdup(diskpath);

		len = strlen(diskpath) + strlen("/dev/") + 1;

		newpath = (char *)kmem_alloc(len, KM_SLEEP);

		snprintf(newpath, len, "/dev/%s", diskpath);
	}

	bsdnameosstr = 0;
	iokit_hl = 0;

	return (newpath);
}

extern int
vdev_iokit_get_size(vdev_iokit_t *dvd, uint64_t *size,
    uint64_t *max_size, uint64_t *ashift)
{
	IOMedia * iokit_hl = 0;
	uint64_t blksize = 0;

	if (!dvd || !dvd->vd_iokit_hl)
		return (EINVAL);

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl)
		return (EINVAL);

	if (size != 0) {
		*size = iokit_hl->getSize();
	}

	if (max_size != 0) {
		*max_size = *size;
	}

	if (ashift != 0) {
		blksize = iokit_hl->getPreferredBlockSize();
		if (blksize == 0) {
			blksize = DEV_BSIZE;
		}

		*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;
	}

	iokit_hl = 0;

	return (0);
}

/*
 * Return 0 on success,
 *  EINVAL or EIO as needed
 */
extern int
vdev_iokit_status(vdev_iokit_t *dvd)
{
	/*
	 * XXX - TO DO
	 *
	 * By attaching to the IOMedia device, we can both check
	 * the status via IOKit functions, and be informed of
	 * device changes.
	 *
	 * Determine other methods of checking the device status.
	 *	I have tested this with unexpected device removal by
	 *	hot-plugging a USB flash drive while pool is imported
	 *	with readonly=on and off. Have not experienced panics
	 *	however the behavior is basically the same as before.
	 *	A readonly pool can be exported if no datasets/zvols
	 *	are mounted or in use.
	 *
	 * Right now the only checks performed are whether the
	 *	IOMedia device has been terminated, and if it is
	 *	still 'formatted'. isFormatted actually returns
	 *	whether the capacity and blocksize are available.
	 */
	IOMedia * iokit_hl	= 0;

	if (!dvd)
		return (EINVAL);

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl)
		return (EINVAL);

	if (iokit_hl->isInactive() == true ||
	    iokit_hl->isFormatted() != true) {

		iokit_hl	= 0;
		return (ENXIO);
	} else {
		iokit_hl	= 0;
		return (0);
	}
}

int
vdev_iokit_ioctl(vdev_iokit_t *dvd, zio_t *zio)
{
	/*
	 * XXX - TO DO
	 *  multiple IOctls / passthrough
	 *
	 *  Flush cache
	 *   vdev_iokit_sync(dvd,zio)
	 */

	vdev_iokit_log_ptr("vdev_iokit_ioctl: dvd:", dvd);
	vdev_iokit_log_ptr("vdev_iokit_ioctl: zio:", zio);

	/*
	 *  Handle ioctl
	 */

	return (0);
}

/*
 * Must already have handle_open called on dvd
 *
 * dvd and vd_iokit_hl must be non-null,
 * zio can be null
 */
int
vdev_iokit_sync(vdev_iokit_t *dvd, zio_t *zio)
{
	IOMedia * iokit_hl	= 0;
	IOService * zfs_hl = 0;
	IOReturn result = kIOReturnError;

	if (!dvd || !dvd->vd_iokit_hl) {
		return (EINVAL);
	}

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl) {
		return (EINVAL);
	}

	zfs_hl = OSDynamicCast(IOService,
	    static_cast<OSObject *>(dvd->vd_zfs_hl));

	if (!zfs_hl) {
		iokit_hl = 0;
		return (EINVAL);
	}

	result = iokit_hl->synchronizeCache(zfs_hl);

	zfs_hl = 0;
	iokit_hl = 0;

	if (result != kIOReturnSuccess) {
		return (ENOTSUP);
	} else {
		return (0);
	}
}

/* Must already have handle_open called on dvd */
extern int
vdev_iokit_physio(vdev_iokit_t *dvd, void *data,
    size_t size, uint64_t offset, int fmode)
{
	/*	IOBufferMemoryDescriptor * buffer = 0; */
	IOMemoryDescriptor * buffer = 0;
	IOMedia * iokit_hl = 0;
	IOService * zfs_hl = 0;
	IOReturn result = kIOReturnError;
	uint64_t actualByteCount = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl ||
	    !data || size == 0)
		return (EINVAL);

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl)
		return (EINVAL);

	zfs_hl = OSDynamicCast(IOService,
	    static_cast<OSObject *>(dvd->vd_zfs_hl));

	if (!zfs_hl) {
		iokit_hl = 0;
		return (EINVAL);
	}

	buffer = IOMemoryDescriptor::withAddress(
	    data, size, (fmode == FREAD ?
	    kIODirectionIn :
	    kIODirectionOut));

	/* Verify the buffer is ready for use */
	if (!buffer || buffer->getLength() != size) {

		result = kIOReturnError;
		goto error;
	}

	result = buffer->prepare(fmode == FWRITE ?
	    kIODirectionOut : kIODirectionIn);

	if (result != kIOReturnSuccess) {

		buffer->release();

		result = kIOReturnError;
		goto error;
	}

	if (fmode == FREAD) {
		result = iokit_hl->IOMedia::read(zfs_hl, offset,
		    buffer, 0, &actualByteCount);
	} else {
		result = iokit_hl->IOMedia::write(zfs_hl, offset,
		    buffer, 0, &actualByteCount);
	}

	buffer->complete();

	buffer->release();
	buffer = 0;

	zfs_hl = 0;
	iokit_hl = 0;

error:
	/* Verify the correct number of bytes were transferred */
	if (result == kIOReturnSuccess && actualByteCount == size) {
		return (0);
	} else {
		return (EIO);
	}
}

/* Must already have handle_open called on dvd */
extern int
vdev_iokit_strategy(vdev_iokit_t *dvd, zio_t *zio)
{
	vdev_iokit_context_t *io_context = 0;
	IOMedia * iokit_hl = 0;
	IOService * zfs_hl = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl ||
	    !zio || !(zio->io_data) || zio->io_size == 0) {
		return (EINVAL);
	}

	iokit_hl = OSDynamicCast(IOMedia,
	    static_cast<OSObject *>(dvd->vd_iokit_hl));

	if (!iokit_hl)
		return (EINVAL);

	zfs_hl = OSDynamicCast(IOService,
	    static_cast<OSObject *>(dvd->vd_zfs_hl));

	if (!zfs_hl) {
		iokit_hl = 0;
		return (EINVAL);
	}

	/*
	 * io_context = (net_lundman_vdev_io_context *)
	 *	vdev_iokit_get_context(dvd, zio);
	 */

	io_context = vdev_iokit_context_alloc(zio);

	if (!io_context) {
		zfs_hl = 0;
		iokit_hl = 0;

		/*
		 * Return ENOMEM for failure to allocate
		 */
		return (ENOMEM);

		/* If all IO_contexts are in use, try the IO again */
		/* return (EAGAIN); */
	}

	if (!io_context->buffer) {
		vdev_iokit_context_free(io_context);
		goto error;
	}

	/* Configure the context */
	/*	io_context->configure(zio); */

	/* Prepare the IOMemoryDescriptor (wires memory) */
	if (io_context->buffer->prepare(zio->io_type == ZIO_TYPE_WRITE ?
	    kIODirectionOut : kIODirectionIn) != kIOReturnSuccess) {

		vdev_iokit_context_free(io_context);
		goto error;
	}

	if (zio->io_type == ZIO_TYPE_WRITE) {
		iokit_hl->IOMedia::write(zfs_hl, zio->io_offset,
		    io_context->buffer, 0,
		    &(io_context->completion));
	} else {
		iokit_hl->IOMedia::read(zfs_hl, zio->io_offset,
		    io_context->buffer, 0,
		    &(io_context->completion));
	}

error:
	io_context = 0;
	zfs_hl = 0;
	iokit_hl = 0;

	return (0);
}

extern void
vdev_iokit_io_intr(void * target, void * parameter,
    kern_return_t status, UInt64 actualByteCount)
{
	vdev_iokit_context_t *io_context = 0;
	zio_t *zio = 0;
	vdev_t *vd = 0;

	if (!target || !parameter) {
		return;
	}

	/* Get the io_context from target */
	io_context = static_cast<vdev_iokit_context_t *>(target);

	if (!io_context) {
		return;
	}

	/* Get the zio from parameter */
	zio = static_cast<zio_t *>(parameter);
	if (!zio) {
		return;
	}

	/* Teardown the IOMemoryDescriptor */
	if (io_context && io_context->buffer->complete()
	    != kIOReturnSuccess) {
		return;
	}

	/* Reset the IOMemoryDescriptor */
	/*	io_context->buffer->reset(); */

	/* vdev_iokit_return_context(zio, (void *)io_context); */
	vdev_iokit_context_free(io_context);
	io_context = 0;

	/* Get the vdev object from the zio */
	vd = zio->io_vd;
	if (!vd)
		return;

	/*
	 * The rest of the zio stack only deals with EIO, ECKSUM, and ENXIO.
	 * Rather than teach the rest of the stack about other error
	 * possibilities (EFAULT, etc), we normalize the error value here.
	 */
	zio->io_error = (status != 0 ? EIO : 0);

	if (zio->io_error == 0 &&
	    actualByteCount < zio->io_size) {
		zio->io_error = EIO;
	}

	zio_interrupt(zio);

	zio = 0;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif
