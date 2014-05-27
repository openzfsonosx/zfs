
/*
 * Apple IOKit (c++)
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOPlatformExpert.h>

#include <sys/vdev_impl.h>
#include <sys/vdev_iokit.h>
#include <sys/vdev_iokit_context.h>

/*
 * XXX To do -
 * Determine best value
 * First used value was 8
 */
#define VDEV_IOKIT_PREALLOCATE_CONTEXTS		16

/*
 * IOKit C++ functions
 */

extern void vdev_iokit_log(const char * logString)
{
	IOLog("ZFS: vdev: %s\n", logString);
}

extern void vdev_iokit_log_str(const char * logString1, const char * logString2)
{
	IOLog("ZFS: vdev: %s {%s}\n", logString1, logString2);
}

extern void vdev_iokit_log_ptr(const char * logString, const void * logPtr)
{
	IOLog("ZFS: vdev: %s [%p]\n", logString, logPtr);
}

extern void vdev_iokit_log_num(const char * logString, const uint64_t logNum)
{
	IOLog("ZFS: vdev: %s (%llu)\n", logString, logNum);
}


#if 0
static inline void vdev_iokit_context_free(vdev_iokit_context_t * io_context);

static inline vdev_iokit_context_t * vdev_iokit_context_alloc(zio_t * zio)
{
	vdev_iokit_context_t * io_context = 0;
	IOMemoryDescriptor * newDescriptor = 0;

	if (!zio)
		return 0;

	/* KM_PUSHPAGE for IO context */
	io_context = static_cast <vdev_iokit_context_t *> (kmem_alloc(
				sizeof (vdev_iokit_context_t), KM_NOSLEEP));

	if (!io_context) {
		return 0;
	}

	newDescriptor = IOMemoryDescriptor::withAddress(zio->io_data, zio->io_size,
				(zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn));

	if (!newDescriptor) {
		goto error;
	}

	io_context->buffer = (IOMemoryDescriptor*)newDescriptor;

	newDescriptor = 0;

	if (io_context->buffer == NULL) {
		vdev_iokit_context_free(io_context);
	}

	io_context->zio = zio;

	return io_context;

error:
	if (io_context) {
		if (io_context->zio)
			io_context->zio = 0;

		io_context = 0;
	}

	return 0;
}

static inline void vdev_iokit_context_free(vdev_iokit_context_t * io_context)
{
	if (!io_context) {
		return;
	}

	io_context->zio = 0;

	if (io_context->buffer) {
		io_context->buffer->release();

		io_context->buffer = 0;
	}

	kmem_free(io_context, sizeof (vdev_iokit_context_t));

	io_context = 0;
}
#endif

extern inline void * vdev_iokit_get_context(vdev_iokit_t * dvd, zio_t * zio)
{
	bool blocking = false;
	IOCommandPool * command_pool = 0;

	if (!zio || !dvd)
		return 0;

	if (zio->io_type == ZIO_TYPE_WRITE) {
		command_pool = ((IOCommandPool*)dvd->out_command_pool);
	} else {
		command_pool = ((IOCommandPool*)dvd->in_command_pool);
	}

	if (!command_pool) {
		vdev_iokit_log("vdev_iokit_get_context: invalid command_pools");
		return 0;
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

extern inline void vdev_iokit_return_context(zio_t * zio, void * io_context)
{
	vdev_iokit_t * dvd = 0;
	IOCommandPool * command_pool = 0;

	if (!zio || !zio->io_vd || !zio->io_vd->vdev_tsd)
		return;

	dvd = static_cast <vdev_iokit_t *> (zio->io_vd->vdev_tsd);

	if (!dvd)
		return;

	if (zio->io_type == ZIO_TYPE_WRITE) {
		command_pool = ((IOCommandPool*)dvd->out_command_pool);
	} else {
		command_pool = ((IOCommandPool*)dvd->in_command_pool);
	}

	if (!command_pool)
		return;

	command_pool->returnCommand((IOCommand*)io_context);
}

extern int vdev_iokit_context_pool_alloc(vdev_iokit_t * dvd)
{
	OSSet * new_set = 0;
	IOWorkLoop * work_loop = 0;
	IOCommandPool * new_in_pool = 0;
	IOCommandPool * new_out_pool = 0;
	net_lundman_vdev_io_context * new_context = 0;
	int preallocate =	VDEV_IOKIT_PREALLOCATE_CONTEXTS;
	int error = EINVAL;

	/* Only allocate if dvd avail and command pools are not */
	if (!dvd || (dvd->in_command_pool && dvd->out_command_pool)) {
		return EINVAL;
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
		work_loop = IOWorkLoop::workLoopWithOptions(IOWorkLoop::kPreciousStack);
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
			new_context = (net_lundman_vdev_io_context*)net_lundman_vdev_io_context::withDirection(kIODirectionIn);

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
		work_loop = IOWorkLoop::workLoopWithOptions(IOWorkLoop::kPreciousStack);
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
			new_context = (net_lundman_vdev_io_context*)net_lundman_vdev_io_context::withDirection(kIODirectionOut);

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

	return 0;

error:
	vdev_iokit_context_pool_free(dvd);

	return error;
}

extern int vdev_iokit_context_pool_free(vdev_iokit_t * dvd)
{
	IOCommandPool * command_pool = 0;
	OSSet * command_set = 0;

	if (!dvd)
		return EINVAL;

	if (dvd->in_command_pool) {
		command_pool = (IOCommandPool*)dvd->in_command_pool;

		dvd->in_command_pool = 0;

		command_pool->release();
		command_pool = 0;
	}
	if (dvd->out_command_pool) {
		command_pool = (IOCommandPool*)dvd->out_command_pool;

		dvd->out_command_pool = 0;

		command_pool->release();
		command_pool = 0;
	}

	if (dvd->command_set) {
		command_set = (OSSet*)dvd->command_set;

		dvd->command_set = 0;

		/* This will release all of the contained IOCommands */
		command_set->flushCollection();

		command_set->release();
		command_set = 0;
	}

	return 0;
}

extern void * vdev_iokit_get_service()
{
	IORegistryIterator * registryIterator = 0;
	OSIterator * newIterator = 0;
	IORegistryEntry * currentEntry = 0;
	OSDictionary * matchDict = 0;
	OSOrderedSet * allServices = 0;
	OSString * entryName = 0;
	IOService * zfs_service = 0;

	currentEntry = IORegistryEntry::fromPath("IOService:/IOResources/net_lundman_zfs_zvol", 0, 0, 0, 0);

	if (currentEntry) {
		zfs_service = OSDynamicCast(IOService, currentEntry);

		currentEntry->release();
		currentEntry = 0;

		if (zfs_service) {
			return (void *)zfs_service;
		}
	}

	matchDict = IOService::resourceMatching("net_lundman_zfs_zvol", 0);

	if (matchDict) {
		newIterator = IOService::getMatchingServices(matchDict);
		matchDict->release();
		matchDict = 0;

		if (newIterator) {
			registryIterator = OSDynamicCast(IORegistryIterator, newIterator);
			if (registryIterator) {

				zfs_service = OSDynamicCast(IOService, registryIterator->getCurrentEntry());

				if (zfs_service)
					zfs_service->retain();

				registryIterator->release();
				registryIterator = 0;
			}
		}
	}

	if (zfs_service) {
		zfs_service->release();
	}

	/* Should be matched, go to plan B if not */
	if (!zfs_service) {
		registryIterator = IORegistryIterator::iterateOver(gIOServicePlane, kIORegistryIterateRecursively);
		if (!registryIterator) {
			vdev_iokit_log("vdev_iokit_get_service: couldn't iterate over service plane");
		} else {

			do {
				if (allServices)
					allServices->release();

				allServices = registryIterator->iterateAll();
			} while (! registryIterator->isValid());

			registryIterator->release();
			registryIterator = 0;
		}

		if (!allServices) {
			vdev_iokit_log_ptr("vdev_iokit_get_service: couldn't get service list from iterator:", registryIterator);
			return 0;
		}

		while ((currentEntry = OSDynamicCast(IORegistryEntry,
											allServices->getFirstObject()))) {
			if (currentEntry) {

				entryName = OSDynamicCast(OSString, currentEntry->copyName());

				if (entryName) {
					if (entryName->isEqualTo("net_lundman_zfs_zvol")) {
						zfs_service = OSDynamicCast(IOService, currentEntry);
						zfs_service->retain();
					}
					entryName->release();
					entryName = 0;
				}

				// Remove from the set
				allServices->removeObject(currentEntry);
				currentEntry = 0;

				if (zfs_service) {
					/* Found service */
					break;
				}
			}
		}

		allServices->release();
		allServices = 0;
	}

	if (zfs_service) {
		zfs_service->release();
	}

	return (void *)zfs_service;

} /* vdev_iokit_get_service */

/*
 * We want to match on all disks or volumes that
 * do not contain a partition map / raid / LVM
 * - Caller must release the returned object
 */
extern OSSet * vdev_iokit_get_disks()
{
//	const OSSymbol * leafProp = OSSymbol::withCString("Leaf");
//	OSDictionary * matchDict = 0;
//	OSIterator * iterator = 0;
//	IOService * match = 0;

	const OSBoolean * matchBool = OSBoolean::withBoolean(true);
	OSSet * allMatches = 0;

	IORegistryIterator * registryIterator = 0;
	IORegistryEntry * currentEntry = 0;
	OSOrderedSet * allEntries = 0;
	boolean_t result = false;

#if 0
	matchDict = IOService::serviceMatching(kIOMediaClass);

	//	IOService::propertyMatching(leafProp, matchBool, matchDict);

	if (!matchDict) {
		return 0;
	}

	iterator = IOService::getMatchingServices(matchDict);

	if (!iterator) {
		leafProp->release();
		matchBool->release();
		matchDict->release();
		return 0;
	}

	do
	{
		if (allMatches) {
			allMatches->release();
		}

		allMatches = OSSet::withCapacity(1);

		while ((match = (IOService *) iterator->getNextObject())) {
			allMatches->setObject(match);
			match = 0;
		}

	} while (!iterator->isValid());

	iterator->release();
	iterator = 0;

	if (allMatches && allMatches->getCount() > 0) {
		return allMatches;
	} else {
		if (allMatches) {
			allMatches->release();
			allMatches = 0;
		}
	}
#endif

	registryIterator = IORegistryIterator::iterateOver(gIOServicePlane,
				kIORegistryIterateRecursively);

	if (!registryIterator) {
		registryIterator = 0;
		return 0;
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
		currentEntry = OSDynamicCast(IORegistryEntry, allEntries->getFirstObject());

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
		matchBool = OSDynamicCast(OSBoolean, currentEntry->getProperty(kIOMediaLeafKey));

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

	return allMatches;

}

/* Returned object will have a reference count and should be released */
int
vdev_iokit_find_by_path(vdev_iokit_t * dvd, char * diskPath)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IORegistryEntry * currentDisk = 0;
	IORegistryEntry * matchedDisk = 0;
	OSObject * bsdnameosobj = 0;
	OSString * bsdnameosstr = 0;
	char * diskName = 0;

	if (!dvd || !diskPath) {
		return EINVAL;
	}

	allDisks = vdev_iokit_get_disks();

	if (!allDisks) {
		return EINVAL;
	}

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

		bsdnameosobj = currentDisk->getProperty(kIOBSDNameKey,
				gIOServicePlane,
				kIORegistryIterateRecursively);

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
			if (matchedDisk) {
				matchedDisk->release();
				matchedDisk = 0;
			}

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

	if (allDisks) {
		allDisks->flushCollection();
		allDisks->release();
		allDisks = 0;
	}

	if (matchedDisk) {
		/* Already retained */
		dvd->vd_iokit_hl = (void*)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return 0;
	} else {
		return ENOENT;
	}

}

/*
 * Check all disks for matching guid
 * Assign vd_iokit_t -> vd_iokit_hl
 * Returned object will have a reference count and should be released
 */
int
vdev_iokit_find_by_guid(vdev_iokit_t * dvd, uint64_t guid)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IOMedia * currentDisk = 0;
	IOMedia * matchedDisk = 0;
	nvlist_t * config = 0;

	uint64_t min_size = 100<<20; /* 100 Mb */
	uint64_t txg = 0, besttxg = 0;
	uint64_t current_guid = 0;

	if (!dvd || guid == 0)
		return EINVAL;

	allDisks = vdev_iokit_get_disks();

	if (!allDisks || allDisks->getCount() == 0) {
		return ENOENT;
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

		/* Get and check txg and guid */
		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG, &txg) != 0 ||
			nvlist_lookup_uint64(config, ZPOOL_CONFIG_GUID, &current_guid) != 0 ||
			txg < besttxg || current_guid != guid) {

			txg = 0;
			current_guid = 0;

			nvlist_free(config);
			config = 0;

			/* Pop from list */
			allDisks->removeObject(currentEntry);
			currentEntry = 0;
			currentDisk = 0;
			continue;
		}

		besttxg = txg;

		/* Previous match? Release it */
		if (matchedDisk) {
			matchedDisk->release();
			matchedDisk = 0;
		}

		/* Save it and up the retain count */
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

	/* Found a match? Save it in dvd as vd_iokit_hl */
	if (matchedDisk) {
		dvd->vd_iokit_hl = (void *)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return 0;
	} else {
		return ENOENT;
	}
}

/* Returned nvlist should be freed */
extern int vdev_iokit_find_pool(vdev_iokit_t * dvd, char * pool_name)
{
	OSSet * allDisks = 0;
	OSObject * currentEntry = 0;
	IOMedia * currentDisk = 0;
	IOMedia * matchedDisk = 0;
	nvlist_t * config = 0;
	char * cur_pool_name = 0;

	uint64_t min_size = 100<<20; /* 100 Mb */
	uint64_t txg = 0, besttxg = 0;

	if (!pool_name)
		return EINVAL;

	allDisks = vdev_iokit_get_disks();

	if (!allDisks || allDisks->getCount() == 0) {
		return ENOENT;
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
		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG, &txg) != 0 ||
			nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &cur_pool_name) != 0 ||
			txg < besttxg || strlen(cur_pool_name) == 0 ||
			strncmp(cur_pool_name, pool_name, strlen(cur_pool_name)) != 0) {

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

		vdev_iokit_log_ptr("ZFS: vdev_iokit_find_pool: Found matching pool on disk:", currentDisk);

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
		dvd->vd_iokit_hl = (void*)matchedDisk;
		matchedDisk = 0;
	}

	if (dvd->vd_iokit_hl != 0) {
		return 0;
	} else {
		return ENOENT;
	}
}

/* If path is valid, copy into physpath */
extern int vdev_iokit_physpath(vdev_t * vd, char * physpath)
{
	vdev_iokit_t * dvd = 0;

	if (!vd)
		return EINVAL;

	dvd = static_cast <vdev_iokit_t *> (vd->vdev_tsd);

	if (!dvd || !dvd->vd_iokit_hl)
		return EINVAL;

	/* If physpath arg is provided */
	if (physpath && strlen(physpath) > 0) {

		/* Save the physpath arg into physpath */
		vd->vdev_physpath = spa_strdup(physpath);
		return 0;
	} else if (vd->vdev_path && strlen(vd->vdev_path) > 0) {

		/* Save the current path into physpath */
		vd->vdev_physpath = spa_strdup(vd->vdev_path);
		return 0;
	} else {

		/* No usable physpath available */
		return EINVAL;
	}
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
	IOMedia * vdev_hl = 0;
	int error = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl)
		return EINVAL;

	vdev_hl = (IOMedia *)dvd->vd_iokit_hl;

	if (!vdev_hl) {
		error = EINVAL;
		goto error;
	}

	/* Check if device is already open (by any clients, including ZFS) */
	if (vdev_hl->isOpen(0) == true) {
		error = EBUSY;
		goto error;
	}

	/* If read/write mode is requested, check that device is actually writeable */
	if (fmode > FREAD &&
		vdev_hl->isWritable() == false) {

		vdev_iokit_log_ptr("ZFS: vdev_iokit_handle_open: Disk is not writeable:", dvd);
		error = ENODEV;
		goto error;
	}

	if (vdev_hl->IOMedia::open((IOService *)dvd->vd_zfs_hl,
				0, (fmode == FREAD ?
				kIOStorageAccessReader :
				kIOStorageAccessReaderWriter)) == false) {

				error = EIO;
				goto error;
	}

#if 0
	if (!dvd->in_command_pool || !dvd->out_command_pool) {

		/* Allocate several io_context objects */
		if (vdev_iokit_context_pool_alloc(dvd) != 0) {
			goto error;
		}
	}
#endif

	goto out;

error:

	if (error == 0)
		error = EIO;

	vdev_hl = 0;

	return error;

out:

	vdev_hl = 0;

	/* Success */
	return 0;
}

extern int
vdev_iokit_handle_close(vdev_iokit_t *dvd, int fmode = 0)
{
	if (!dvd || !dvd->vd_zfs_hl || !dvd->vd_iokit_hl)
		return EINVAL;

	((IOMedia *)dvd->vd_iokit_hl)->close(((IOService *)dvd->vd_zfs_hl), (fmode == FREAD ?
				kIOStorageAccessReader : kIOStorageAccessReaderWriter));

	return 0;
}

extern int
vdev_iokit_open_by_path(vdev_iokit_t * dvd, char * path)
{
	if (!dvd || !path) {
		return EINVAL;
	}

	if (vdev_iokit_find_by_path(dvd, path) != 0 ||
		!dvd->vd_iokit_hl) {

		return ENOENT;
	}

	/* Open the device handle */
	if (vdev_iokit_handle_open(dvd) == 0) {
		return 0;
	} else {
		return EIO;
	}
}

extern int
vdev_iokit_open_by_guid(vdev_iokit_t * dvd, uint64_t guid)
{
	if (!dvd || guid == 0) {
		return EINVAL;
	}

	if (vdev_iokit_find_by_guid(dvd, guid) != 0 ||
		!dvd->vd_iokit_hl) {

		return ENOENT;
	}

	/* Open the device handle */
	if (vdev_iokit_handle_open(dvd) == 0) {
		return 0;
	} else {
		return EIO;
	}
}

extern int
vdev_iokit_get_size(vdev_iokit_t * dvd, uint64_t *size, uint64_t *max_size, uint64_t *ashift)
{
	uint64_t blksize = 0;

	if (!dvd || !dvd->vd_iokit_hl)
		return EINVAL;

	if (size != 0) {
		*size = ((IOMedia *)dvd->vd_iokit_hl)->getSize();
	}

	if (max_size != 0) {
		*max_size = *size;
	}
	
	if (ashift != 0) {
		blksize = ((IOMedia *)dvd->vd_iokit_hl)->getPreferredBlockSize();
		if (blksize <= 0) {
			blksize = SPA_MINBLOCKSIZE;
		}

		*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;
	}

	return 0;
}

/*
 * Return 0 on success,
 *  EINVAL or EIO as needed
 */
extern int
vdev_iokit_status(vdev_iokit_t * dvd)
{

	if (!dvd)
		return EINVAL;

	if (((IOMedia *)dvd->vd_iokit_hl)->isFormatted() == true)
		return 0;
	else
		return ENXIO;
}

int
vdev_iokit_ioctl(vdev_iokit_t * dvd, zio_t * zio)
{
	/*
	 * XXX - TO DO
	 *  multiple IOctls / passthrough
	 *
	 *  Flush cache
	 *   vdev_iokit_sync(dvd,zio)
	 */

	vdev_iokit_log_ptr("ZFS: vdev_iokit_ioctl: dvd:", dvd);
	vdev_iokit_log_ptr("ZFS: vdev_iokit_ioctl: zio:", zio);

	/*
	 *  Handle ioctl
	 */

	return 0;
}

/* Must already have handle_open called on dvd */
int
vdev_iokit_sync(vdev_iokit_t *dvd, zio_t * zio)
{
	/*
	 * dvd and vd_iokit_hl need to be specified,
	 * zio can be null
	 */
	if (!dvd || !dvd->vd_iokit_hl) {
		return EINVAL;
	}

	if (((IOMedia*)dvd->vd_iokit_hl)->synchronizeCache((IOService*)dvd->vd_zfs_hl) == kIOReturnSuccess) {
		return 0;
	} else {
		vdev_iokit_log("ZFS: vdev_iokit_sync: fail");
		return EIO;
	}
}

/* Must already have handle_open called on dvd */
extern int
vdev_iokit_physio(vdev_iokit_t * dvd, void * data, size_t size, uint64_t offset, int fmode)
{
	IOBufferMemoryDescriptor * buffer = 0;
	IOReturn result = kIOReturnError;
	uint64_t actualByteCount = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl ||
		!data || size == 0)
		return EINVAL;

	buffer = (IOBufferMemoryDescriptor*)IOBufferMemoryDescriptor::withAddress(data,
				size, (fmode == FREAD ? kIODirectionIn : kIODirectionOut));

	/* Verify the buffer is ready for use */
	if (!buffer || buffer->getLength() != size) {

		result = kIOReturnError;
		goto error;
	}

	result = buffer->prepare(kIODirectionNone);

	if (result != kIOReturnSuccess) {

		buffer->release();

		result = kIOReturnError;
		goto error;
	}

	if (fmode == FREAD) {
		result = ((IOMedia*)dvd->vd_iokit_hl)->IOMedia::read((IOService *)(dvd->vd_zfs_hl),
				offset, buffer, 0, &actualByteCount);
	} else {
		result = ((IOMedia*)dvd->vd_iokit_hl)->IOMedia::write((IOService *)(dvd->vd_zfs_hl),
				offset, buffer, 0, &actualByteCount);
	}

	buffer->complete();

	buffer->release();
	buffer = 0;

error:
	/* Verify the correct number of bytes were transferred */
	return (result == kIOReturnSuccess && actualByteCount == size ? 0 : EIO);
}

/* Must already have handle_open called on dvd */
extern int
vdev_iokit_strategy(vdev_iokit_t * dvd, zio_t * zio)
{
	net_lundman_vdev_io_context * io_context = 0;

	if (!dvd || !dvd->vd_iokit_hl || !dvd->vd_zfs_hl ||
		!zio || !(zio->io_data) || zio->io_size == 0) {
		return EINVAL;
	}

	io_context = (net_lundman_vdev_io_context *)vdev_iokit_get_context(dvd, zio);

	if (!io_context) {
		vdev_iokit_log("ZFS: vdev_iokit_strategy: Couldn't get an IO Context");

		/* If all IO_contexts are in use, try the IO again */
		return EAGAIN;

		/*
		 * Alternatively return ENOMEM for failure to allocate,
		 *  was used before in_command_pool and out_command_pool
		 */
		/* return ENOMEM; */
	}

	/* Configure the context */
	io_context->configure(zio);

	/* Prepare the IOMemoryDescriptor (wires memory) */
	io_context->prepare();

	if (zio->io_type == ZIO_TYPE_WRITE) {
		((IOMedia *)dvd->vd_iokit_hl)->IOMedia::write((IOService *)(dvd->vd_zfs_hl),
				zio->io_offset, io_context->buffer, 0, &(io_context->completion));
	} else {
		((IOMedia *)dvd->vd_iokit_hl)->IOMedia::read((IOService *)(dvd->vd_zfs_hl),
				zio->io_offset, io_context->buffer, 0, &(io_context->completion));
	}

	io_context = 0;

	return 0;
}

extern void vdev_iokit_io_intr(void * target, void * parameter, kern_return_t status, UInt64 actualByteCount)
{
	net_lundman_vdev_io_context * io_context = 0;
	zio_t * zio = 0;

	io_context = (net_lundman_vdev_io_context*)parameter;

	if (!io_context) {
		return;
	}

	zio = io_context->zio;

	if (!zio) {
		return;
	}

	/* Teardown the IOMemoryDescriptor */
	io_context->complete();

	/* Reset the IOMemoryDescriptor */
	io_context->reset();

	vdev_iokit_return_context(zio, (void*)io_context);
	io_context = 0;

	if (status != 0)
		zio->io_error = EIO;

	zio_interrupt(zio);

	zio = 0;
}

#ifdef __cplusplus
}   /* extern "C" */
#endif