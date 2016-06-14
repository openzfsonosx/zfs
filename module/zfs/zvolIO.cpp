
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOStorageProtocolCharacteristics.h>

/*
 * Device
 */


//#define dprintf IOLog

// Define the superclass
#define	super IOBlockStorageDevice

#define	ZVOL_BSIZE	DEV_BSIZE

static const char* ZVOL_PRODUCT_NAME_PREFIX = "ZVOL ";

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol_device, IOBlockStorageDevice)

bool
net_lundman_zfs_zvol_device::init(zvol_state_t *c_zv,
    OSDictionary *properties)
{
	dprintf("zvolIO_device:init\n");
	if (super::init(properties) == false)
	return (false);

	zv = c_zv;
	// Is it safe/ok to keep a pointer reference like this?
	zv->zv_iokitdev = (void *) this;

  super::setProperty(kIOMediaContentHintKey,
			  zv->zv_minor == -1 ? "zfs_pool_proxy" : "ZFS Volume");
  return true;
}


bool
net_lundman_zfs_zvol_device::attach(IOService* provider)
{
	OSDictionary *protocolCharacteristics = 0;
	OSDictionary *deviceCharacteristics = 0;
	OSDictionary *storageFeatures = 0;
	OSBoolean *unmapFeature = 0;
	OSString *dataString = 0;
	OSNumber *dataNumber = 0;

	char product_name[strlen(ZVOL_PRODUCT_NAME_PREFIX) + MAXPATHLEN + 1];
	
	if (super::attach(provider) == false)
		return (false);
	m_provider = OSDynamicCast(net_lundman_zfs_zvol, provider);
	if (m_provider == NULL)
		return (false);

	/*
	 * We want to set some additional properties for ZVOLs, in
	 * particular, "Virtual Device", and type "File"
	 * (or is Internal better?)
	 *
	 * Finally "Generic" type.
	 *
	 * These properties are defined in *protocol* characteristics
	 */

	protocolCharacteristics = OSDictionary::withCapacity(3);

	if (!protocolCharacteristics) {
		IOLog("failed to create dict for protocolCharacteristics.\n");
		return (true);
	}

	dataString = OSString::withCString(
	    kIOPropertyPhysicalInterconnectTypeVirtual);

	if (!dataString) {
		IOLog("could not create interconnect type string\n");
		return (true);
	}
	protocolCharacteristics->setObject(
	    kIOPropertyPhysicalInterconnectTypeKey, dataString);

	dataString->release();
	dataString = 0;

	dataString = OSString::withCString(kIOPropertyInterconnectFileKey);
	if (!dataString) {
		IOLog("could not create interconnect location string\n");
		return (true);
	}
	protocolCharacteristics->setObject(
	    kIOPropertyPhysicalInterconnectLocationKey, dataString);

	dataString->release();
	dataString = 0;

	setProperty(kIOPropertyProtocolCharacteristicsKey,
	    protocolCharacteristics);

	protocolCharacteristics->release();
	protocolCharacteristics = 0;

	/*
	 * We want to set some additional properties for ZVOLs, in
	 * particular, physical block size (volblocksize) of the
	 * underlying ZVOL, and 'logical' block size presented by
	 * the virtual disk. Also set physical bytes per sector.
	 *
	 * These properties are defined in *device* characteristics
	 */

	deviceCharacteristics = OSDictionary::withCapacity(3);

	if (!deviceCharacteristics) {
		IOLog("failed to create dict for deviceCharacteristics.\n");
		return (true);
	}

	/* Set logical block size to ZVOL_BSIZE (512b) */
	dataNumber =	OSNumber::withNumber(ZVOL_BSIZE,
	    8 * sizeof (ZVOL_BSIZE));

	deviceCharacteristics->setObject(kIOPropertyLogicalBlockSizeKey,
	    dataNumber);

	dprintf("logicalBlockSize %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Set physical block size to match volblocksize property */
	dataNumber =	OSNumber::withNumber(zv->zv_volblocksize,
	    8 * sizeof (zv->zv_volblocksize));

	deviceCharacteristics->setObject(kIOPropertyPhysicalBlockSizeKey,
	    dataNumber);

	dprintf("physicalBlockSize %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Set physical bytes per sector to match volblocksize property */
	dataNumber =	OSNumber::withNumber((uint64_t)(zv->zv_volblocksize),
	    8 * sizeof (uint64_t));

	deviceCharacteristics->setObject(kIOPropertyBytesPerPhysicalSectorKey,
	    dataNumber);

	dprintf("physicalBytesPerSector %llu\n",
	    dataNumber->unsigned64BitValue());

	dataNumber->release();
	dataNumber	= 0;

	/* Publish the Device / Media name */
	(void)snprintf(product_name, sizeof(product_name), "%s%s", ZVOL_PRODUCT_NAME_PREFIX, zv->zv_name);
	dataString = OSString::withCString(product_name);
	deviceCharacteristics->setObject(kIOPropertyProductNameKey, dataString);
	dataString->release();
	dataString = 0;
	
	/* Apply these characteristics */
	setProperty(kIOPropertyDeviceCharacteristicsKey,
	    deviceCharacteristics);

	deviceCharacteristics->release();
	deviceCharacteristics	= 0;

	/*
	 * ZVOL unmap support
	 *
	 * These properties are defined in IOStorageFeatures
	 */

	storageFeatures =	OSDictionary::withCapacity(1);
	if (!storageFeatures) {
		IOLog("failed to create dictionary for storageFeatures.\n");
		return (true);
	}

	/* Set unmap feature */
	unmapFeature =	OSBoolean::withBoolean(true);
	storageFeatures->setObject(kIOStorageFeatureUnmap, unmapFeature);
	unmapFeature->release();
	unmapFeature	= 0;

	/* Apply these storage features */
	setProperty(kIOStorageFeaturesKey, storageFeatures);
	storageFeatures->release();
	storageFeatures	= 0;


	/*
	 * Set transfer limits:
	 *
	 *  Maximum transfer size (bytes)
	 *  Maximum transfer block count
	 *  Maximum transfer block size (bytes)
	 *  Maximum transfer segment count
	 *  Maximum transfer segment size (bytes)
	 *  Minimum transfer segment size (bytes)
	 *
	 *  We will need to establish safe defaults for all / per volblocksize
	 *
	 *  Example: setProperty(kIOMinimumSegmentAlignmentByteCountKey, 1, 1);
	 */

	/*
	 * Finally "Generic" type, set as a device property. Tried setting this
	 * to the string "ZVOL" however the OS does not recognize it as a block
	 * storage device. This would probably be possible by extending the
	 * IOBlockStorage Device / Driver relationship.
	 */

	setProperty(kIOBlockStorageDeviceTypeKey,
	    kIOBlockStorageDeviceTypeGeneric);

	return (true);
}

int
net_lundman_zfs_zvol_device::getBSDName(void)
{
	IORegistryEntry *ioregdevice = 0;
	OSObject *bsdnameosobj = 0;
	OSString* bsdnameosstr = 0;

	ioregdevice = OSDynamicCast(IORegistryEntry, this);

	if (!ioregdevice)
		return (-1);

	bsdnameosobj = ioregdevice->getProperty(kIOBSDNameKey,
	    gIOServicePlane, kIORegistryIterateRecursively);

	if (!bsdnameosobj)
		return (-1);

	bsdnameosstr = OSDynamicCast(OSString, bsdnameosobj);

	IOLog("zvol: bsd name is '%s'\n",
	    bsdnameosstr->getCStringNoCopy());

	if (!zv)
		return (-1);

	zv->zv_bsdname[0] = 'r'; // for 'rdiskX'.
	strlcpy(&zv->zv_bsdname[1],
	    bsdnameosstr->getCStringNoCopy(),
	    sizeof (zv->zv_bsdname)-1);
	/*
	 * IOLog("name assigned '%s'\n", zv->zv_bsdname);
	 */

	return (0);
}


void
net_lundman_zfs_zvol_device::detach(IOService* provider)
{
	if (m_provider == provider)
		m_provider = NULL;
	super::detach(provider);
}


bool
net_lundman_zfs_zvol_device::handleOpen(IOService *client,
    IOOptionBits options, void *argument)
{
	IOStorageAccess access = (IOStorageAccess)(uint64_t)argument;
	bool ret = true;

	dprintf("open: options %lx\n", options);

	if (super::handleOpen(client, options, argument) == false)
		return (false);

	/*
	 * It was the hope that openHandle would indicate the type of open
	 * required such that we can set FREAD/FWRITE/ZVOL_EXCL as needed, but
	 * alas, "access" is always 0 here.
	 */


    spa_exporting_vdevs = B_TRUE;


	switch (access) {

		case kIOStorageAccessReader:
			//IOLog("handleOpen: readOnly\n");
			zv->zv_openflags = FREAD;
			//zvol_open_impl(zv, FREAD /* ZVOL_EXCL */, 0, NULL);
			break;

		case kIOStorageAccessReaderWriter:
			// IOLog("handleOpen: options %04x\n", options);
			zv->zv_openflags = FWRITE | ZVOL_EXCL;
			break;

		default:
			// IOLog("handleOpen with unknown access %04lu\n",
			//	access);
			zv->zv_openflags = FWRITE;
	}

	if (zvol_open_impl(zv, zv->zv_openflags, 0, NULL)) {
		dprintf("Open failed - testing readonly\n");

		zv->zv_openflags = FREAD;
		if (zvol_open_impl(zv, FREAD /* ZVOL_EXCL */, 0, NULL))
			ret = false;

	}

    spa_exporting_vdevs = B_FALSE;

	dprintf("Open done\n");

	return (true);
}



void
net_lundman_zfs_zvol_device::handleClose(IOService *client,
    IOOptionBits options)
{
	super::handleClose(client, options);

	// IOLog("handleClose\n");
    spa_exporting_vdevs = B_TRUE;
	zvol_close_impl(zv, zv->zv_openflags, 0, NULL);
    spa_exporting_vdevs = B_FALSE;

	if (ejected)
		this->m_provider->doEjectMedia(zv);


}

IOReturn
net_lundman_zfs_zvol_device::doAsyncReadWrite(
    IOMemoryDescriptor *buffer, UInt64 block, UInt64 nblks,
    IOStorageAttributes *attributes, IOStorageCompletion *completion)
{
    IODirection               direction;
    IOByteCount               actualByteCount;


    // Return errors for incoming I/O if we have been terminated.
    if (isInactive() == true) {
      dprintf("asyncReadWrite notActive fail\n");
      return kIOReturnNotAttached;
    }

    // Ensure the start block being targeted is within the disk’s capacity.
    if ((block)*(ZVOL_BSIZE) >= zv->zv_volsize) {
      dprintf("asyncReadWrite start block outside volume\n");
      return kIOReturnBadArgument;
    }

    // Shorten the read, if beyond the end
    if (((block + nblks)*(ZVOL_BSIZE)) > zv->zv_volsize) {
      dprintf("asyncReadWrite block shortening needed\n");
      return kIOReturnBadArgument;
    }

    // Get the buffer’s direction, whether the operation is a read or a write.
    direction = buffer->getDirection();
    if ((direction != kIODirectionIn) && (direction != kIODirectionOut)) {
      dprintf("asyncReadWrite kooky direction\n");
      return kIOReturnBadArgument;
    }

    dprintf("%s offset @block %llu numblocks %llu: blksz %llu\n",
            direction == kIODirectionIn ? "Read" : "Write",
            block, nblks, (ZVOL_BSIZE));
    //IOLog("getMediaBlockSize is %llu\n", m_provider->getMediaBlockSize());
    // Perform the read or write operation through the transport driver.
    actualByteCount = (nblks*(ZVOL_BSIZE));

	// Only do IO on ZVolumes - the others are fake
	if (zv->zv_minor != -1) {

		// These variables are set in zvol_first_open(), which should
		// have been called already.
		if (!zv->zv_objset || !zv->zv_dbuf) {
			dprintf("asyncReadWrite no objset nor dbuf\n");
			return kIOReturnNotAttached;
		}
		/* Make sure we don't go away while the command is being executed */
		retain();
		m_provider->retain();

		if (direction == kIODirectionIn) {

			if (zvol_read_iokit(zv,
								(block*(ZVOL_BSIZE)),
								actualByteCount,
								(void *)buffer))
				actualByteCount = 0;

		} else {

			if (zvol_write_iokit(zv,
								 (block*(ZVOL_BSIZE)),
								 actualByteCount,
								 (void *)buffer))
        actualByteCount = 0;

		}
	}

	m_provider->release();
	release();

	if (actualByteCount != nblks*(ZVOL_BSIZE))
		dprintf("Read/Write operation failed\n");

    // Call the completion function.
    (completion->action)(completion->target, completion->parameter,
                         kIOReturnSuccess, actualByteCount);
    return kIOReturnSuccess;
}

IOReturn
net_lundman_zfs_zvol_device::doDiscard(UInt64 block, UInt64 nblks)
{
	dprintf("doDiscard called with block, nblks (%llu, %llu)\n",
	    block, nblks);
	uint64_t bytes		= 0;
	uint64_t off		= 0;

	/* Convert block/nblks to offset/bytes */
	off =	block * ZVOL_BSIZE;
	bytes =	nblks * ZVOL_BSIZE;
	dprintf("calling zvol_unmap with offset, bytes (%llu, %llu)\n",
	    off, bytes);

	if (zvol_unmap(zv, off, bytes) == 0)
		return (kIOReturnSuccess);
	else
		return (kIOReturnError);
}


IOReturn
net_lundman_zfs_zvol_device::doUnmap(IOBlockStorageDeviceExtent *extents,
    UInt32 extentsCount, UInt32 options = 0)
{
	UInt32 i = 0;
	IOReturn result;

	dprintf("doUnmap called with (%u) extents and options (%u)\n",
	    (uint32_t)extentsCount, (uint32_t)options);

	if (options > 0) {
		return (kIOReturnUnsupported);
	}

	for (i = 0; i < extentsCount; i++) {

		result = doDiscard(extents[i].blockStart,
		    extents[i].blockCount);

		if (result != kIOReturnSuccess) {
			return (result);
		}
	}

	return (kIOReturnSuccess);
}

UInt32
net_lundman_zfs_zvol_device::doGetFormatCapacities(UInt64* capacities,
    UInt32 capacitiesMaxCount) const
{
	dprintf("formatCap\n");

	/*
	 * Ensure that the array is sufficient to hold all our formats
	 * (we require one element).
	 */
	if ((capacities != NULL) && (capacitiesMaxCount < 1))
		return (0);
		/* Error, return an array size of 0. */

	/*
	 * The caller may provide a NULL array if it wishes to query the number
	 * of formats that we support.
	 */
	if (capacities != NULL)
		capacities[0] = zv->zv_volsize;

	dprintf("returning capacity[0] size %llu\n", zv->zv_volsize);

	return (1);
}

char *
net_lundman_zfs_zvol_device::getProductString(void)
{
	dprintf("getProduct %p\n", zv);

	if (zv)
		return (zv->zv_name);

	return ((char *)"ZVolume");
}

IOReturn
net_lundman_zfs_zvol_device::reportBlockSize(UInt64 *blockSize)
{
	*blockSize = (ZVOL_BSIZE);
	dprintf("reportBlockSize %llu\n", *blockSize);
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportMaxValidBlock(UInt64 *maxBlock)
{
	*maxBlock = (zv->zv_volsize / (ZVOL_BSIZE)) - 1;
	dprintf("reportMaxValidBlock %llu\n", *maxBlock);
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportMediaState(bool *mediaPresent,
    bool *changedState)
{
	printf("reportMediaState\n");
	*mediaPresent = true;
	*changedState = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportPollRequirements(bool *pollRequired,
    bool *pollIsExpensive)
{
	dprintf("reportPollReq\n");
	*pollRequired = false;
	*pollIsExpensive = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportRemovability(bool *isRemovable)
{
	dprintf("reportRemova\n");
	*isRemovable = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doEjectMedia(void)
{
	dprintf("ejectMedia\n");
	ejected = 1;

#if 0
	IOLog("I am of class %s\n", getMetaClass()->getClassName());
	IOLog("provider class %s\n", getProvider()->getMetaClass()->getClassName());
	IOLog("provider provider class %s\n", getProvider()->getProvider()->getMetaClass()->getClassName());

	getClient()->getClient()->registerService(kIOServiceSynchronous);
	printf("BSDName %s\n", this->getBSDName());
#endif

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doFormatMedia(UInt64 byteCapacity)
{
	printf("doFormat\n");

	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doLockUnlockMedia(bool doLock)
{
	dprintf("doLockUnlock\n");
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::doSynchronizeCache(void)
{
	dprintf("doSync\n");
	if (zv && zv->zv_zilog) {
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	}
	return (kIOReturnSuccess);
}

char *
net_lundman_zfs_zvol_device::getVendorString(void)
{
	dprintf("getVendor\n");
	return ((char *)"ZVOL");
}

char *
net_lundman_zfs_zvol_device::getRevisionString(void)
{
	dprintf("getRevision\n");
	return ((char *)ZFS_META_VERSION);
}

char *
net_lundman_zfs_zvol_device::getAdditionalDeviceInfoString(void)
{
	dprintf("getAdditional\n");
	return ((char *)"ZFS Volume");
}

IOReturn
net_lundman_zfs_zvol_device::reportEjectability(bool *isEjectable)
{
	dprintf("reportEjecta\n");
	/*
	 * Which do we prefer? If you eject it, you can't get volume back until
	 * you import it again.
	 */

	*isEjectable = false;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportLockability(bool *isLockable)
{
	dprintf("reportLocka\n");
	*isLockable = true;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::reportWriteProtection(bool *isWriteProtected)
{
	if (zv && (zv->zv_flags & ZVOL_RDONLY))
		*isWriteProtected = true;
	else
		*isWriteProtected = false;
	dprintf("reportWritePro: %d\n", *isWriteProtected);
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::getWriteCacheState(bool *enabled)
{
	dprintf("getCacheState\n");
	*enabled = true;
	return (kIOReturnSuccess);
}

IOReturn
net_lundman_zfs_zvol_device::setWriteCacheState(bool enabled)
{
	dprintf("setWriteCache\n");
	return (kIOReturnSuccess);
}


IOReturn
net_lundman_zfs_zvol_device::newUserClient(task_t owningTask,
										   void* securityID, UInt32 type,
										   OSDictionary* properties,
										   IOUserClient** handler)
{
	printf("newUserClient\n");
	return true;
}
