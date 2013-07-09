
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>
#include <IOKit/storage/IOBlockStorageDevice.h>


/*
 * Device
 */


//#define dprintf IOLog

// Define the superclass
#define super IOBlockStorageDevice

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol_device,IOBlockStorageDevice)

bool net_lundman_zfs_zvol_device::init(zvol_state_t *c_zv,
                                       OSDictionary *properties)
{
  dprintf("zolio_device:init\n");
  if (super::init(properties) == false)
    return false;

  zv = c_zv;
  // Is it safe/ok to keep a pointer reference like this?
  zv->zv_iokitdev = (void *) this;

  return true;
}


bool net_lundman_zfs_zvol_device::attach(IOService* provider)
{
    if (super::attach(provider) == false)
        return false;
    m_provider = OSDynamicCast(net_lundman_zfs_zvol, provider);
    if (m_provider == NULL)
        return false;
    return true;
}

void net_lundman_zfs_zvol_device::detach(IOService* provider)
{
    if (m_provider == provider)
        m_provider = NULL;
    super::detach(provider);
}




bool net_lundman_zfs_zvol_device::handleOpen( IOService *client,
                                              IOOptionBits options,
                                              void *argument)
{
  IOStorageAccess access = (IOStorageAccess) (uint64_t) argument;

  dprintf("open\n");

  if (super::handleOpen(client, options, argument) == false)
    return false;

  /*
   * It was the hope that openHandle would indicate the type of open required
   * such that we can set FREAD/FWRITE/ZVOL_EXCL as needed, but alas,
   * "access" is always 0 here.
   */

  switch (access) {

  case kIOStorageAccessReader:
    IOLog("handleOpen: readOnly\n");
    zv->zv_openflags = FREAD;
    zvol_open_impl(zv, FREAD /* ZVOL_EXCL */, 0, NULL);
    break;

  case kIOStorageAccessReaderWriter:
    IOLog("handleOpen: options %04x\n", options);
    zv->zv_openflags = FWRITE | ZVOL_EXCL;
    break;

  default:
    //IOLog("handleOpen with unknown access %04lu - guessing\n", access);
    zv->zv_openflags = FWRITE;
  }

  if (zvol_open_impl(zv, zv->zv_openflags, 0, NULL))
    return false;

  return true;
}



void net_lundman_zfs_zvol_device::handleClose( IOService *client,
                                               IOOptionBits options)
{
  super::handleClose(client, options);

  //IOLog("handleClose\n");
  zvol_close_impl(zv, zv->zv_openflags, 0, NULL);
}

IOReturn net_lundman_zfs_zvol_device::doAsyncReadWrite(
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
    // These variables are set in zvol_first_open(), which should have been
    // called already.
    if (!zv->zv_objset || !zv->zv_dbuf) {
      dprintf("asyncReadWrite no objset nor dbuf\n");
      return kIOReturnNotAttached;
    }

    // Ensure the start block being targeted is within the disk’s capacity.
    if ((block)*zv->zv_volblocksize >= zv->zv_volsize) {
      dprintf("asyncReadWrite start block outside volume\n");
      return kIOReturnBadArgument;
    }

    // Shorten the read, if beyond the end
    if (((block + nblks)*zv->zv_volblocksize) > zv->zv_volsize) {
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
            block, nblks, zv->zv_volblocksize);

    // Perform the read or write operation through the transport driver.
    actualByteCount = (nblks*zv->zv_volblocksize);

    if (direction == kIODirectionIn) {

      if (zvol_read_iokit(zv,
                          (block*zv->zv_volblocksize),
                          actualByteCount,
                          (void *)buffer))
        actualByteCount = 0;

    } else {

      if (zvol_write_iokit(zv,
                           (block*zv->zv_volblocksize),
                            actualByteCount,
                           (void *)buffer))
        actualByteCount = 0;

    }

    if (actualByteCount != nblks*zv->zv_volblocksize)
      dprintf("Read/Write operation failed\n");

    // Call the completion function.
    (completion->action)(completion->target, completion->parameter,
                         kIOReturnSuccess, actualByteCount);
    return kIOReturnSuccess;
}




UInt32 net_lundman_zfs_zvol_device::doGetFormatCapacities(UInt64* capacities,
                                                          UInt32 capacitiesMaxCount) const
{
  dprintf("formatCap\n");
    // Ensure that the array is sufficient to hold all our formats
    // (we require 1 element).
    if ((capacities != NULL) && (capacitiesMaxCount < 1))
      return 0;               // Error, return an array size of 0.
    // The caller may provide a NULL array if it wishes to query
    // the number of formats that we support.
    if (capacities != NULL)
      //capacities[0] = m_blockCount * kDiskBlockSize;
      capacities[0] = zv->zv_volsize - zv->zv_volblocksize;
    dprintf("returning capacity[0] size %llu\n", zv->zv_volsize);
    return 1;
}



char* net_lundman_zfs_zvol_device::getProductString(void)
{
  dprintf("getProduct %p\n", zv);
  if (zv && zv->zv_name) return zv->zv_name;
  return (char*)"ZVolume";
}



IOReturn net_lundman_zfs_zvol_device::reportBlockSize(UInt64 *blockSize)
{
  *blockSize = zv->zv_volblocksize;
  dprintf("reportBlockSize %llu\n", *blockSize);
  return kIOReturnSuccess;
}

IOReturn net_lundman_zfs_zvol_device::reportMaxValidBlock(UInt64 *maxBlock)
{
  *maxBlock = (zv->zv_volsize / zv->zv_volblocksize)-1 ; //-1
  dprintf("reportMaxValidBlock %llu\n", *maxBlock);
  return kIOReturnSuccess;
}

IOReturn net_lundman_zfs_zvol_device::reportMediaState(bool *mediaPresent, bool
   *changedState)
{
    *mediaPresent = true;

    *changedState = true;
    dprintf("reportMediaState\n");
    return kIOReturnSuccess;
}

IOReturn net_lundman_zfs_zvol_device::reportPollRequirements(bool *pollRequired,
   bool *pollIsExpensive)
{
    *pollRequired = true;
    *pollIsExpensive = false;
    dprintf("reportPollReq\n");
    return kIOReturnSuccess;
}

IOReturn net_lundman_zfs_zvol_device::reportRemovability(bool *isRemovable)
{
    *isRemovable = true;
    dprintf("reportRemova\n");
    return kIOReturnSuccess;
}




IOReturn net_lundman_zfs_zvol_device::doEjectMedia(void)
{
    dprintf("ejectMedia\n");
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doFormatMedia(UInt64 byteCapacity)
{
    dprintf("doFormat\n");
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doLockUnlockMedia(bool doLock)
{
    dprintf("doLockUnlock\n");
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doSynchronizeCache(void)
{
    dprintf("doSync\n");
    return kIOReturnSuccess;
}

char     *net_lundman_zfs_zvol_device::getVendorString(void)
{
    dprintf("getVendor\n");
    return  (char*)"ZVOL";
}

char     *net_lundman_zfs_zvol_device::getRevisionString(void)
{
    dprintf("getRevision\n");
    return  (char*)ZFS_META_VERSION;
}

char     *net_lundman_zfs_zvol_device::getAdditionalDeviceInfoString(void)
{
    dprintf("getAdditional\n");
    return  (char*)"ZFS Volume";
}

IOReturn  net_lundman_zfs_zvol_device::reportEjectability(bool *isEjectable)
{
    dprintf("reportEjecta\n");
    *isEjectable = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::reportLockability(bool *isLockable)
{
    dprintf("reportLocka\n");
    *isLockable = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::reportWriteProtection(bool *isWriteProtected)
{
    dprintf("reportWritePro\n");
    *isWriteProtected = false;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::getWriteCacheState(bool *enabled)
{
    dprintf("getCacheState\n");
    *enabled = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::setWriteCacheState(bool enabled)
{
    dprintf("setWriteCache\n");
    return kIOReturnSuccess;
}


// getMediaBlockSize()
//getDeviceTypeName
// 	status = messageClients ( type, arg, sizeof ( IOMediaState ) );
