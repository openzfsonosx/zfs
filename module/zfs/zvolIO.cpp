
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>

extern "C" {
  kern_return_t zfs_start (kmod_info_t * ki, void * d);
  kern_return_t zfs_stop (kmod_info_t * ki, void * d);
};

/*
 * Can those with more C++ experience clean this up?
 */
static void *global_c_interface = NULL;


// Define the superclass.
#define super IOService

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol, IOService)


bool net_lundman_zfs_zvol::init (OSDictionary* dict)
{
    bool res = super::init(dict);
    IOLog("IOKitTest::init\n");
    printf("zvolio:init\n");
    global_c_interface = (void *)this;
    zfs_start(NULL, NULL);
    return res;
}


void net_lundman_zfs_zvol::free (void)
{
    IOLog("IOKitTest::free\n");
    zfs_stop(NULL, NULL);
    global_c_interface = NULL;
    super::free();
}


IOService* net_lundman_zfs_zvol::probe (IOService* provider, SInt32* score)
{
    IOService *res = super::probe(provider, score);
    IOLog("IOKitTest::probe\n");
    return res;
}



bool net_lundman_zfs_zvol::start (IOService *provider)
{
    bool res = super::start(provider);
    IOLog("IOKitTest::start\n");

    // Allocate an IOBlockStorageDevice nub.
    // If you want one created on load.
    //if (createBlockStorageDevice(16*1024*1024, "TestVolume") == false)
    //  return false;

    return res;
}

void net_lundman_zfs_zvol::stop (IOService *provider)
{
    IOLog("IOKitTest::stop\n");
    super::stop(provider);
}

bool net_lundman_zfs_zvol::createBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = false;

    // Allocate a new IOBlockStorageDevice nub.
    nub = new net_lundman_zfs_zvol_device;
    if (nub == NULL)
        goto bail;

    // Call the custom init method (passing the overall disk size).
    if (nub->init(zv->zv_volsize) == false)
        goto bail;

    // Attach the IOBlockStorageDevice to the this driver.
    // This call increments the reference count of the nub object,
    // so we can release our reference at function exit.
    if (nub->attach(this) == false)
        goto bail;

    // Allow the upper level drivers to match against the IOBlockStorageDevice.
    nub->registerService();
    result = true;
 bail:
    // Unconditionally release the nub object.
    if (nub != NULL)
        nub->release();
    return result;
}

extern "C" int zvolCreateNewDevice(zvol_state_t *zv);

int zvolCreateNewDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->createBlockStorageDevice(zv);
    return 0;
}


IOByteCount net_lundman_zfs_zvol::performRead (IOMemoryDescriptor* dstDesc,
                                               UInt64 byteOffset,
                                               UInt64 byteCount)
{
    return dstDesc->writeBytes(0, (void*)((uintptr_t)m_buffer + byteOffset),
                               byteCount);
}

IOByteCount net_lundman_zfs_zvol::performWrite (IOMemoryDescriptor* srcDesc,
                                                UInt64 byteOffset,
                                                UInt64 byteCount)
{
    return srcDesc->readBytes(0, (void*)((uintptr_t)m_buffer + byteOffset), byteCount);
}








#undef super
/*
 * Device
 */

#include <IOKit/storage/IOBlockStorageDevice.h>

// Define the superclass
#define super IOBlockStorageDevice

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol_device, IOBlockStorageDevice)

#define kDiskBlockSize          512


bool net_lundman_zfs_zvol_device::init(UInt64 diskSize,
                                       OSDictionary *properties)
{
    printf("zolio_device:init\n");
    if (super::init(properties) == false)
        return false;
    m_blockCount = diskSize / kDiskBlockSize;
    this->setProperty(kIOBSDNameKey, "zvol"); // doesnt work
	//this->setProperty(kIOBSDNameKey, "nbd");
    //this->setProperty(kIOBSDMajorKey, 92);

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

UInt32 net_lundman_zfs_zvol_device::doGetFormatCapacities(UInt64* capacities,
                                                          UInt32 capacitiesMaxCount) const
{
    // Ensure that the array is sufficient to hold all our formats
    // (we require 1 element).
    if ((capacities != NULL) && (capacitiesMaxCount < 1))
      return 0;               // Error, return an array size of 0.
    // The caller may provide a NULL array if it wishes to query
    // the number of formats that we support.
    if (capacities != NULL)
        capacities[0] = m_blockCount * kDiskBlockSize;
    return 1;
}

char* net_lundman_zfs_zvol_device::getProductString(void)
{
    if (zv && zv->zv_name) return zv->zv_name;
    return (char*)"ZVolume";
}

IOReturn net_lundman_zfs_zvol_device::reportBlockSize(UInt64 *blockSize)
{
    *blockSize = kDiskBlockSize;
    return kIOReturnSuccess;
}
IOReturn net_lundman_zfs_zvol_device::reportMaxValidBlock(UInt64 *maxBlock)
{
    *maxBlock = m_blockCount-1;
    return kIOReturnSuccess;
}
IOReturn net_lundman_zfs_zvol_device::reportMediaState(bool *mediaPresent, bool
   *changedState)
{
    *mediaPresent = true;

    *changedState = false;
    return kIOReturnSuccess;
}
IOReturn net_lundman_zfs_zvol_device::reportPollRequirements(bool *pollRequired,
   bool *pollIsExpensive)
{
    *pollRequired = false;
    *pollIsExpensive = false;
    return kIOReturnSuccess;
}
IOReturn net_lundman_zfs_zvol_device::reportRemovability(bool *isRemovable)
{
    *isRemovable = true;
    return kIOReturnSuccess;
}
IOReturn net_lundman_zfs_zvol_device::doAsyncReadWrite(
    IOMemoryDescriptor *buffer, UInt64 block, UInt64 nblks,
    IOStorageAttributes *attributes, IOStorageCompletion *completion)
{
    IODirection               direction;
    IOByteCount               actualByteCount;
    // Return errors for incoming I/O if we have been terminated.
    if (isInactive() == true)
        return kIOReturnNotAttached;
    // Ensure the block range being targeted is within the disk’s capacity.
    if ((block + nblks) > m_blockCount)
        return kIOReturnBadArgument;
    // Get the buffer’s direction, which indicates whether the operation is a read or a write.
    direction = buffer->getDirection();
    if ((direction != kIODirectionIn) && (direction != kIODirectionOut))
        return kIOReturnBadArgument;
    // Perform the read or write operation through the transport driver.
    if (direction == kIODirectionIn) {

      //if (!zvol_read(zv, uio, cr)) {
      if (0) {

      } else {
        actualByteCount = 0;
      }

        actualByteCount = m_provider->performRead(buffer, (block*kDiskBlockSize),
                                                  (nblks*kDiskBlockSize));
    } else {
        actualByteCount = m_provider->performWrite(buffer, (block*kDiskBlockSize),
                                                   (nblks*kDiskBlockSize));
    }
    // Call the completion function.
    (completion->action)(completion->target, completion->parameter, kIOReturnSuccess,
                         actualByteCount);
    return kIOReturnSuccess;
}



IOReturn net_lundman_zfs_zvol_device::doEjectMedia(void)
{
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doFormatMedia(UInt64 byteCapacity)
{
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doLockUnlockMedia(bool doLock)
{
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::doSynchronizeCache(void)
{
    return kIOReturnSuccess;
}

char     *net_lundman_zfs_zvol_device::getVendorString(void)
{
    return  (char*)"ZVOL";
}

char     *net_lundman_zfs_zvol_device::getRevisionString(void)
{
    return  (char*)ZFS_META_VERSION;
}

char     *net_lundman_zfs_zvol_device::getAdditionalDeviceInfoString(void)
{
    return  (char*)"ZFS Volume";
}

IOReturn  net_lundman_zfs_zvol_device::reportEjectability(bool *isEjectable)
{
    *isEjectable = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::reportLockability(bool *isLockable)
{
    *isLockable = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::reportWriteProtection(bool *isWriteProtected)
{
    *isWriteProtected = false;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::getWriteCacheState(bool *enabled)
{
    *enabled = true;
    return kIOReturnSuccess;
}

IOReturn  net_lundman_zfs_zvol_device::setWriteCacheState(bool enabled)
{
    return kIOReturnSuccess;
}
