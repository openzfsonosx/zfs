//
//  vdevIO.cpp
//  zfs
//
//  Created by Evan Susarret on 5/8/14.
//
//

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
//#include <IOKit/IOBSD.h>
    
#include <sys/vdev_iokit.h>
#include <sys/vdev_iokit_context.h>

//#include <IOKit/IOStoragePool.h>

// Define the superclass
#define super IOCommand

OSDefineMetaClassAndStructors(net_lundman_vdev_io_context,IOCommand)

inline bool net_lundman_vdev_io_context::init(OSDictionary *dict)
{
    zio =   0;
    

    /* 
//old//    buffer =                new IOMemoryDescriptor;
     * static IOMemoryDescriptor *withOptions( void *buffers, UInt32 count,
     *                      UInt32 offset, task_t task, IOOptionBits options,
     *                      IOMapper *mapper = kIOMapperSystem);
     * IODirection forDirection = kIODirectionNone
     */
    
    completion.target =    0;
    completion.parameter = this;
    completion.action =    (IOStorageCompletionAction) &vdev_iokit_io_intr;
    
    return true;
}

inline void net_lundman_vdev_io_context::free()
{
    zio =   0;
    
    if (buffer)
        buffer->release();
    
    buffer = 0;
    
    completion.target =    0;
    completion.parameter = 0;
    completion.action =    0;
    
    super::free();
}

inline bool net_lundman_vdev_io_context::initWithTransfer(zio_t * new_zio)
{
    /* NULL new_zio should be valid for pre-allocation of resources */
    if (!new_zio)
        return false;
    
    /* Pre-initialize */
    if ( !init() ) {
        vdev_iokit_log("ZFS: initWithTransfer: failed");
        return false;
    }
    
    /* XXX TO DO 
     *  Currently requires a new_zio
     */
    
    //    buffer =                IOBufferMemoryDescriptor::withAddress(&completion,1,(zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn));
    //buffer =                IOMemoryDescriptor::withAddress(&completion,1,(new_zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn));
    
//    buffer =                IOBufferMemoryDescriptor::withOptions(kIODirectionOutIn,256*1024,PAGE_SIZE);
  
    buffer =            0;
//    if (!buffer)
//        return false;
    
    //old//    buffer->init();
    
    if (new_zio)
        configure(new_zio);
    
    return true;
}

inline bool net_lundman_vdev_io_context::initWithDirection(IODirection new_direction)
{
    /* Pre-initialize */
    if ( !init() ) {
        vdev_iokit_log("ZFS: initWithDirection: failed");
        return false;
    }
    
    direction =             new_direction;
    
    //buffer =                IOBufferMemoryDescriptor::withAddress(&completion,1,direction);
    //buffer =                IOBufferMemoryDescriptor::withOptions(direction,256*1024,PAGE_SIZE);

    buffer =                0;
    
//    if (!buffer)
//        return false;
    
    //old//    buffer->init();
    
    return true;
}
    
IOCommand* net_lundman_vdev_io_context::withTransfer(zio_t * new_zio)
{
    /* NULL new_zio is valid - pre-allocation of resources */
    /*
    if (!new_zio)
        return 0;
    */
    net_lundman_vdev_io_context * new_context =     new net_lundman_vdev_io_context;
    
    if (!new_context)
        return 0;
    
    if (! new_context->initWithTransfer(new_zio) ) {
        new_context->release();
        new_context = 0;
        return 0;
    }
    
    return new_context;
}
    
IOCommand* net_lundman_vdev_io_context::withDirection(IODirection new_direction) {
    net_lundman_vdev_io_context * new_context =     new net_lundman_vdev_io_context;
    
    if (!new_context)
        return 0;
    
    if (! new_context->initWithDirection(new_direction) ) {
        new_context->release();
        new_context = 0;
        return 0;
    }
    
    return new_context;
}
    
bool net_lundman_vdev_io_context::configure(zio_t * new_zio)
{
    if (!new_zio)
        return false;
    
    zio =       new_zio;
    
    /*
     * withAddress will re-use the buffer object
     */
    if (buffer) {
        buffer->release();
    }
    
    //    buffer->withOptions(direction, zio->io_size, PAGE_SIZE);
    
    buffer = (IOBufferMemoryDescriptor*)IOBufferMemoryDescriptor::withAddress(zio->io_data, zio->io_size, direction);

    //(zio->io_type == ZIO_TYPE_WRITE ? kIODirectionOut : kIODirectionIn)
    
    return true;
}
    
/* Prepare buffer for I/O */
bool net_lundman_vdev_io_context::prepare()
{
    return ( buffer->prepare(kIODirectionNone) == kIOReturnSuccess );
}

/* Inform buffer that I/O is complete */
bool net_lundman_vdev_io_context::complete()
{
    return ( buffer->complete(kIODirectionNone) == kIOReturnSuccess );
}
    
/* Reset memory buffer and zio */
bool net_lundman_vdev_io_context::reset()
{
    zio = 0;
    
    /* Release buffer object */
    if (buffer) {
        buffer->release();
        buffer = 0;
//        buffer->withAddress(&completion,1,direction);
    }
    
    return 0;
}
 
#ifdef __cplusplus
}
#endif /* __cplusplus */
