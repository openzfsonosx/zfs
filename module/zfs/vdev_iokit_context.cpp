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

#include <sys/vdev_iokit.h>
#include <sys/vdev_iokit_context.h>

// Define the superclass
#define	super IOCommand

OSDefineMetaClassAndStructors(net_lundman_vdev_io_context, IOCommand)

inline bool
net_lundman_vdev_io_context::init(OSDictionary *dict)
{
	zio = 0;

	completion.target = 0;
	completion.parameter = this;
	completion.action = (IOStorageCompletionAction) &vdev_iokit_io_intr;

	return (true);
}

inline void
net_lundman_vdev_io_context::free()
{
	zio = 0;

	if (buffer)
		buffer->release();

	buffer = 0;

	completion.target = 0;
	completion.parameter = 0;
	completion.action = 0;

	super::free();
}

inline bool
	net_lundman_vdev_io_context::initWithTransfer(zio_t * new_zio)
{
	/* NULL new_zio should be valid for pre-allocation of resources */
	if (!new_zio)
		return (false);

	/* Pre-initialize */
	if (!init()) {
		vdev_iokit_log("initWithTransfer: failed");
		return (false);
	}

	buffer = 0;

	if (new_zio)
		configure(new_zio);

	return (true);
}

inline bool
net_lundman_vdev_io_context::initWithDirection(IODirection new_direction)
{
	/* Pre-initialize */
	if (!init()) {
		vdev_iokit_log("initWithDirection: failed");
		return (false);
	}

	direction = new_direction;

	buffer = 0;

	return (true);
}

IOCommand *
net_lundman_vdev_io_context::withTransfer(zio_t * new_zio)
{
	/* NULL new_zio is valid - pre-allocation of resources */
	net_lundman_vdev_io_context * new_context =
					new net_lundman_vdev_io_context;

	if (!new_context)
		return (0);

	if (! new_context->initWithTransfer(new_zio)) {
		new_context->release();
		new_context = 0;
		return (0);
	}

	return (new_context);
}

IOCommand *
net_lundman_vdev_io_context::withDirection(IODirection new_direction) {
	net_lundman_vdev_io_context * new_context =
					new net_lundman_vdev_io_context;

	if (!new_context)
		return (0);

	if (! new_context->initWithDirection(new_direction)) {
		new_context->release();
		new_context = 0;
		return (0);
	}

	return (new_context);
}

bool
net_lundman_vdev_io_context::configure(zio_t * new_zio)
{
	if (!new_zio)
		return (false);

	zio = new_zio;

	/*
	 * initWithAddress can re-use the buffer object
	 */
	if (buffer) {
		buffer->release();
	}

	buffer = (IOBufferMemoryDescriptor*)
		IOBufferMemoryDescriptor::withAddress(
			zio->io_data, zio->io_size, direction);

	return (true);
}

/* Prepare buffer for I/O */
bool
net_lundman_vdev_io_context::prepare()
{
	return (buffer->prepare(kIODirectionNone) == kIOReturnSuccess);
}

/* Inform buffer that I/O is complete */
bool
net_lundman_vdev_io_context::complete()
{
	return (buffer->complete(kIODirectionNone) == kIOReturnSuccess);
}

/* Reset memory buffer and zio */
bool
net_lundman_vdev_io_context::reset()
{
	zio = 0;

	/* Release buffer object */
	if (buffer) {
		buffer->release();
		buffer = 0;
	}

	return (0);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
