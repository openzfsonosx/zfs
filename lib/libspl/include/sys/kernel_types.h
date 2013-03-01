#ifndef LIBSPL_SYS_KERNEL_TYPES_H
#define LIBSPL_SYS_KERNEL_TYPES_H

#undef vnode_t
#undef uio_t
#include_next <sys/kernel_types.h>
#define vnode_t struct vnode
#define uio_t struct uio


#endif
