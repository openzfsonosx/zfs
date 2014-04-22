/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2014 Jorgen Lundman <lundman@lundman.net>
 */

#include <sys/zfs_context.h>
#include <sys/fm/fs/zfs.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/ddt.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_disk.h>
#include <sys/metaslab.h>
#include <sys/metaslab_impl.h>
#include <sys/uberblock_impl.h>
#include <sys/txg.h>
#include <sys/avl.h>
#include <sys/dmu_traverse.h>
#include <sys/dmu_objset.h>
#include <sys/unique.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_synctask.h>
#include <sys/fs/zfs.h>
#include <sys/arc.h>
#include <sys/callb.h>
#include <sys/systeminfo.h>
#include <sys/spa_boot.h>
#include <sys/zfs_ioctl.h>
#include <sys/dsl_scan.h>
#include <sys/zfeature.h>
#include <sys/zfs_context.h>
#include <sys/dsl_destroy.h>
#include <sys/zvol.h>

#ifdef	_KERNEL
#include <sys/bootprops.h>
#include <sys/callb.h>
#include <sys/cpupart.h>
#include <sys/pool.h>
#include <sys/sysdc.h>
#include <sys/zone.h>
#include <sys/vnode.h>
#endif	/* _KERNEL */


typedef struct osx_datasets {
    char *osx_name;
    void *osx_node;  // ptr to the iokit entity
    list_node_t     osx_next;
} osx_datasets_t;


int
spa_osx_create_devs(const char *dsname, void *arg)
{
    list_t *list = (list_t *)arg;
    osx_datasets_t *osd;

    osd = kmem_alloc(sizeof(osx_datasets_t), KM_SLEEP);
    if (osd) {
        osd->osx_name = spa_strdup(dsname);
        list_insert_head(list, osd);
    }

    return (0);
}


osx_datasets_t *spa_osx_find_parent(list_t *list, char *name)
{
    osx_datasets_t *ods;

    for ((ods = list_head(list));
         ods;
         (ods = list_next(list, ods))) {
        if (!strcmp(ods->osx_name, name)) return ods;
    }
    return NULL;
}


/*
 * Create a new /dev/ entry here. parent points to the parent node, if there
 * if one. Or parent=NULL to create a POOL, ie, new top level entry.
 * Return the newly created node.
 */
void *spa_osx_create_node(void *parent,
                          char *name)
{
    void *node;

    node = spa_get_random(-1ULL);

    printf("   parent '%p' create '%s' type '%s' -> %p\n",
           parent, name,
           parent ? "dataset" : "pool",
           node);
    return node;
}




void spa_osx_create_nodes(char *poolname)
{
    list_t datasets;
    osx_datasets_t *ods, *parent;
    char *slash;

    printf("Importing pool '%s'\n", poolname);
    // Create a list, so we can process it in reverse
    list_create(&datasets, sizeof(osx_datasets_t),
                offsetof(osx_datasets_t, osx_next));

    dmu_objset_find(poolname, spa_osx_create_devs,
                    &datasets, DS_FIND_CHILDREN);

    parent = NULL;

    for ((ods = list_head(&datasets));
         ods;
         (ods = list_next(&datasets, ods))) {

        parent = NULL;

        // Split at last "/"
        slash = strrchr(ods->osx_name, '/');

        if (slash) {
            *slash = 0;
            parent = spa_osx_find_parent(&datasets, ods->osx_name);
            *slash = '/';
        }

        // Create the node, passing the parent.
        ods->osx_node = spa_osx_create_node(parent?parent->osx_node:NULL,
                                            ods->osx_name);

    }

    while((ods = list_head(&datasets))) {
        list_remove(&datasets, ods);
        spa_strfree(ods->osx_name);
        kmem_free(ods, sizeof (osx_datasets_t));
    }
    list_destroy(&datasets);
}
