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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/fstyp.h>
#include <sys/vfs.h>
#include <sys/kmem.h>
#include <sys/mntent.h>

#ifndef __APPLE__
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/user.h>
#endif /* !__APPLE__ */

#include <sys/fstyp.h>
#include <sys/kmem.h>

#ifndef __APPLE__
#include <sys/systm.h>
#include <sys/proc.h>
#endif /* !__APPLE__ */

#include <sys/mount.h>
#include <sys/vfs.h>

#ifndef __APPLE__
#include <sys/vfs_opreg.h>
#include <sys/fem.h>
#endif /* !__APPLE__ */

#include <sys/mntent.h>

#ifndef __APPLE__
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/statfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/rwstlock.h>
#include <sys/dnlc.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/swap.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/pathname.h>
#include <sys/bootconf.h>
#include <sys/dumphdr.h>
#include <sys/dc_ki.h>
#include <sys/poll.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/policy.h>
#include <sys/ctfs.h>
#include <sys/objfs.h>
#include <sys/console.h>
#include <sys/reboot.h>
#include <sys/attr.h>
#include <sys/zio.h>
#include <sys/spa.h>
#include <sys/lofi.h>
#include <sys/bootprops.h>
#endif /* !__APPLE__ */

#define dprintf printf

static char ** vfs_mergecancelopts(const mntopt_t *, const mntopt_t *);
static void vfs_clearmntopt_nolock(mntopts_t *, const char *, int);
static void vfs_freeopt(mntopt_t *);
static void vfs_copyopt(const mntopt_t *s, mntopt_t *d);
static void vfs_copyopttbl_extend(const mntopts_t *, mntopts_t *, int);
static void vfs_createopttbl_extend(mntopts_t *, const char *,
    const mntopts_t *);
static char **vfs_copycancelopt_extend(char **const, int);
static void vfs_freecancelopt(char **);

/*
 * Table for generic options recognized in the VFS layer and acted
 * on at this level before parsing file system specific options.
 * The nosuid option is stronger than any of the devices and setuid
 * options, so those are canceled when nosuid is seen.
 *
 * All options which are added here need to be added to the
 * list of standard options in usr/src/cmd/fs.d/fslib.c as well.
 */
/*
 * VFS Mount options table
 */
static char *ro_cancel[] = { MNTOPT_RW, NULL };
static char *rw_cancel[] = { MNTOPT_RO, NULL };
static char *suid_cancel[] = { MNTOPT_NOSUID, NULL };
static char *nosuid_cancel[] = { MNTOPT_SUID, MNTOPT_DEVICES, MNTOPT_NODEVICES,
    MNTOPT_NOSETUID, MNTOPT_SETUID, NULL };
static char *devices_cancel[] = { MNTOPT_NODEVICES, NULL };
static char *nodevices_cancel[] = { MNTOPT_DEVICES, NULL };
static char *setuid_cancel[] = { MNTOPT_NOSETUID, NULL };
static char *nosetuid_cancel[] = { MNTOPT_SETUID, NULL };
static char *nbmand_cancel[] = { MNTOPT_NONBMAND, NULL };
static char *nonbmand_cancel[] = { MNTOPT_NBMAND, NULL };
static char *exec_cancel[] = { MNTOPT_NOEXEC, NULL };
static char *noexec_cancel[] = { MNTOPT_EXEC, NULL };

static const mntopt_t mntopts[] = {
/*
 *	option name		cancel options		default arg	flags
 */
	{ MNTOPT_REMOUNT,	NULL,			NULL,
		MO_NODISPLAY, (void *)0 },
	{ MNTOPT_RO,		ro_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_RW,		rw_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_SUID,		suid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOSUID,	nosuid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_DEVICES,	devices_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NODEVICES,	nodevices_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_SETUID,	setuid_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOSETUID,	nosetuid_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_NBMAND,	nbmand_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NONBMAND,	nonbmand_cancel,	NULL,		0,
		(void *)0 },
	{ MNTOPT_EXEC,		exec_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOEXEC,	noexec_cancel,		NULL,		0,
		(void *)0 },
};

const mntopts_t vfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	(mntopt_t *)&mntopts[0]
};

static char **
vfs_mergecancelopts(const mntopt_t *mop1, const mntopt_t *mop2)
{
	dprintf("+vfs_mergecancelopts\n");
	int c1 = 0;
	int c2 = 0;
	char **result;
	char **sp1, **sp2, **dp;

	/*
	 * First we count both lists of cancel options.
	 * If either is NULL or has no elements, we return a copy of
	 * the other.
	 */
	if (mop1->mo_cancel != NULL) {
		for (; mop1->mo_cancel[c1] != NULL; c1++)
			/* count cancel options in mop1 */;
	}

	if (c1 == 0)
		return (vfs_copycancelopt_extend(mop2->mo_cancel, 0));

	if (mop2->mo_cancel != NULL) {
		for (; mop2->mo_cancel[c2] != NULL; c2++)
			/* count cancel options in mop2 */;
	}

	result = vfs_copycancelopt_extend(mop1->mo_cancel, c2);

	if (c2 == 0)
		return (result);

	/*
	 * When we get here, we've got two sets of cancel options;
	 * we need to merge the two sets.  We know that the result
	 * array has "c1+c2+1" entries and in the end we might shrink
	 * it.
	 * Result now has a copy of the c1 entries from mop1; we'll
	 * now lookup all the entries of mop2 in mop1 and copy it if
	 * it is unique.
	 * This operation is O(n^2) but it's only called once per
	 * filesystem per duplicate option.  This is a situation
	 * which doesn't arise with the filesystems in ON and
	 * n is generally 1.
	 */

	dp = &result[c1];
	for (sp2 = mop2->mo_cancel; *sp2 != NULL; sp2++) {
		for (sp1 = mop1->mo_cancel; *sp1 != NULL; sp1++) {
			if (strcmp(*sp1, *sp2) == 0)
				break;
		}
		if (*sp1 == NULL) {
			/*
			 * Option *sp2 not found in mop1, so copy it.
			 * The calls to vfs_copycancelopt_extend()
			 * guarantee that there's enough room.
			 */
			*dp = kmem_alloc(strlen(*sp2) + 1, KM_SLEEP);
			(void) strcpy(*dp++, *sp2);
		}
	}
	if (dp != &result[c1+c2]) {
		size_t bytes = (dp - result + 1) * sizeof (char *);
		char **nres = kmem_alloc(bytes, KM_SLEEP);

		bcopy(result, nres, bytes);
		kmem_free(result, (c1 + c2 + 1) * sizeof (char *));
		result = nres;
	}
	dprintf("-vfs_mergecancelopts\n");
	return (result);
}

/*
 * Merge two mount option tables (outer and inner) into one.  This is very
 * similar to "merging" global variables and automatic variables in C.
 *
 * This isn't (and doesn't have to be) fast.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect omo, imo & dmo.
 */
void
vfs_mergeopttbl(const mntopts_t *omo, const mntopts_t *imo, mntopts_t *dmo)
{
	dprintf("+vfs_mergeopttbl\n");

	if(omo != NULL && imo != NULL) {
		dprintf("omo count %d : imo count %d\n", omo->mo_count, imo->mo_count);
	}

	uint_t i, count;
	mntopt_t *mop, *motbl;
	uint_t freeidx;

	/*
	 * First determine how much space we need to allocate.
	 */
	count = omo->mo_count;
	for (i = 0; i < imo->mo_count; i++) {
		if (imo->mo_list[i].mo_flags & MO_EMPTY)
			continue;
		if (vfs_hasopt(omo, imo->mo_list[i].mo_name) == NULL)
			count++;
	}
	ASSERT(count >= omo->mo_count &&
	    count <= omo->mo_count + imo->mo_count);
	motbl = kmem_alloc(count * sizeof (mntopt_t), KM_SLEEP);
	for (i = 0; i < omo->mo_count; i++)
		vfs_copyopt(&omo->mo_list[i], &motbl[i]);
	freeidx = omo->mo_count;
	for (i = 0; i < imo->mo_count; i++) {
		if (imo->mo_list[i].mo_flags & MO_EMPTY)
			continue;
		if ((mop = vfs_hasopt(omo, imo->mo_list[i].mo_name)) != NULL) {
			char **newcanp;
			uint_t index = mop - omo->mo_list;

			newcanp = vfs_mergecancelopts(mop, &motbl[index]);

			vfs_freeopt(&motbl[index]);
			vfs_copyopt(&imo->mo_list[i], &motbl[index]);

			vfs_freecancelopt(motbl[index].mo_cancel);
			motbl[index].mo_cancel = newcanp;
		} else {
			/*
			 * If it's a new option, just copy it over to the first
			 * free location.
			 */
			vfs_copyopt(&imo->mo_list[i], &motbl[freeidx++]);
		}
	}
	dmo->mo_count = count;
	dmo->mo_list = motbl;
	dprintf("-vfs_mergeopttbl\n");
}



/*
 * Functions to set and clear mount options in a mount options table.
 */

/*
 * Clear a mount option, if it exists.
 *
 * The update_mnttab arg indicates whether mops is part of a vfs that is on
 * the vfs list.
 */
static void
vfs_clearmntopt_nolock(mntopts_t *mops, const char *opt, int update_mnttab)
{
	dprintf("+vfs_clearmntopt_nolock\n");
	struct mntopt *mop;
	uint_t i, count;

	//ASSERT(!update_mnttab || RW_WRITE_HELD(&vfslist));
	ASSERT(!update_mnttab);

	count = mops->mo_count;
	dprintf("mops mo_count is %d\n", count);
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;
		if (strcmp(opt, mop->mo_name))
			continue;
		mop->mo_flags &= ~MO_SET;
		if (mop->mo_arg != NULL) {
			kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
		}
		mop->mo_arg = NULL;
		//if (update_mnttab)
		//	vfs_mnttab_modtimeupd();
		break;
	}
	dprintf("-vfs_clearmntopt_nolock\n");
}

void
vfs_clearmntopt(struct illumos_vfs *vfsp, const char *opt)
{
	dprintf("+vfs_clearmntopt\n");

	int gotlock = 0;

#if 0
	if (VFS_ON_LIST(vfsp)) {
		gotlock = 1;
		vfs_list_lock();
	}
#endif
	vfs_clearmntopt_nolock(&vfsp->vfs_mntopts, opt, gotlock);
#if 0
	if (gotlock)
		vfs_list_unlock();
#endif
	dprintf("-vfs_clearmntopt\n");
}


/*
 * Set a mount option on.  If it's not found in the table, it's silently
 * ignored.  If the option has MO_IGNORE set, it is still set unless the
 * VFS_NOFORCEOPT bit is set in the flags.  Also, VFS_DISPLAY/VFS_NODISPLAY flag
 * bits can be used to toggle the MO_NODISPLAY bit for the option.
 * If the VFS_CREATEOPT flag bit is set then the first option slot with
 * MO_EMPTY set is created as the option passed in.
 *
 * The update_mnttab arg indicates whether mops is part of a vfs that is on
 * the vfs list.
 */
void
vfs_setmntopt_nolock(mntopts_t *mops, const char *opt,
    const char *arg, int flags, int update_mnttab)
{
	dprintf("+vfs_setmntopt_nolock\n");
        mntopt_t *mop;
        uint_t i, count;
        char *sp;

        //ASSERT(!update_mnttab || RW_WRITE_HELD(&vfslist));
        ASSERT(!update_mnttab);

        if (flags & VFS_CREATEOPT) {
                if (vfs_hasopt(mops, opt) != NULL) {
                        flags &= ~VFS_CREATEOPT;
                }
        }
        count = mops->mo_count;
	dprintf("mops mo_count is %d\n", count);
        for (i = 0; i < count; i++) {
                mop = &mops->mo_list[i];

                if (mop->mo_flags & MO_EMPTY) {
                        if ((flags & VFS_CREATEOPT) == 0)
                                continue;
                        sp = kmem_alloc(strlen(opt) + 1, KM_SLEEP);
                        (void) strcpy(sp, opt);
                        mop->mo_name = sp;
                        if (arg != NULL)
                                mop->mo_flags = MO_HASVALUE;
                        else
                                mop->mo_flags = 0;
                } else if (strcmp(opt, mop->mo_name)) {
                        continue;
                }
                if ((mop->mo_flags & MO_IGNORE) && (flags & VFS_NOFORCEOPT))
                        break;
                if (arg != NULL && (mop->mo_flags & MO_HASVALUE) != 0) {
                        sp = kmem_alloc(strlen(arg) + 1, KM_SLEEP);
                        (void) strcpy(sp, arg);
                } else {
                        sp = NULL;
                }
                if (mop->mo_arg != NULL)
                        kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
                mop->mo_arg = sp;
                if (flags & VFS_DISPLAY)
                        mop->mo_flags &= ~MO_NODISPLAY;
                if (flags & VFS_NODISPLAY)
                        mop->mo_flags |= MO_NODISPLAY;
                mop->mo_flags |= MO_SET;
                if (mop->mo_cancel != NULL) {
                        char **cp;

                        for (cp = mop->mo_cancel; *cp != NULL; cp++)
                                vfs_clearmntopt_nolock(mops, *cp, 0);
                }
                //if (update_mnttab)
                //        vfs_mnttab_modtimeupd();
                break;
        }
	dprintf("-vfs_setmntopt_nolock\n");
}

void
vfs_setmntopt(struct illumos_vfs *vfsp, const char *opt, const char *arg, int flags)
{
	dprintf("+vfs_setmntopt\n");

        int gotlock = 0;

#if 0
        if (VFS_ON_LIST(vfsp)) {
		gotlock = 1;
                vfs_list_lock();
        }
#endif
        vfs_setmntopt_nolock(&vfsp->vfs_mntopts, opt, arg, flags, gotlock);
#if 0
        if (gotlock)
                vfs_list_unlock();
#endif
	dprintf("-vfs_setmntopt\n");
}

void
vfs_parsemntopts(mntopts_t *mops, char *osp, int create)
{
	printf("+vfs_parsemntopts\n");
	char *s = osp, *p, *nextop, *valp, *cp, *ep;
	int setflg = VFS_NOFORCEOPT;

printf("vfs_parsemntopts : mops p %p : osp p %p : osp s %s : create d %d\n", mops, osp, osp, create);
	if (osp == NULL)
		return;
	while (*s != '\0') {
		p = strchr(s, ',');	/* find next option */
		if (p == NULL) {
			cp = NULL;
			p = s + strlen(s);
		} else {
			cp = p;		/* save location of comma */
			*p++ = '\0';	/* mark end and point to next option */
		}
		nextop = p;
		p = strchr(s, '=');	/* look for value */
		if (p == NULL) {
			valp = NULL;	/* no value supplied */
		} else {
			ep = p;		/* save location of equals */
			*p++ = '\0';	/* end option and point to value */
			valp = p;
		}
		/*
		 * set option into options table
		 */
		if (create)
			setflg |= VFS_CREATEOPT;
		vfs_setmntopt_nolock(mops, s, valp, setflg, 0);
		if (cp != NULL)
			*cp = ',';	/* restore the comma */
		if (valp != NULL)
			*ep = '=';	/* restore the equals */
		s = nextop;
	}
	printf("-vfs_parsemntopts\n");
}

/*
 * Function to inquire if an option exists in a mount options table.
 * Returns a pointer to the option if it exists, else NULL.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mops.
 */
struct mntopt *
vfs_hasopt(const mntopts_t *mops, const char *opt)
{
        dprintf("+vfs_hasopt\n");
        struct mntopt *mop;
        uint_t i, count;

        count = mops->mo_count;
        for (i = 0; i < count; i++) {
                mop = &mops->mo_list[i];

                if (mop->mo_flags & MO_EMPTY)
                        continue;
                if (strcmp(opt, mop->mo_name) == 0)
                {
                        dprintf("-vfs_hasopt 1\n");
                        return (mop);
                }
        }
        dprintf("-vfs_hasopt 2\n");
        return (NULL);
}

/*
 * Function to inquire if an option is set in a mount options table.
 * Returns non-zero if set and fills in the arg pointer with a pointer to
 * the argument string or NULL if there is no argument string.
 */
int
vfs_optionisset_nolock(const mntopts_t *mops, const char *opt, char **argp)
{
	dprintf("+vfs_optionisset_nolock\n");
	struct mntopt *mop;
	uint_t i, count;

	count = mops->mo_count;
	for (i = 0; i < count; i++) {
		mop = &mops->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;
		if (strcmp(opt, mop->mo_name))
			continue;
		if ((mop->mo_flags & MO_SET) == 0) {
			dprintf("-vfs_optionisset_nolock ret 0 1st\n");
			return (0);
		}
		if (argp != NULL && (mop->mo_flags & MO_HASVALUE) != 0)
			*argp = mop->mo_arg;
		dprintf("-vfs_optionisset_nolock ret 1\n");
		return (1);
	}
	dprintf("-vfs_optionisset_nolock ret 0 2nd\n");
	return (0);
}


int
vfs_optionisset(const struct illumos_vfs *vfsp, const char *opt, char **argp)
{
	dprintf("+vfs_optionisset\n");
	int ret;

#if 0
	vfs_list_read_lock();
#endif
	ret = vfs_optionisset_nolock(&vfsp->vfs_mntopts, opt, argp);
#if 0
	vfs_list_unlock();
#endif

	dprintf("-vfs_optionisset\n");
	return (ret);
}

/*
 * Construct a comma separated string of the options set in the given
 * mount table, return the string in the given buffer.  Return non-zero if
 * the buffer would overflow.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mp.
 */
int
vfs_buildoptionstr(const mntopts_t *mp, char *buf, int len)
{
	char *cp;
	uint_t i;

	buf[0] = '\0';
	cp = buf;
printf("mp p %p, buf p %p, len %d\n", mp, buf, len);
printf("mp->mo_count d %d\n", mp->mo_count);
	for (i = 0; i < mp->mo_count; i++) {
		struct mntopt *mop;
		mop = &mp->mo_list[i];
printf("mop->mo_flags & MO_SET d %d\n", mop->mo_flags & MO_SET);
printf("mop->mo_name %s\n", mop->mo_name);
		if (mop->mo_flags & MO_SET) {
			int optlen, comma = 0;

			if (buf[0] != '\0')
				comma = 1;
			optlen = strlen(mop->mo_name);
			if (strlen(buf) + comma + optlen + 1 > len)
				goto err;
			if (comma)
				*cp++ = ',';
			(void) strcpy(cp, mop->mo_name);
			cp += optlen;
			/*
			 * Append option value if there is one
			 */
			if (mop->mo_arg != NULL) {
				int arglen;

				arglen = strlen(mop->mo_arg);
				if (strlen(buf) + arglen + 2 > len)
					goto err;
				*cp++ = '=';
				(void) strcpy(cp, mop->mo_arg);
				cp += arglen;
			}
		}
	}
	return (0);
err:
	return (EOVERFLOW);
}

/*
 * Create an empty options table with enough empty slots to hold all
 * The options in the options string passed as an argument.
 * Potentially prepend another options table.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mops.
 */
static void
vfs_createopttbl_extend(mntopts_t *mops, const char *opts,
    const mntopts_t *mtmpl)
{
	dprintf("+vfs_createopttbl_extend\n");
	const char *s = opts;
	uint_t count;

	if (opts == NULL || *opts == '\0') {
		count = 0;
	} else {
		count = 1;

		/*
		 * Count number of options in the string
		 */
		for (s = strchr(s, ','); s != NULL; s = strchr(s, ',')) {
			count++;
			s++;
		}
	}
	vfs_copyopttbl_extend(mtmpl, mops, count);
	dprintf("-vfs_createopttbl_extend\n");
}

/*
 * Swap two mount options tables
 */
void
vfs_swapopttbl_nolock(mntopts_t *optbl1, mntopts_t *optbl2)
{
	uint_t tmpcnt;
	mntopt_t *tmplist;

	tmpcnt = optbl2->mo_count;
	tmplist = optbl2->mo_list;
	optbl2->mo_count = optbl1->mo_count;
	optbl2->mo_list = optbl1->mo_list;
	optbl1->mo_count = tmpcnt;
	optbl1->mo_list = tmplist;
}

void
vfs_swapopttbl(mntopts_t *optbl1, mntopts_t *optbl2)
{
	//vfs_list_lock();
	vfs_swapopttbl_nolock(optbl1, optbl2);
	//vfs_mnttab_modtimeupd();
	//vfs_list_unlock();
}

static char **
vfs_copycancelopt_extend(char **const moc, int extend)
{
	int i = 0;
	int j;
	char **result;

	if (moc != NULL) {
		for (; moc[i] != NULL; i++)
			/* count number of options to cancel */;
	}

	if (i + extend == 0)
		return (NULL);

	result = kmem_alloc((i + extend + 1) * sizeof (char *), KM_SLEEP);

	for (j = 0; j < i; j++) {
		result[j] = kmem_alloc(strlen(moc[j]) + 1, KM_SLEEP);
		(void) strcpy(result[j], moc[j]);
	}
	for (; j <= i + extend; j++)
		result[j] = NULL;

	return (result);
}


static void
vfs_copyopt(const mntopt_t *s, mntopt_t *d)
{
	char *sp, *dp;

	d->mo_flags = s->mo_flags;
	d->mo_data = s->mo_data;
	sp = s->mo_name;
	if (sp != NULL) {
		dp = kmem_alloc(strlen(sp) + 1, KM_SLEEP);
		(void) strcpy(dp, sp);
		d->mo_name = dp;
	} else {
		d->mo_name = NULL; /* should never happen */
	}

	d->mo_cancel = vfs_copycancelopt_extend(s->mo_cancel, 0);

	sp = s->mo_arg;
	if (sp != NULL) {
		dp = kmem_alloc(strlen(sp) + 1, KM_SLEEP);
		(void) strcpy(dp, sp);
		d->mo_arg = dp;
	} else {
		d->mo_arg = NULL;
	}
}

/*
 * Copy a mount options table, possibly allocating some spare
 * slots at the end.  It is permissible to copy_extend the NULL table.
 */
static void
vfs_copyopttbl_extend(const mntopts_t *smo, mntopts_t *dmo, int extra)
{
	dprintf("+vfs_copyopttbl_extend\n");
	uint_t i, count;
	mntopt_t *motbl;

	/*
	 * Clear out any existing stuff in the options table being initialized
	 */
	vfs_freeopttbl(dmo);
	count = (smo == NULL) ? 0 : smo->mo_count;
	if ((count + extra) == 0)	/* nothing to do */
		return;
	dmo->mo_count = count + extra;
	motbl = kmem_zalloc((count + extra) * sizeof (mntopt_t), KM_SLEEP);
	dmo->mo_list = motbl;
	for (i = 0; i < count; i++) {
		vfs_copyopt(&smo->mo_list[i], &motbl[i]);
	}
	for (i = count; i < count + extra; i++) {
		motbl[i].mo_flags = MO_EMPTY;
	}
	dprintf("-vfs_copyopttbl_extend\n");
}



/*
 * Copy a mount options table.
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect smo and dmo.
 */
void
vfs_copyopttbl(const mntopts_t *smo, mntopts_t *dmo)
{
	vfs_copyopttbl_extend(smo, dmo, 0);
}


static void
vfs_freecancelopt(char **moc)
{
	dprintf("+vfs_freecancelopt\n");
	if (moc != NULL) {
		int ccnt = 0;
		char **cp;

		for (cp = moc; *cp != NULL; cp++) {
			kmem_free(*cp, strlen(*cp) + 1);
			ccnt++;
		}
		kmem_free(moc, (ccnt + 1) * sizeof (char *));
	}
	dprintf("-vfs_freecancelopt\n");
}

static void
vfs_freeopt(mntopt_t *mop)
{
	dprintf("+vfs_freeopt\n");
	if (mop->mo_name != NULL)
		kmem_free(mop->mo_name, strlen(mop->mo_name) + 1);

	vfs_freecancelopt(mop->mo_cancel);

	if (mop->mo_arg != NULL)
		kmem_free(mop->mo_arg, strlen(mop->mo_arg) + 1);
	dprintf("-vfs_freeopt\n");
}

/*
 * Free a mount options table
 *
 * This function is *not* for general use by filesystems.
 *
 * Note: caller is responsible for locking the vfs list, if needed,
 *       to protect mp.
 */
void
vfs_freeopttbl(mntopts_t *mp)
{
	dprintf("+vfs_freeopttbl\n");
	uint_t i, count;

	count = mp->mo_count;
	for (i = 0; i < count; i++) {
		vfs_freeopt(&mp->mo_list[i]);
	}
	if (count) {
		kmem_free(mp->mo_list, sizeof (mntopt_t) * count);
		mp->mo_count = 0;
		mp->mo_list = NULL;
	}
	dprintf("-vfs_freeopttbl\n");
}

/*
 * Find a vfssw entry given a file system type name.
 * Try to autoload the filesystem if it's not found.
 * If it's installed, return the vfssw locked to prevent unloading.
 */
struct vfssw *
vfs_getvfssw(const char *type)
{
	struct vfssw *vswp;
	const char *modname;

	//RLOCK_VFSSW();
	vswp = vfs_getvfsswbyname(type);
#if 0
	modname = vfs_to_modname(type);

	if (rootdir == NULL) {
		/*
		 * If we haven't yet loaded the root file system, then our
		 * _init won't be called until later. Allocate vfssw entry,
		 * because mod_installfs won't be called.
		 */
		if (vswp == NULL) {
			RUNLOCK_VFSSW();
			WLOCK_VFSSW();
			if ((vswp = vfs_getvfsswbyname(type)) == NULL) {
				if ((vswp = allocate_vfssw(type)) == NULL) {
					WUNLOCK_VFSSW();
					return (NULL);
				}
			}
			WUNLOCK_VFSSW();
			RLOCK_VFSSW();
		}
		if (!VFS_INSTALLED(vswp)) {
			RUNLOCK_VFSSW();
			(void) modloadonly("fs", modname);
		} else
			RUNLOCK_VFSSW();
		return (vswp);
	}

	/*
	 * Try to load the filesystem.  Before calling modload(), we drop
	 * our lock on the VFS switch table, and pick it up after the
	 * module is loaded.  However, there is a potential race:  the
	 * module could be unloaded after the call to modload() completes
	 * but before we pick up the lock and drive on.  Therefore,
	 * we keep reloading the module until we've loaded the module
	 * _and_ we have the lock on the VFS switch table.
	 */
	while (vswp == NULL || !VFS_INSTALLED(vswp)) {
		RUNLOCK_VFSSW();
		if (modload("fs", modname) == -1)
			return (NULL);
		RLOCK_VFSSW();
		if (vswp == NULL)
			if ((vswp = vfs_getvfsswbyname(type)) == NULL)
				break;
	}
	RUNLOCK_VFSSW();
#endif
	return (vswp);
}

/*
 * Find a vfssw entry given a file system type name.
 */
struct vfssw *
vfs_getvfsswbyname(const char *type)
{
	struct vfssw *vswp;

//	ASSERT(VFSSW_LOCKED());
	if (type == NULL || *type == '\0')
		return (NULL);

	for (vswp = &vfssw[1]; vswp < &vfssw[nfstype]; vswp++) {
		if (strcmp(type, vswp->vsw_name) == 0) {
			vfs_refvfssw(vswp);
			return (vswp);
		}
	}

	return (NULL);
}

/*
 * Reference a vfssw entry.
 */
void
vfs_refvfssw(struct vfssw *vswp)
{
	dprintf("vfs_refvfssw\n");
	//mutex_enter(&vswp->vsw_lock);
	//vswp->vsw_count++;
	//mutex_exit(&vswp->vsw_lock);
}

