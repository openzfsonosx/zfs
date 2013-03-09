/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2006 Ricardo Correia.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <string.h>
#include <mntent.h>
#include <ctype.h> /* for isspace() */
#include <errno.h>
#include <unistd.h>
#include <sys/mnttab.h>

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/fcntl.h>

#define BUFSIZE (MNT_LINE_MAX + 2)

/*__thread*/ char buf[BUFSIZE];

#define DIFF(xx) ((mrefp->xx != NULL) && \
		  (mgetp->xx == NULL || strcmp(mrefp->xx, mgetp->xx) != 0))

int
getmntany(FILE *fp, struct mnttab *mgetp, struct mnttab *mrefp)
{
        struct statfs *sfsp;
        int nitems;

        nitems = getmntinfo(&sfsp, MNT_WAIT);

        while (nitems-- > 0) {
                if (strcmp(mrefp->mnt_fstype, sfsp->f_fstypename) == 0 &&
                    strcmp(mrefp->mnt_special, sfsp->f_mntfromname) == 0) {
                        mgetp->mnt_special = sfsp->f_mntfromname;
                        mgetp->mnt_mountp = sfsp->f_mntonname;
                        mgetp->mnt_fstype = sfsp->f_fstypename;
                        mgetp->mnt_mntopts = "";
                        return (0);
                }
                ++sfsp;
        }
        return (-1);
}

char *
mntopt(char **p)
{
        char *cp = *p;
        char *retstr;

        while (*cp && isspace(*cp))
                cp++;

        retstr = cp;
        while (*cp && *cp != ',')
                cp++;

        if (*cp) {
                *cp = '\0';
                cp++;
        }

        *p = cp;
        return (retstr);
}

char *
hasmntopt(struct mnttab *mnt, char *opt)
{
        char tmpopts[MNT_LINE_MAX];
        char *f, *opts = tmpopts;

        if (mnt->mnt_mntopts == NULL)
                return (NULL);
        (void) strcpy(opts, mnt->mnt_mntopts);
        f = mntopt(&opts);
        for (; *f; f = mntopt(&opts)) {
                if (strncmp(opt, f, strlen(opt)) == 0)
                        return (f - tmpopts + mnt->mnt_mntopts);
        }
        return (NULL);
}


int
getmntent(FILE *fp, struct mnttab *mgetp)
{
    static struct statfs *mntbufp = NULL;
    static unsigned int total   = 0;
    static unsigned int current = 0;

    if (!mntbufp) {

        total = getmntinfo(&mntbufp, MNT_WAIT);
        current = 0;

        if (total <= 0) return -1; // EOF

    }

    if (current < total) {

        mgetp->mnt_special = mntbufp[current].f_mntfromname;
        mgetp->mnt_mountp =  mntbufp[current].f_mntonname;
        mgetp->mnt_fstype =  mntbufp[current].f_fstypename;
        mgetp->mnt_mntopts = "";

        current++;
        return 0; // Valid record
    }

    // Finished all nodes, return EOF once, and get ready for next time
    mntbufp = NULL;

    return -1; // EOF
}


int
getextmntent(FILE *fp, struct extmnttab *mp, int len)
{
	int ret;
	struct stat64 st;

	ret = getmntent(fp, (struct mnttab *) mp);
	if (ret == 0) {
		if (stat64(mp->mnt_mountp, &st) != 0) {
			mp->mnt_major = 0;
			mp->mnt_minor = 0;
			return ret;
		}
		mp->mnt_major = major(st.st_dev);
		mp->mnt_minor = minor(st.st_dev);
	}

	return ret;
}

DIR *
fdopendir(int fd)
{
	char fullpath[MAXPATHLEN];

	if (fcntl(fd, F_GETPATH, fullpath) < 0) {
		perror("fcntl");
		return (NULL);
	}
	if (close(fd) < 0) {
		return (NULL);
	}

	return (opendir(fullpath));
}

static int
chdir_block_begin(int newroot_fd)
{
	int cwdfd, error;

	cwdfd = open(".", O_RDONLY | O_DIRECTORY);
	if (cwdfd == -1)
		return (-1);

	if (fchdir(newroot_fd) == -1) {
		error = errno;
		(void) close(cwdfd);
		errno = error;
		return (-1);
	}
	return (cwdfd);
}

static void
chdir_block_end(int cwdfd)
{
	int error = errno;
	(void) fchdir(cwdfd);
	(void) close(cwdfd);
	errno = error;
}

int
openat64(int dirfd, const char *path, int flags, ...)
{
	int cwdfd, filefd;

	if ((cwdfd = chdir_block_begin(dirfd)) == -1)
		return (-1);

	if ((flags & O_CREAT) != 0) {
		va_list ap;
		int mode;

		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);

		filefd = open(path, flags, mode);
	} else
		filefd = open(path, flags);

	chdir_block_end(cwdfd);
	return (filefd);
}

int
fstatat64(int dirfd, const char *path, struct stat64 *statbuf, int flag)
{
	int cwdfd, error;

	if ((cwdfd = chdir_block_begin(dirfd)) == -1)
		return (-1);

	if (flag == AT_SYMLINK_NOFOLLOW)
		error = lstat64(path, statbuf);
	else
		error = stat64(path, statbuf);

	chdir_block_end(cwdfd);
	return (error);
}
