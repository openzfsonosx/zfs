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

#if 0 //Replacing with FreeBSD implementation
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
#endif

#if 0 //Replacing with FreeBSD implementation
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
#endif

#if 0 //Replacing with FreeBSD implementation
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
#endif


#if 0 //Replacing with FreeBSD implementation
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
#endif


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
fstatat64(int dirfd, const char *path, struct stat *statbuf, int flag)
{
	int cwdfd, error;

	if ((cwdfd = chdir_block_begin(dirfd)) == -1)
		return (-1);

	if (flag == AT_SYMLINK_NOFOLLOW)
		error = lstat(path, statbuf);
	else
		error = stat(path, statbuf);

	chdir_block_end(cwdfd);
	return (error);
}


static char *
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

static void
optadd(char *mntopts, size_t size, const char *opt)
{

	if (mntopts[0] != '\0')
		strlcat(mntopts, ",", size);
	strlcat(mntopts, opt, size);
}

void
statfs2mnttab(struct statfs *sfs, struct mnttab *mp)
{
	static char mntopts[MNTMAXSTR];
	long flags;

	mntopts[0] = '\0';

	flags = sfs->f_flags;
#define	OPTADD(opt)	optadd(mntopts, sizeof(mntopts), (opt))
	if (flags & MNT_RDONLY)
		OPTADD(MNTOPT_RO);
	else
		OPTADD(MNTOPT_RW);
	if (flags & MNT_NOSUID)
		OPTADD(MNTOPT_NOSUID);
	else
		OPTADD(MNTOPT_SETUID);
	if (flags & MNT_UPDATE)
		OPTADD(MNTOPT_REMOUNT);
	if (flags & MNT_NOATIME)
		OPTADD(MNTOPT_NOATIME);
	else
		OPTADD(MNTOPT_ATIME);
#ifdef __FreeBSD__
	OPTADD(MNTOPT_NOXATTR);
#endif
#ifdef __APPLE__
	if (flags & MNT_NOUSERXATTR)
		OPTADD(MNTOPT_NOXATTR);
	else
		OPTADD(MNTOPT_XATTR);
#endif
	if (flags & MNT_NOEXEC)
		OPTADD(MNTOPT_NOEXEC);
	else
		OPTADD(MNTOPT_EXEC);
	if (flags & MNT_DONTBROWSE)
		OPTADD(MNTOPT_NOBROWSE);
	else
		OPTADD(MNTOPT_BROWSE);
	if (flags & MNT_IGNORE_OWNERSHIP)
		OPTADD(MNTOPT_NOOWNERS);
	else
		OPTADD(MNTOPT_OWNERS);
#undef	OPTADD
	mp->mnt_special = sfs->f_mntfromname;
	mp->mnt_mountp = sfs->f_mntonname;
	mp->mnt_fstype = sfs->f_fstypename;
	mp->mnt_mntopts = mntopts;
	mp->mnt_fssubtype = sfs->f_fssubtype;
	//if (strcmp(mp->mnt_fstype, MNTTYPE_ZFS) == 0)
		//printf("mnttab: %s %s %s %s\n", mp->mnt_special, mp->mnt_mountp, mp->mnt_fstype, mp->mnt_mntopts);
}

static struct statfs *gsfs = NULL;
static int allfs = 0;

static int
statfs_init(void)
{
	struct statfs *sfs;
	int error;

	if (gsfs != NULL) {
		free(gsfs);
		gsfs = NULL;
	}
	allfs = getfsstat(NULL, 0, MNT_WAIT);
	if (allfs == -1)
		goto fail;
	gsfs = malloc(sizeof(gsfs[0]) * allfs * 2);
	if (gsfs == NULL)
		goto fail;
	allfs = getfsstat(gsfs, (long)(sizeof(gsfs[0]) * allfs * 2),
                      MNT_WAIT);
	if (allfs == -1)
		goto fail;
	sfs = realloc(gsfs, allfs * sizeof(gsfs[0]));
	if (sfs != NULL)
		gsfs = sfs;
	return (0);
fail:
	error = errno;
	if (gsfs != NULL)
		free(gsfs);
	gsfs = NULL;
	allfs = 0;
	return (error);
}

int
getmntany(FILE *fd __unused, struct mnttab *mgetp, struct mnttab *mrefp)
{
	//struct statfs *sfs; //Not sure what FreeBSD was planning to do with this.
	int i, error;

	error = statfs_init();
	if (error != 0)
		return (error);

	for (i = 0; i < allfs; i++) {
		if (mrefp->mnt_special != NULL &&
		    strcmp(mrefp->mnt_special, gsfs[i].f_mntfromname) != 0) {
			continue;
		}
		if (mrefp->mnt_mountp != NULL &&
		    strcmp(mrefp->mnt_mountp, gsfs[i].f_mntonname) != 0) {
			continue;
		}
		if (mrefp->mnt_fstype != NULL &&
		    strcmp(mrefp->mnt_fstype, gsfs[i].f_fstypename) != 0) {
			continue;
		}
		statfs2mnttab(&gsfs[i], mgetp);
		return (0);
	}
	return (-1);
}

int
getmntent(FILE *fp, struct mnttab *mp)
{
	//struct statfs *sfs; //Not sure what FreeBSD was planning to do with this.
	int error, nfs;

	nfs = (int)lseek(fileno(fp), 0, SEEK_CUR);
	if (nfs == -1)
		return (errno);
	/* If nfs is 0, we want to refresh out cache. */
	if (nfs == 0 || gsfs == NULL) {
		error = statfs_init();
		if (error != 0)
			return (error);
	}
	if (nfs >= allfs)
		return (-1);
	statfs2mnttab(&gsfs[nfs], mp);
	if (lseek(fileno(fp), 1, SEEK_CUR) == -1)
		return (errno);
	return (0);
}
