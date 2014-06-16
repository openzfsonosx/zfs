/*
* Copyright (c) 2007 Apple Inc. All rights reserved.
* Use is subject to license terms stated below.
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License v. 1.0 (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://www.opensolaris.org/os/licensing <http://www.opensolaris.org/os/licensing> .
* See the License for the specific language governing permissions
* and limitations under the License.
*
* THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*THE POSSIBILITY OF SUCH DAMAGE.
*/

/*	@(#)zfsutil.c   (c) 2007 Apple Inc.	*/

#include <syslog.h>
#include <libzfs.h>
#include <paths.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/vmmeter.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/disk.h>
#include <sys/loadable_fs.h>
#include <sys/attr.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

const char *progname;

static void
usage(void)
{
	fprintf(stderr, "usage: %s -p device\n", progname);
	closelog();
        exit(FSUR_INVAL);
}
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#include <DiskArbitration/DiskArbitration.h>




static int
zfs_probe(const char *devpath)
{
	int result = FSUR_UNRECOGNIZED;
	char *volname = "somename";
	CFMutableDictionaryRef  matchingDict;
    io_service_t            service;

	if (!strncmp("/dev/", devpath, 5))
		devpath = &devpath[5];

	syslog(LOG_NOTICE, "+zfs_probe : devpath %s", devpath);

	matchingDict = IOBSDNameMatching(kIOMasterPortDefault, 0, devpath);
    if (NULL == matchingDict) {
			syslog(LOG_NOTICE, "IOBSDNameMatching returned a NULL dictionary.\n");
    } else {
        // Fetch the object with the matching BSD node name.
        // Note that there should only be one match, so IOServiceGetMatchingService is used instead of
        // IOServiceGetMatchingServices to simplify the code.
        service = IOServiceGetMatchingService(kIOMasterPortDefault, matchingDict);

        if (IO_OBJECT_NULL == service) {
			syslog(LOG_NOTICE, "IOServiceGetMatchingService returned IO_OBJECT_NULL.\n");
        } else {
			syslog(LOG_NOTICE, "writing\n");
			if (IOObjectConformsTo(service, kIOMediaClass)) {


#if 0  // Figure out what to do with "service" here.

				//IOService *media = OSDynamicCast(IOMedia, service);
				//OSbject *o = media->getProperty("DATASET");
				volname = service->getProperty("DATASET")->getCStringNoCopy();
				if (o) {
					//OSString *os = OSDynamicCast(OSString, o);
					//if (os) {
						volname = os->getCStringNoCopy();
						syslog(LOG_NOTICE, "writing volname %s\n", volname);
						//}
				}
#endif
			}
            IOObjectRelease(service);
        }
	}

	write(1, volname, strlen(volname));
	result = FSUR_RECOGNIZED;

	syslog(LOG_NOTICE, "-zfs_probe : result %d", result);
	return (result);
}

int
main(int argc, char **argv)
{
	setlogmask(LOG_UPTO(LOG_NOTICE));

        int argindex;
        for (argindex = 0; argindex < argc; argindex++) {
                syslog(LOG_NOTICE, "argv[%d]: %s\n", argindex, argv[argindex]);
        }

	char  blkdevice[MAXPATHLEN];
	char  what;
	char  *cp;
	char  *devname;
	struct stat  sb;
	int  ret = FSUR_INVAL;

	/* save & strip off program name */
	progname = argv[0];
	argc--;
	argv++;

	if (argc < 2 || argv[0][0] != '-')
		usage();

	what = argv[0][1];
	syslog(LOG_NOTICE, "zfs.util called with option %c", what);

	devname = argv[1];
	cp = strrchr(devname, '/');
	if (cp != 0)
		devname = cp + 1;
	if (*devname == 'r')
		devname++;
	(void) sprintf(blkdevice, "%s%s", _PATH_DEV, devname);
	syslog(LOG_NOTICE, "blkdevice is %s", blkdevice);

	if (stat(blkdevice, &sb) != 0) {
		syslog(LOG_NOTICE, "%s: stat %s failed, %s", progname, blkdevice, strerror(errno));
		closelog();
		exit(FSUR_INVAL);
	}

	switch (what) {
	case FSUC_PROBE:
		ret = zfs_probe(blkdevice);
		if (ret == -1)
			syslog(LOG_NOTICE, "FSUC_PROBE %s : FSUR_RECOGNIZED", blkdevice);
		else if (ret == -2)
			syslog(LOG_NOTICE, "FSUC_PROBE %s : FSUR_UNRECOGNIZED", blkdevice);
		else
			syslog(LOG_NOTICE, "FSUC_PROBE returned invalid probe status : %d", ret);
		break;
	default:
		usage();
	}

	closelog();
	exit(ret);
}
