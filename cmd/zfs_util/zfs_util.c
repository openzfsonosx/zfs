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
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#include <uuid/uuid.h>


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


#ifndef FSUC_GETUUID
#define FSUC_GETUUID 'k'
#endif

#ifndef FSUC_QUICKVERIFY
#define FSUC_QUICKVERIFY 'q'
#endif



static int
zfs_probe(const char *devpath, char **volname)
{
	int result = FSUR_UNRECOGNIZED;
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
				CFStringRef serialNumberAsCFString;
				//CFStringEncoding encoding = kCFStringEncodingUTF8;
				CFStringEncoding encoding = kCFStringEncodingMacRoman;


				// Do we want to mount it yet?
#if 1

				serialNumberAsCFString = (CFStringRef*) IORegistryEntryCreateCFProperty(service, CFSTR("DOMOUNTME"), kCFAllocatorDefault, 0);
				if (serialNumberAsCFString &&
					CFEqual(serialNumberAsCFString, CFSTR("FALSE") )) {
					result = FSUR_UNRECOGNIZED;
					IOObjectRelease(service);
					syslog(LOG_NOTICE, "-zfs_probe : lying about it result %d", result);
					return (result);
				}
#endif


				serialNumberAsCFString = (CFStringRef*) IORegistryEntryCreateCFProperty(service, CFSTR("DATASET"), kCFAllocatorDefault, 0);

				if (serialNumberAsCFString) {
					*volname = CFStringGetCStringPtr(serialNumberAsCFString, encoding);
					result = FSUR_RECOGNIZED;
				}

				syslog(LOG_NOTICE, "writing volname %s\n", *volname);

			}
            IOObjectRelease(service);
        }
	}

	syslog(LOG_NOTICE, "-zfs_probe : result %d", result);
	return (result);
}

int
main(int argc, char **argv, char **env)
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
	char *volname = NULL;

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
			ret = zfs_probe(blkdevice, &volname);

			if (ret == FSUR_RECOGNIZED)
				write(1, volname, strlen(volname));
			break;

		case FSUC_GETUUID:
			ret = zfs_probe(blkdevice, &volname);
			if (ret == FSUR_RECOGNIZED) {
				MD5_CTX  md5c;
				unsigned char digest[MD5_DIGEST_LENGTH];
				char uuidLine[40];
				MD5_Init( &md5c );
				MD5_Update( &md5c, volname, strlen(volname));
				MD5_Final( digest, &md5c );
				// 12962490-0DBE-3BCD-B22E-31B6CD7054E4
				uuid_unparse(digest, uuidLine);
				write(1, uuidLine, strlen(uuidLine));
				syslog(LOG_NOTICE, "UUID is %s", uuidLine);
				ret = FSUR_IO_SUCCESS;
			}
			break;

		case FSUC_QUICKVERIFY:
			syslog(LOG_NOTICE, "%s: returning OK on VERIFY", progname);
			ret = 0;
			break;

		default:
			usage();
	}

	closelog();
	exit(ret);
}
