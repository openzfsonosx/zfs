#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <mach-o/dyld.h>

char*
getexecname(char *buf, size_t buflen)
{
	uint32_t execnamelen = buflen;

	if (_NSGetExecutablePath(buf, &execnamelen) == 0)
		return (buf);
	else
		return (NULL);
}

char *
getexecrealpath(char *buf, size_t buflen)
{
	char *execbuf;
	const char *execname;
	char *rp = NULL;

	execbuf = malloc(buflen);
	if (execbuf != NULL) {
		execname = getexecname(execbuf, buflen);
		if (execname != NULL)
			rp = realpath(execname, buf);
		free(execbuf);
	}

	return (rp);
}
