#include <unistd.h>
#include <fcntl.h>

int
fdatasync(int fd)
{
	if (fcntl(fd, F_FULLFSYNC) == -1)
		return -1;
	return 0;
}
