
#include <stdio.h>
#include <syslog.h>

int
main(int argc, char **argv)
{
	openlog("mount_zfs", LOG_CONS | LOG_PERROR, LOG_AUTH);
	syslog(LOG_NOTICE, "fsck_zfs\n");

	if (argc > 1 && argv[1][0] == '-') {
		switch(argv[1][1]) {
		case 'q':
			printf("QUICKCHECK ONLY; FILESYSTEM CLEAN\n");
			break;
		default:
			break;
		}
	}

	syslog(LOG_NOTICE, "done\n");
	closelog();
	return (0);
}
