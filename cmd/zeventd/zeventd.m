

#import <sys/sysctl.h>
#import <Foundation/Foundation.h>
#import <Foundation/NSUserNotification.h>
#import <objc/runtime.h>

//#import "AppDelegate.h"

#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "events.h"

#define SPL_CONTROL_NAME "net.lundman.spl.notification"

static int time_to_die = 0;

void exit_interrupt(int roger)
{
    time_to_die = 1;
}


NSString *fakeBundleIdentifier = nil;
//NSString *fakeBundleIdentifier = @"net.lundman.spl";

@implementation NSBundle(swizle)
// Overriding bundleIdentifier works, but overriding NSUserNotificationAlertStyle does not work.
- (NSString *)__bundleIdentifier
{
  if (self == [NSBundle mainBundle]) {
    return fakeBundleIdentifier ? fakeBundleIdentifier : @"com.apple.finder";
  } else {
    return [self __bundleIdentifier];
  }
}
@end

BOOL installNSBundleHook()
{
    Class class = objc_getClass("NSBundle");
    if (class) {
        method_exchangeImplementations(class_getInstanceMethod(class, @selector(bundleIdentifier)),
                                       class_getInstanceMethod(class, @selector(__bundleIdentifier)));
        return YES;
    }
        return NO;
}

void sendNotification(NSString *title, NSString *msg)
{
  NSUserNotification *notification = [[NSUserNotification alloc] init];
  notification.title = title;
  notification.informativeText = msg;
  notification.soundName = NSUserNotificationDefaultSoundName;

  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
}


int main(int argc, const char * argv[])
{

    @autoreleasepool {

      int fd;
      struct kev_vendor_code vc;
      int dsize, nret, bytes;
      static fd_set io_fdset_read;
      static struct timeval timeout;
      struct kern_event_msg msg;
      struct kev_request req;

      installNSBundleHook();

      signal(SIGINT, exit_interrupt);

      fd = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
      if (fd < 0) {
        printf("Failed to open socket for events\n");
        return fd;
      }

      // Attempt to look up vendor (if kext is loaded)

      strcpy(vc.vendor_string, SPL_CONTROL_NAME);

      if (ioctl(fd, SIOCGKEVVENDOR, &vc)) {

        printf("Waiting for spl.kext to be loaded...\n");

        while(!time_to_die) {
          sleep(5);
          if (!ioctl(fd, SIOCGKEVVENDOR, &vc)) {
            break;
          }
        }
      }

      if (time_to_die) return -1;

      printf("SPL: Vendor code %d\n", vc.vendor_code);

      req.vendor_code=vc.vendor_code;
      req.kev_class=KEV_ANY_CLASS;
      req.kev_subclass=KEV_ANY_SUBCLASS;

      if (ioctl(fd, SIOCSKEVFILT, &req)) {
        perror("SIOCSKEVFILT");
      }


      printf("Listening for events...\n");

      while (!time_to_die) {

        dsize = getdtablesize();
        FD_ZERO( &io_fdset_read  );
        FD_SET(fd, &io_fdset_read);
        timeout.tv_usec = 0;
        timeout.tv_sec  = 5;

        nret = select( dsize, &io_fdset_read, NULL, NULL, &timeout);
        switch ( nret ) {
        case -1:    // error
          if (( errno == EAGAIN ) || ( errno == EINTR )) {
            break;
          }
          time_to_die = 1;
          break;
        case 0:     // timeout - perform various timeout checks.
          break;
        default:    // there was something happening on our sockets.
          if (FD_ISSET( fd, &io_fdset_read )) {
            bytes = recv(fd, &msg, sizeof(msg), MSG_WAITALL);
            if (bytes < 0) {
              time_to_die = 1;
              printf("Received error %d from recv() call.\n", bytes);
              break;
            }
            printf("Received %d bytes from kernel: %d:%d:%d:%d\n",
                   bytes, msg.vendor_code, msg.kev_class,
                   msg.kev_subclass, msg.event_code);

            if (msg.kev_class == SPL_CLASS_NOTIFY) {
              if (msg.kev_subclass == SPL_SUBCLASS_INFO) {
                switch(msg.event_code) {
                case SPL_EVENT_ZFS_LOAD:
                  sendNotification(@"ZFS kext", @"ZFS Module Loaded");
                  printf("ZFS kext loaded.\n");
                  break;
                case SPL_EVENT_ZFS_UNLOAD:
                  sendNotification(@"ZFS kext", @"ZFS Module Unloaded");
                  printf("ZFS kext unloaded.\n");
                  break;
                } // switch
              } // subclass
            } // class

          } // FD_ISSET
          break;
        }
      } // time to die

      close(fd);
      printf("\n\nQuitting...\n");

    }
}


