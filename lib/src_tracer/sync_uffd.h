/*
   src_tracer/sync_uffdio.h
   synchronization between trace producer and consuming process using userfault fd linux API
*/

#ifndef SRC_TRACER_SYNC_UFFD_H
#define SRC_TRACER_SYNC_UFFD_H

#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

// somehow missing in the headers on my system
#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif
#ifndef UFFDIO_WRITEPROTECT
struct uffdio_writeprotect {
    struct uffdio_range range; /* Range to change write permission*/
    __u64 mode;                /* Mode to change write permission */
};
#define _UFFDIO_WRITEPROTECT  (0x06)
#define UFFDIO_WRITEPROTECT   _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, \
                                    struct uffdio_writeprotect)
#define UFFDIO_WRITEPROTECT_MODE_WP		((__u64)1<<0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE	((__u64)1<<1)
#endif

extern int _trace_uffd;

#endif // SRC_TRACER_SYNC_UFFD_H
