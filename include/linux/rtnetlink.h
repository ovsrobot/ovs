#ifndef __UAPI_LINUX_RTNETLINK_WRAPPER_H
#define __UAPI_LINUX_RTNETLINK_WRAPPER_H 1

#if !defined(__KERNEL__) && !defined(HAVE_RTPROT_OVN)

#define RTPROT_OVN 84

#endif /* !__KERNEL__ && !HAVE_RTPROT_OVN */

#include_next <linux/rtnetlink.h>

#endif /* __UAPI_LINUX_RTNETLINK_WRAPPER_H */
