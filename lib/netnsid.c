#include <config.h>
#include "netnsid.h"

/* The nsid that the local kernel assigns to our own network namespace when a
 * self-referential mapping exists, or NETNSID_LOCAL when none does.
 *
 * It is set once at startup by the platform-specific netdev code (see
 * netdev-linux.c) before any namespace-tagged netlink event can be received,
 * and is read afterwards by netnsid_is_local().  A self-referential nsid
 * mapping is permanent once created, so this value never changes again. */
int netnsid_self = NETNSID_LOCAL;

void
netnsid_set_self(int nsid)
{
    netnsid_self = nsid;
}
