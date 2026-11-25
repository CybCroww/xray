#ifndef CVPN_PATH_POLICY_H
#define CVPN_PATH_POLICY_H
#include <stdbool.h>

typedef enum { CVPNPathKeep, CVPNPathPause, CVPNPathReset } CVPNPathAction;

static inline CVPNPathAction CVPNDecidePath(bool hasPrevious, bool wasOffline,
    bool isOffline, bool activating, bool samePhysical) {
    if (isOffline) return hasPrevious && wasOffline ? CVPNPathKeep : CVPNPathPause;
    if (!hasPrevious) return CVPNPathKeep;
    return wasOffline || (!samePhysical && !activating) ? CVPNPathReset : CVPNPathKeep;
}
#endif
