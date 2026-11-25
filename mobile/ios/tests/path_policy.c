#include "../CVPNPathPolicy.h"
#include <assert.h>

int main(void) {
    // Starting a monitor and changing only DNS/cost must preserve live sockets.
    assert(CVPNDecidePath(false, false, false, false, false) == CVPNPathKeep);
    assert(CVPNDecidePath(true, false, false, false, true) == CVPNPathKeep);
    // The first dial can activate a previously satisfiable path.
    assert(CVPNDecidePath(true, false, false, true, false) == CVPNPathKeep);
    // Wi-Fi/cellular and address-family changes invalidate old sockets.
    assert(CVPNDecidePath(true, false, false, false, false) == CVPNPathReset);
    // Offline notifications pause once; restoration resumes even on the same route.
    assert(CVPNDecidePath(false, false, true, false, false) == CVPNPathPause);
    assert(CVPNDecidePath(true, false, true, false, true) == CVPNPathPause);
    assert(CVPNDecidePath(true, true, true, false, false) == CVPNPathKeep);
    assert(CVPNDecidePath(true, true, false, false, true) == CVPNPathReset);
    return 0;
}
