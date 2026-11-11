// SPDX-License-Identifier: MIT
/* The host build's entry point: the same dispatch as rmc-radiusd's, without hostapd behind it. */
#include <stdio.h>

#include "rmc-guest.h"

int main(int argc, char *argv[])
{
    int ret = rmc_guest_main(argc, argv);

    if (ret == -1)
        fprintf(stderr, "usage: rmc-guest-host guestd|portal ...\n");
    return ret == -1 ? 2 : ret;
}
