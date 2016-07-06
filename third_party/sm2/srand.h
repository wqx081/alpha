#ifndef __RAND_GEN_H__
#define __RAND_GEN_H__
#include "const.h"
#include "bigint.h"

namespace oly {

U8 random_string(
    U8 * rand, 
    int len
);

void random_limit (
    mpz_ptr x, 
    mpz_ptr p
);

}

#endif

