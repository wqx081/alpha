#include "const.h"
#include "srand.h"
#include "bigint.h"
#include "paramp.h"


#include <stdlib.h>
#include <time.h>
#include <stdio.h>

namespace oly {

U8 random_string(
    unsigned char *rand, 
    int rlen
)
{
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        fread(rand, 1, rlen, fp);
        fclose(fp);
    }
    return 1;
}

void random_limit (
    mpz_ptr x, 
    mpz_ptr p
)
{
	U16 n=(mpz_sizeinbase(p,2)+7)/8;
	//U8 *ptr=((U8 *)(x->data))+4;
	unsigned long size = 0;

   // random_string(ptr+MAX_FIELD_BYTES-n,n);
	U8 *ptr=((U8 *)(x->data));
	 random_string(ptr, n);
     
	while (mpz_cmp(x, p) > 0) {
		size = mpz_sizeinbase(x, 2) - 1;
		mpz_clrbit(x, size);
    }    

}


}
