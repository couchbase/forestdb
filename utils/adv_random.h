#ifndef _JSAHN_ADV_RANDOM_H
#define _JSAHN_ADV_RANDOM_H

#include <stdint.h>
#include <math.h>

#ifndef UINT64_MAX
#define UINT64_MAX ((uint64_t)0xffffffffffffffff);
#endif

#define BDR_RNG_VARS  \
        uint64_t rngx=rand(), rngy=362436069, rngz=521288629; \
        uint64_t rngt, rngz2;

#define BDR_RNG_VARS_SET(x)  \
        uint64_t rngx=(x), rngy=362436069, rngz=521288629; \
        uint64_t rngt, rngz2;

//rngz contains the new value
#define BDR_RNG_NEXT \
        rngx ^= rngx << 16; \
        rngx ^= rngx >> 5; \
        rngx ^= rngx << 1; \
        rngt = rngx; \
        rngx = rngy; \
        rngy = rngz; \
        rngz = rngt ^ rngx ^ rngy;

//rngz, rngz2 contains the new values
#define BDR_RNG_NEXTPAIR \
        rngx ^= rngx << 16; \
        rngx ^= rngx >> 5; \
        rngx ^= rngx << 1; \
        rngt = rngx; \
        rngx = rngy; \
        rngy = rngz; \
        rngz = rngt ^ rngx ^ rngy; \
        rngz2 = rngz; \
        rngx ^= rngx << 16; \
        rngx ^= rngx >> 5; \
        rngx ^= rngx << 1; \
        rngt = rngx; \
        rngx = rngy; \
        rngy = rngz; \
        rngz = rngt ^ rngx ^ rngy;

#define BDR_RNG_GET_INT(number) (rngz % (number))
#define BDR_RNG_GET_INT_PAIR(a, b, number) \
    (a) = (rngz % (number)); \
    (b) = (rngz2 % (number));

typedef enum {
    RND_UNIFORM,
    RND_NORMAL
} rndtype_t;

struct rndinfo{
    rndtype_t type;
    // for uniform: lower bound of range (including itself)
    // for normal: average (or median)
    int64_t a;
    // for uniform: upper bound of range (including itself but extremely rare (probability == 1/(2^64))
    // for normal: standard deviation (=sigma)
    int64_t b;
};

static double __PI = 3.141592654;

int64_t get_random(struct rndinfo* ri, uint64_t rv1, uint64_t rv2)
{
    if (ri->type == RND_UNIFORM)
    {
        double anorm = ((double) rv1) / UINT64_MAX;
        return (anorm * (ri->b - ri->a) + ri->a);
    }
    else if (ri->type == RND_NORMAL){
        double r1, r2;
        r1 = -log(1-(((double)  rv1) / UINT64_MAX ));
        r2 =  2 * __PI * (((double) rv2) / UINT64_MAX );
        r1 =  sqrt(2*r1);
        return ri->b * r1 * cos(r2) + ri->a;
    }
    return 0;
}

#ifdef __RAND_GEN_TEST

void _rand_gen_test()
{
    int n = 32, m = 1<<20;
    int arr[n];
    int i;
    double cdf;
    int64_t r;
    struct rndinfo ri;
    BDR_RNG_VARS;

    memset(arr, 0, sizeof(int)*n);
    cdf = 0;
    ri.type = RND_UNIFORM;
    ri.a = 0;
    ri.b = 32;

    for (i=0;i<m;++i){
        BDR_RNG_NEXTPAIR;
        r = get_random(&ri, rngz, rngz2);
        arr[r]++;
    }

    for (i=0;i<n;++i){
        cdf += (double)arr[i]/m*100;
        printf("arr[%d] = %7d (%.2f %% / %.2f %%)\n", i, arr[i], (double)arr[i]/m*100, cdf);
    }

    memset(arr, 0, sizeof(int)*n);
    cdf = 0;
    ri.type = RND_NORMAL;
    ri.a = 16;
    ri.b = 2;

    for (i=0;i<m;++i){
        BDR_RNG_NEXTPAIR;
        r = get_random(&ri, rngz, rngz2);
        if (r<0) r=0;
        if (r>=n) r=n-1;
        arr[r]++;
    }

    for (i=0;i<n;++i){
        cdf += (double)arr[i]/m*100;
        printf("arr[%d] = %7d (%.2f %% / %.2f %%)\n", i, arr[i], (double)arr[i]/m*100, cdf);
    }
}

#endif

#endif
