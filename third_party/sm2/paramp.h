#ifndef __PARAM_H__
#define __PARAM_H__

#include "const.h"
#include "bigint.h"
#include "curvep.h"
#include "sm2.h"

namespace oly {

typedef struct
{
    mpz_t           fieldp;
    mpz_t           subgrpq;
    mpz_t           cofactor;
	mpz_t			coa;
	mpz_t			cob;
	point_affn_t	generator;
} ecc_param;

// TODO(wqx):
extern ecc_param *g_paramptr;

}

// TODO(wqx):
#define FIELD_P				g_paramptr->fieldp
#define SUBGRP_ORDER		g_paramptr->subgrpq
#define COA					g_paramptr->coa
#define COB					g_paramptr->cob
#define GENERATOR			g_paramptr->generator

#endif
