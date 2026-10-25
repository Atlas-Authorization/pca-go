//go:build less && cgo

/* The patched LESS reference C (lessc/, a copy of sdks/pca-less-c) compiled into package pca for the `less` build; see less_cgo.go. */
#include "lessc/lib/codes.c"
#include "lessc/lib/fips202.c"
/* fips202.c and keccakf1600.c each define ROL and NROUNDS for their own code; separate them as separate units would be. */
#undef ROL
#undef NROUNDS
#include "lessc/lib/keccakf1600.c"
#include "lessc/lib/LESS.c"
#include "lessc/lib/monomial.c"
#include "lessc/lib/rng.c"
#include "lessc/lib/seedtree.c"
#include "lessc/lib/sign.c"
#include "lessc/lib/utils.c"
#include "lessc/lib/sort.c"
#include "lessc/lib/canonical.c"
#include "lessc/lib/transpose.c"
#include "lessc/atlas_less.c"
