#define PERL_NO_GET_CONTEXT 1
#define PERL_CORE 1   /* required for HINTS_REFCNT_LOCK et al */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define PERL_VERSION_DECIMAL(r,v,s) (r*1000000 + v*1000 + s)
#define PERL_DECIMAL_VERSION \
	PERL_VERSION_DECIMAL(PERL_REVISION,PERL_VERSION,PERL_SUBVERSION)
#define PERL_VERSION_GE(r,v,s) \
	(PERL_DECIMAL_VERSION >= PERL_VERSION_DECIMAL(r,v,s))

#define QHAVE_UNITCHECK PERL_VERSION_GE(5,9,5)

#define QHAVE_WARNINGS_AS_SV (!PERL_VERSION_GE(5,9,4))
#if QHAVE_WARNINGS_AS_SV
# define WARNINGS_t SV
#else /* !QHAVE_WARNINGS_AS_SV */
# define WARNINGS_t STRLEN
#endif /* !QHAVE_WARNINGS_AS_SV */

#define QHAVE_COP_LABEL (!PERL_VERSION_GE(5,11,0))
#define QHAVE_COP_HINTS PERL_VERSION_GE(5,9,4)
#define QHAVE_COP_HINTS_HASH PERL_VERSION_GE(5,9,4)
#define QHAVE_COP_ARYBASE (!PERL_VERSION_GE(5,9,4))
#define QHAVE_COP_IO (!PERL_VERSION_GE(5,9,4) && PERL_VERSION_GE(5,8,0))

#ifndef COP_SEQ_RANGE_LOW
# if PERL_VERSION_GE(5,9,5)
#  define COP_SEQ_RANGE_LOW(sv) ((XPVNV*)SvANY(sv))->xnv_u.xpad_cop_seq.xlow
#  define COP_SEQ_RANGE_HIGH(sv) ((XPVNV*)SvANY(sv))->xnv_u.xpad_cop_seq.xhigh
# else /* <5.9.5 */
#  define COP_SEQ_RANGE_LOW(sv) ((U32)SvNVX(sv))
#  define COP_SEQ_RANGE_HIGH(sv) ((U32)SvIVX(sv))
# endif /* <5.9.5 */
#endif /* !COP_SEQ_RANGE_LOW */

#if PERL_VERSION_GE(5,8,9) && !PERL_VERSION_GE(5,9,0)
/* there is a bogus definition, not actually used */
# undef PARENT_PAD_INDEX
#endif

#ifndef PARENT_PAD_INDEX
# if PERL_VERSION_GE(5,9,5)
#  define PARENT_PAD_INDEX(sv) ((XPVNV*)SvANY(sv))->xnv_u.xpad_cop_seq.xlow
#  define PARENT_FAKELEX_FLAGS(sv) \
	((XPVNV*)SvANY(sv))->xnv_u.xpad_cop_seq.xhigh
# elif PERL_VERSION_GE(5,9,0)
#  define PARENT_PAD_INDEX(sv) ((U32)SvNVX(sv))
#  define PARENT_FAKELEX_FLAGS(sv) ((U32)SvIVX(sv))
# endif /* >=5.9.0 */
#endif /* !PARENT_PAD_INDEX */

#if PERL_VERSION_GE(5,11,2)
# define pad_findmy_sv(sv) pad_findmy(SvPVX(sv), SvCUR(sv), 0)
#else /* <5.11.2 */
# define pad_findmy_sv(sv) pad_findmy(SvPVX(sv))
#endif /* <5.11.2 */

#ifndef newSV_type
# define newSV_type(type) THX_newSV_type(aTHX_ type)
static SV *THX_newSV_type(pTHX_ svtype type)
{
	SV *sv = newSV(0);
	SvUPGRADE(sv, type);
	return sv;
}
#endif /* !newSV_type */

#ifndef gv_fetchpvs
# ifdef gv_fetchpvn_flags
#  define gv_fetchpvs(name, flags, type) \
		gv_fetchpvn_flags(""name"", sizeof(name)-1, flags, type)
# else /* !gv_fetchpvn_flags */
#  define gv_fetchpvs(name, flags, type) gv_fetchpv(""name"", flags, type)
# endif /* !gv_fetchpvn_flags */
#endif /* !gv_fetchpvs */

#ifndef sv_setpvs
# define sv_setpvs(sv, string) sv_setpvn(sv, ""string"", sizeof(string)-1)
#endif /* !sv_setpvs */

#ifndef newSVpvs
# define newSVpvs(string) newSVpvn(""string"", sizeof(string)-1)
#endif /* !newSVpvs */

#ifndef SvPVX_const
# define SvPVX_const(sv) SvPVX(sv)
#endif /* !SvPVX_const */

#ifndef SvPADSTALE
# define SvPADSTALE(sv) 0
#endif /* !SvPADSTALE */

#ifndef SvPAD_STATE
# define SvPAD_STATE(sv) 0
#endif /* !SvPAD_STATE */

#ifndef HvNAME_get
# define HvNAME_get(hv) HvNAME(hv)
#endif /* !HvNAME_get */

#ifndef HvRITER_get
# define HvRITER_get(hv) HvRITER(hv)
#endif /* !HvRITER_get */

#ifndef HvEITER_get
# define HvEITER_get(hv) HvEITER(hv)
#endif /* !HvEITER_get */

#ifndef HvRITER_set
# define HvRITER_set(hv, val) (HvRITER(hv) = val)
#endif /* !HvRITER_set */

#ifndef HvEITER_set
# define HvEITER_set(hv, val) (HvEITER(hv) = val)
#endif /* !HvEITER_set */

#ifndef CvGV_set
# define CvGV_set(cv, val) (CvGV(cv) = val)
#endif /*!CvGV_set */

#if PERL_VERSION_GE(5,9,5)
# define PL_error_count (PL_parser->error_count)
# define lex_start_simple(line) lex_start(line, NULL, 1)
#else /* <5.9.5 */
# define lex_start_simple(line) do { \
		lex_start(line); \
		SAVEI32(PL_error_count); \
		PL_error_count = 0; \
	} while(0)
#endif /* <5.9.5 */

#define sv_is_glob(sv) (SvTYPE(sv) == SVt_PVGV)

#if PERL_VERSION_GE(5,11,0)
# define sv_is_regexp(sv) (SvTYPE(sv) == SVt_REGEXP)
#else /* <5.11.0 */
# define sv_is_regexp(sv) 0
#endif /* <5.11.0 */

#define sv_is_undef(sv) (!sv_is_glob(sv) && !sv_is_regexp(sv) && !SvOK(sv))

#define sv_is_string(sv) \
	(!sv_is_glob(sv) && !sv_is_regexp(sv) && \
	 (SvFLAGS(sv) & (SVf_IOK|SVf_NOK|SVf_POK|SVp_IOK|SVp_NOK|SVp_POK)))

enum {
	/* this enumeration must match gen_current_environment_op() */
	ENV_PACKAGE,
	ENV_WARNINGS,
#if QHAVE_COP_ARYBASE
	ENV_ARYBASE,
#endif /* QHAVE_COP_ARYBASE */
#if QHAVE_COP_IO
	ENV_IOHINT,
#endif /* QHAVE_COP_IO */
	ENV_HINTBITS,
#if QHAVE_COP_HINTS_HASH
	ENV_COPHINTHASH,
#endif /* QHAVE_COP_HINTS_HASH */
	ENV_HINTHASH,
	ENV_OUTSIDECV,
	ENV_OUTSIDESEQ,
	ENV_OUTSIDEPAD,
	ENV_SIZE
};

static SV *pkgname_env;
static HV *stash_env, *stash_cophh;

static SV *undef_sv;
static SV *warnsv_all, *warnsv_none;

static OP *(*nxck_entersub)(pTHX_ OP *op);
static CV *curenv_cv;

#if QHAVE_COP_HINTS_HASH

# define refcounted_he_inc(rhe) THX_refcounted_he_inc(aTHX_ rhe)
static struct refcounted_he *THX_refcounted_he_inc(pTHX_
	struct refcounted_he *rhe)
{
	HINTS_REFCNT_LOCK;
	rhe->refcounted_he_refcnt++;
	HINTS_REFCNT_UNLOCK;
	return rhe;
}

# ifndef refcounted_he_free
#  define refcounted_he_free(rhe) Perl_refcounted_he_free(aTHX_ rhe)
# endif /* !refcounted_he_free */

# ifdef PERL_MAGIC_hints
#  ifndef hv_copy_hints_hv
#   define hv_copy_hints_hv(hv) Perl_hv_copy_hints_hv(aTHX_ hv)
#  endif /* !hv_copy_hints_hv */
# endif /* PERL_MAGIC_hints */

#endif /* QHAVE_COP_HINTS_HASH */

#define safe_av_fetch(av, index) THX_safe_av_fetch(aTHX_ av, index)
static SV *THX_safe_av_fetch(pTHX_ AV *av, I32 index)
{
	SV **ptr = av_fetch(av, index, 0);
	return ptr ? *ptr : &PL_sv_undef;
}

#define package_to_sv(pkg) THX_package_to_sv(aTHX_ pkg)
static SV *THX_package_to_sv(pTHX_ HV *pkg)
{
	SV *sv;
	if(!pkg) return SvREFCNT_inc(undef_sv);
	sv = newSVpv(HvNAME_get(pkg), 0);
	SvREADONLY_on(sv);
	return sv;
}

#define package_from_sv(sv) THX_package_from_sv(aTHX_ sv)
static HV *THX_package_from_sv(pTHX_ SV *sv)
{
	if(sv_is_undef(sv)) return NULL;
	if(!sv_is_string(sv)) Perl_croak(aTHX_ "malformed package name");
	return gv_stashsv(sv, GV_ADD);
}

#define iv_to_sv(iv) THX_iv_to_sv(aTHX_ iv)
static SV *THX_iv_to_sv(pTHX_ IV iv)
{
	SV *sv = newSViv(iv);
	SvREADONLY_on(sv);
	return sv;
}

#define iv_from_sv(sv) THX_iv_from_sv(aTHX_ sv)
static IV THX_iv_from_sv(pTHX_ SV *sv)
{
	if(!(sv_is_string(sv) && SvIOK(sv)))
		Perl_croak(aTHX_ "malformed integer");
	return SvIV(sv);
}

#define uv_to_sv(uv) THX_uv_to_sv(aTHX_ uv)
static SV *THX_uv_to_sv(pTHX_ UV uv)
{
	SV *sv = newSVuv(uv);
	SvREADONLY_on(sv);
	return sv;
}

#define uv_from_sv(sv) THX_uv_from_sv(aTHX_ sv)
static UV THX_uv_from_sv(pTHX_ SV *sv)
{
	if(!(sv_is_string(sv) && SvIOK(sv)))
		Perl_croak(aTHX_ "malformed integer");
	return SvUV(sv);
}

#define warnings_to_sv(warnings) THX_warnings_to_sv(aTHX_ warnings)
static SV *THX_warnings_to_sv(pTHX_ WARNINGS_t *warnings)
{
	if(warnings == pWARN_ALL) {
		return SvREFCNT_inc(warnsv_all);
	} else if(warnings == pWARN_NONE) {
		return SvREFCNT_inc(warnsv_none);
	} else if(warnings == pWARN_STD) {
		return SvREFCNT_inc(undef_sv);
	} else {
#if QHAVE_WARNINGS_AS_SV
		SV *sv = newSVsv(warnings);
#else /* !QHAVE_WARNINGS_AS_SV */
		SV *sv = newSVpvn((char*)(warnings+1), warnings[0]);
#endif /* !QHAVE_WARNINGS_AS_SV */
		SvREADONLY_on(sv);
		return sv;
	}
}

#define warnings_from_sv(sv) THX_warnings_from_sv(aTHX_ sv)
static WARNINGS_t *THX_warnings_from_sv(pTHX_ SV *sv)
{
	if(sv == warnsv_all) {
		return pWARN_ALL;
	} else if(sv == warnsv_none) {
		return pWARN_NONE;
	} else if(sv_is_undef(sv)) {
		return pWARN_STD;
	} else {
#if QHAVE_WARNINGS_AS_SV
		return newSVsv(sv);
#else /* !QHAVE_WARNINGS_AS_SV */
		char *warn_octets;
		STRLEN len;
		STRLEN *warnings;
		if(!sv_is_string(sv))
			Perl_croak(aTHX_ "malformed warnings bitset");
		warn_octets = SvPV(sv, len);
		warnings = PerlMemShared_malloc(sizeof(*warnings) + len);
		warnings[0] = len;
		Copy(warn_octets, warnings+1, len, char);
		return warnings;
#endif /* !QHAVE_WARNINGS_AS_SV */
	}
}

#if QHAVE_COP_IO

#define iohint_to_sv(iohint) THX_iohint_to_sv(aTHX_ iohint)
static SV *THX_iohint_to_sv(pTHX_ SV *iohint)
{
	SV *sv;
	if(!iohint) return SvREFCNT_inc(undef_sv);
	sv = newSVsv(iohint);
	SvREADONLY_on(sv);
	return sv;
}

#define iohint_from_sv(sv) THX_iohint_from_sv(aTHX_ sv)
static SV *THX_iohint_from_sv(pTHX_ SV *sv)
{
	if(sv_is_undef(sv)) return NULL;
	return newSVsv(sv);
}

#endif /* QHAVE_COP_IO */

#if QHAVE_COP_HINTS_HASH

#define cophh_to_sv(cophh) THX_cophh_to_sv(aTHX_ cophh)
static SV *THX_cophh_to_sv(pTHX_ struct refcounted_he *cophh)
{
	SV *usv, *rsv;
	if(!cophh) return SvREFCNT_inc(undef_sv);
	refcounted_he_inc(cophh);
	usv = newSVuv((UV)cophh);
	rsv = newRV_noinc(usv);
	sv_bless(rsv, stash_cophh);
	SvREADONLY_on(usv);
	SvREADONLY_on(rsv);
	return rsv;
}

#define cophh_from_sv(sv) THX_cophh_from_sv(aTHX_ sv)
static struct refcounted_he *THX_cophh_from_sv(pTHX_ SV *sv)
{
	SV *usv;
	struct refcounted_he *cophh;
	if(sv_is_undef(sv)) return NULL;
	if(!(SvROK(sv) && (usv = SvRV(sv), 1) &&
			SvOBJECT(usv) && SvSTASH(usv) == stash_cophh &&
			SvIOK(usv)))
		Perl_croak(aTHX_ "malformed cop_hints_hash");
	cophh = (struct refcounted_he *)SvUV(usv);
	refcounted_he_inc(cophh);
	return cophh;
}

#endif /* QHAVE_COP_HINTS_HASH */

#define copy_hv(hin, readonly) THX_copy_hv(aTHX_ hin, readonly)
static HV *THX_copy_hv(pTHX_ HV *hin, int readonly)
{
	HV *hout = newHV();
	STRLEN hv_fill = HvFILL(hin);
	if(hv_fill) {
		HE *entry;
		I32 save_riter = HvRITER_get(hin);
		HE *save_eiter = HvEITER_get(hin);
		STRLEN hv_max = HvMAX(hin);
		while(hv_max && hv_max + 1 >= (hv_fill<<1))
			hv_max >>= 1;
		HvMAX(hout) = hv_max;
		hv_iterinit(hin);
		while((entry = hv_iternext_flags(hin, 0))) {
			SV *sv = newSVsv(HeVAL(entry));
			if(readonly) SvREADONLY_on(sv);
			hv_store_flags(hout, HeKEY(entry), HeKLEN(entry),
				sv, HeHASH(entry), HeKFLAGS(entry));
		}
		HvRITER_set(hin, save_riter);
		HvEITER_set(hin, save_eiter);
	}
	if(readonly) SvREADONLY_on((SV*)hout);
	return hout;
}

#define hinthash_to_sv(hinthash) THX_hinthash_to_sv(aTHX_ hinthash)
static SV *THX_hinthash_to_sv(pTHX_ HV *hinthash)
{
	SV *sv;
	if(!hinthash) return SvREFCNT_inc(undef_sv);
	sv = newRV_noinc((SV*)copy_hv(hinthash, 1));
	SvREADONLY_on(sv);
	return sv;
}

#define hinthash_from_sv(sv) THX_hinthash_from_sv(aTHX_ sv)
static HV *THX_hinthash_from_sv(pTHX_ SV *sv)
{
	HV *hh_copy;
	if(sv_is_undef(sv)) return NULL;
	if(!(SvROK(sv) && (hh_copy = (HV*)SvRV(sv), 1) &&
			SvTYPE((SV*)hh_copy) == SVt_PVHV))
		Perl_croak(aTHX_ "malformed hint hash");
#ifdef PERL_MAGIC_hints
	return hv_copy_hints_hv(hh_copy);
#else /* !PERL_MAGIC_hints */
	return copy_hv(hh_copy, 0);
#endif /* !PERL_MAGIC_hints */
}

#define function_to_sv(func) THX_function_to_sv(aTHX_ func)
static SV *THX_function_to_sv(pTHX_ CV *func)
{
	SV *sv = newRV_inc((SV*)func);
	SvREADONLY_on(sv);
	return sv;
}

#define function_from_sv(sv) THX_function_from_sv(aTHX_ sv)
static CV *THX_function_from_sv(pTHX_ SV *sv)
{
	SV *func;
	if(!(SvROK(sv) && (func = SvRV(sv), 1) && SvTYPE(func) == SVt_PVCV))
		Perl_croak(aTHX_ "malformed function reference");
	return (CV*)SvREFCNT_inc(func);
}

#define array_to_sv(array) THX_array_to_sv(aTHX_ array)
static SV *THX_array_to_sv(pTHX_ AV *array)
{
	SV *sv = newRV_inc((SV*)array);
	SvREADONLY_on(sv);
	return sv;
}

#define array_from_sv(sv) THX_array_from_sv(aTHX_ sv)
static AV *THX_array_from_sv(pTHX_ SV *sv)
{
	SV *array;
	if(!(SvROK(sv) && (array = SvRV(sv), 1) && SvTYPE(array) == SVt_PVAV))
		Perl_croak(aTHX_ "malformed array reference");
	return (AV*)SvREFCNT_inc(array);
}

static OP *pp_current_pad(pTHX)
{
	CV *function = find_runcv(NULL);
	SV *functionsv = sv_2mortal(function_to_sv(function));
	U32 seq = PL_curcop->cop_seq;
	SV *seqsv = sv_2mortal(uv_to_sv(seq));
	AV *padlist = CvPADLIST(function);
	AV *padname = (AV*)*av_fetch(padlist, 0, 0);
	SV **pname = AvARRAY(padname);
	I32 fname = AvFILLp(padname);
	I32 fpad = AvFILLp(PL_comppad);
	I32 ix;
	AV *savedpad = newAV();
	SV *savedpadsv = sv_2mortal(newRV_noinc((SV*)savedpad));
	av_extend(savedpad, fpad);
	av_fill(savedpad, fpad);
	for(ix = (fpad<fname ? fpad : fname) + 1; ix--; ) {
		SV *namesv, *vsv, *vref;
		if((namesv = pname[ix]) &&
				SvPOKp(namesv) && SvCUR(namesv) > 1 &&
				(SvFAKE(namesv) ||
					(seq > COP_SEQ_RANGE_LOW(namesv) &&
					 seq <= COP_SEQ_RANGE_HIGH(namesv))) &&
				(vsv = PL_curpad[ix])) {
			vref = newRV_inc(vsv);
			SvREADONLY_on(vref);
			av_store(savedpad, ix, vref);
		}
	}
	SvREADONLY_on((SV*)savedpad);
	SvREADONLY_on(savedpadsv);
	{
		dSP;
		EXTEND(SP, 3);
		PUSHs(functionsv);
		PUSHs(seqsv);
		PUSHs(savedpadsv);
		PUTBACK;
	}
	return PL_op->op_next;
}

#define gen_current_pad_op() THX_gen_current_pad_op(aTHX)
static OP *THX_gen_current_pad_op(pTHX)
{
	OP *op = newSVOP(OP_CONST, 0, &PL_sv_undef);
	op->op_ppaddr = pp_current_pad;
	return op;
}

#define gen_current_environment_op() THX_gen_current_environment_op(aTHX)
static OP *THX_gen_current_environment_op(pTHX)
{
	CV *cv;
	OP *op;
	/*
	 * Prepare current function's pad for eval behaviour.  This
	 * consists of looking up all lexical variables that are currently
	 * in scope, thus getting them into the current function's pad,
	 * in order to make them available for code compiled later in this
	 * scope.  A variable doesn't get inherited into the current pad
	 * unless it is looked up at compile time.
	 */
	for(cv = CvOUTSIDE(PL_compcv); cv; cv = CvOUTSIDE(cv)) {
		AV *padlist, *padname;
		SV **pname;
		I32 fname, ix;
		padlist = CvPADLIST(cv);
		if(!padlist) continue;
		padname = (AV*)*av_fetch(padlist, 0, 0);
		pname = AvARRAY(padname);
		fname = AvFILLp(padname);
		for(ix = fname+1; ix--; ) {
			SV *namesv = pname[ix];
			if(namesv && SvPOKp(namesv) && SvCUR(namesv) > 1)
				(void)pad_findmy_sv(namesv);
		}
	}
	/*
	 * Generate bless([...], "Parse::Perl::Environment") op tree, that
	 * will assemble an environment object at runtime.  The order of
	 * the append_elem clauses must match the ENV_ enumeration.
	 */
	op = NULL;
	op = append_elem(OP_LIST, op, /* ENV_PACKAGE */
		newSVOP(OP_CONST, 0,
			package_to_sv(PL_curstash)));
	op = append_elem(OP_LIST, op, /* ENV_WARNINGS */
		newSVOP(OP_CONST, 0,
			warnings_to_sv(PL_compiling.cop_warnings)));
#if QHAVE_COP_ARYBASE
	op = append_elem(OP_LIST, op, /* ENV_ARYBASE */
		newSVOP(OP_CONST, 0,
			iv_to_sv(PL_compiling.cop_arybase)));
#endif /* QHAVE_COP_ARYBASE */
#if QHAVE_COP_IO
	op = append_elem(OP_LIST, op, /* ENV_IOHINT */
		newSVOP(OP_CONST, 0,
			iohint_to_sv(PL_compiling.cop_io)));
#endif /* QHAVE_COP_IO */
	op = append_elem(OP_LIST, op, /* ENV_HINTBITS */
		newSVOP(OP_CONST, 0,
			uv_to_sv(PL_hints)));
#if QHAVE_COP_HINTS_HASH
	op = append_elem(OP_LIST, op, /* ENV_COPHINTHASH */
		newSVOP(OP_CONST, 0,
			cophh_to_sv(PL_compiling.cop_hints_hash)));
#endif /* QHAVE_COP_HINTS_HASH */
	op = append_elem(OP_LIST, op, /* ENV_HINTHASH */
		newSVOP(OP_CONST, 0,
			hinthash_to_sv(GvHV(PL_hintgv))));
	op = append_elem(OP_LIST, op, /* ENV_OUTSIDE{CV,SEQ,PAD} */
		gen_current_pad_op());
	return newLISTOP(OP_BLESS, 0, newANONLIST(op),
		newSVOP(OP_CONST, 0, SvREFCNT_inc(pkgname_env)));
}

#define rvop_cv(rvop) THX_rvop_cv(aTHX_ rvop)
static CV *THX_rvop_cv(pTHX_ OP *rvop)
{
	switch(rvop->op_type) {
		case OP_CONST: {
			SV *rv = cSVOPx_sv(rvop);
			return SvROK(rv) ? (CV*)SvRV(rv) : NULL;
		} break;
		case OP_GV: return GvCV(cGVOPx_gv(rvop));
		default: return NULL;
	}
}

static OP *ck_entersub(pTHX_ OP *op)
{
	OP *pushop, *cvop;
	pushop = cUNOPx(op)->op_first;
	if(!pushop->op_sibling) pushop = cUNOPx(pushop)->op_first;
	for(cvop = pushop; cvop->op_sibling; cvop = cvop->op_sibling) ;
	if(cvop->op_type == OP_RV2CV &&
			!(cvop->op_private & OPpENTERSUB_AMPER) &&
			rvop_cv(cUNOPx(cvop)->op_first) == curenv_cv) {
		op = nxck_entersub(aTHX_ op);   /* for prototype checking */
		op_free(op);
		return gen_current_environment_op();
	} else {
		return nxck_entersub(aTHX_ op);
	}
}

#ifdef PARENT_PAD_INDEX

#define populate_pad() THX_populate_pad(aTHX)
static void THX_populate_pad(pTHX)
{
	/* pad is fully populated during normal compilation */
}

#else /* !PARENT_PAD_INDEX */

#define var_from_outside_compcv(cv, namesv) \
	THX_var_from_outside_compcv(aTHX_ cv, namesv)
static int THX_var_from_outside_compcv(pTHX_ CV *cv, SV *namesv)
{
	while(1) {
		/*
		 * Loop invariant: the variable identified by namesv
		 * is inherited into cv from outside, and cv is not
		 * PL_compcv.
		 */
		U32 seq;
		AV *padname;
		I32 ix;
		seq = CvOUTSIDE_SEQ(cv);
		cv = CvOUTSIDE(cv);
		if(!cv) return 0;
		padname = (AV*)*av_fetch(CvPADLIST(cv), 0, 0);
		for(ix = AvFILLp(padname)+1; ix--; ) {
			SV **pnamesv_p, *pnamesv;
			if((pnamesv_p = av_fetch(padname, ix, 0)) &&
					(pnamesv = *pnamesv_p) &&
					SvPOKp(pnamesv) &&
					strEQ(SvPVX(pnamesv), SvPVX(namesv)) &&
					seq > COP_SEQ_RANGE_LOW(pnamesv) &&
					seq <= COP_SEQ_RANGE_HIGH(pnamesv))
				return 0;
		}
		if(cv == PL_compcv) return 1;
	}
}

#define populate_pad_from_sub(func) THX_populate_pad_from_sub(aTHX_ func)
static void THX_populate_pad_from_sub(pTHX_ CV *func)
{
	AV *padname = (AV*)*av_fetch(CvPADLIST(func), 0, 0);
	I32 ix;
	for(ix = AvFILLp(padname)+1; ix--; ) {
		SV **namesv_p, *namesv;
		if((namesv_p = av_fetch(padname, ix, 0)) &&
				(namesv = *namesv_p) &&
				SvPOKp(namesv) && SvCUR(namesv) > 1 &&
				SvFAKE(namesv) &&
				var_from_outside_compcv(func, namesv)) {
			(void)pad_findmy_sv(namesv);
		}
	}
}

#define populate_pad_recursively(func) THX_populate_pad_recursively(aTHX_ func)
static void THX_populate_pad_recursively(pTHX_ CV *func);
static void THX_populate_pad_recursively(pTHX_ CV *func)
{
	AV *padlist = CvPADLIST(func);
	AV *padname = (AV*)*av_fetch(padlist, 0, 0);
	AV *pad = (AV*)*av_fetch(padlist, 1, 0);
	I32 ix;
	for(ix = AvFILLp(padname)+1; ix--; ) {
		SV **namesv_p, *namesv;
		CV *sub;
		if((namesv_p = av_fetch(padname, ix, 0)) &&
				(namesv = *namesv_p) &&
				SvPOKp(namesv) && SvCUR(namesv) == 1 &&
				*SvPVX(namesv) == '&' &&
				(sub = (CV*)*av_fetch(pad, ix, 0)) &&
				CvCLONE(sub)) {
			populate_pad_from_sub(sub);
			populate_pad_recursively(sub);
		}
	}
}

#define populate_pad() THX_populate_pad(aTHX)
static void THX_populate_pad(pTHX)
{
	populate_pad_recursively(PL_compcv);
}

#endif /* !PARENT_PAD_INDEX */

#define close_pad(func, outpad) THX_close_pad(aTHX_ func, outpad)
static void THX_close_pad(pTHX_ CV *func, AV *outpad)
{
#ifndef PARENT_PAD_INDEX
	CV *out = CvOUTSIDE(func);
	AV *out_padlist = out ? CvPADLIST(out) : NULL;
	AV *out_padname =
		out_padlist ? (AV*)*av_fetch(out_padlist, 0, 0) : NULL;
	SV **out_pname = out_padname ? AvARRAY(out_padname) : NULL;
	I32 out_fname = out_padname ? AvFILLp(out_padname) : 0;
	U32 out_seq = CvOUTSIDE_SEQ(func);
#endif /* !PARENT_PAD_INDEX */
	AV *padlist = CvPADLIST(func);
	AV *padname = (AV*)*av_fetch(padlist, 0, 0);
	AV *pad = (AV*)*av_fetch(padlist, 1, 0);
	SV **pname = AvARRAY(padname);
	SV **ppad = AvARRAY(pad);
	I32 fname = AvFILLp(padname);
	I32 fpad = AvFILLp(pad);
	I32 ix;
	for(ix = fname+1; ix--; ) {
		SV *namesv = pname[ix];
		I32 pix;
#ifndef PARENT_PAD_INDEX
		I32 fpix;
#endif /* !PARENT_PAD_INDEX */
		SV *vref, *vsv;
		if(!(namesv && SvFAKE(namesv))) continue;
#ifdef PARENT_PAD_INDEX
		pix = PARENT_PAD_INDEX(namesv);
#else /* !PARENT_PAD_INDEX */
		fpix = 0;
		for(pix = out_fname; pix != 0; pix--) {
			SV *out_namesv = out_pname[pix];
			if(!(out_namesv && SvPOKp(out_namesv) &&
				strEQ(SvPVX(out_namesv), SvPVX(namesv))))
					continue;
			if(SvFAKE(out_namesv)) {
					fpix = pix;
			} else if(out_seq > COP_SEQ_RANGE_LOW(out_namesv) &&
				  out_seq <= COP_SEQ_RANGE_HIGH(out_namesv)) {
					break;
			}
		}
		if(pix == 0) pix = fpix;
#endif /* !PARENT_PAD_INDEX */
		if(!(pix != 0 && ix <= fpad &&
				(vref = safe_av_fetch(outpad, pix), 1) &&
				SvROK(vref) && (vsv = SvRV(vref), 1) &&
				!(SvPADSTALE(vsv) && !SvPAD_STATE(namesv))))
			Perl_croak(aTHX_ "Variable \"%s\" is not available",
					SvPVX_const(namesv));
		SvREFCNT_inc(vsv);
		if(ppad[ix]) SvREFCNT_dec(ppad[ix]);
		ppad[ix] = vsv;
	}
}

MODULE = Parse::Perl PACKAGE = Parse::Perl

BOOT:
	undef_sv = newSV(0);
	SvREADONLY_on(undef_sv);
	pkgname_env = newSVpvs("Parse::Perl::Environment");
	SvREADONLY_on(pkgname_env);
	stash_env = gv_stashpv("Parse::Perl::Environment", 1);
	stash_cophh = gv_stashpv("Parse::Perl::CopHintsHash", 1);
	warnsv_all = newSVpvn(WARN_ALLstring, WARNsize);
	SvREADONLY_on(warnsv_all);
	warnsv_none = newSVpvn(WARN_NONEstring, WARNsize);
	SvREADONLY_on(warnsv_none);
	nxck_entersub = PL_check[OP_ENTERSUB];
	PL_check[OP_ENTERSUB] = ck_entersub;
	curenv_cv = get_cv("Parse::Perl::current_environment", 0);


void
current_environment(...)
PROTOTYPE:
CODE:
	Perl_croak(aTHX_ "current_environment called as a function");

CV *
parse_perl(SV *environment, SV *source)
PROTOTYPE: $$
PREINIT:
	AV *enva;
CODE:
	TAINT_IF(SvTAINTED(environment));
	TAINT_IF(SvTAINTED(source));
	TAINT_PROPER("parse_perl");
	if(!(SvROK(environment) && (enva = (AV*)SvRV(environment), 1) &&
			SvOBJECT((SV*)enva) &&
			SvSTASH((SV*)enva) == stash_env &&
			SvTYPE((SV*)enva) == SVt_PVAV))
		Perl_croak(aTHX_ "environment is not an environment object");
	if(!sv_is_string(source)) Perl_croak(aTHX_ "source is not a string");
	ENTER;
	SAVETMPS;
	/* populate PL_compiling and related state */
	SAVECOPFILE_FREE(&PL_compiling);
	{
		char filename[TYPE_DIGITS(long) + 10];
		sprintf(filename, "(eval %lu)", (unsigned long)++PL_evalseq);
		CopFILE_set(&PL_compiling, filename);
	}
	SAVECOPLINE(&PL_compiling);
	CopLINE_set(&PL_compiling, 1);
	SAVEI32(PL_subline);
	PL_subline = 1;
	SAVESPTR(PL_curstash);
	PL_curstash = package_from_sv(safe_av_fetch(enva, ENV_PACKAGE));
	save_item(PL_curstname);
	sv_setpv(PL_curstname,
			!PL_curstash ? "<none>" : HvNAME_get(PL_curstash));
	SAVECOPSTASH_FREE(&PL_compiling);
	CopSTASH_set(&PL_compiling, PL_curstash);
#if QHAVE_WARNINGS_AS_SV
	SAVESPTR(PL_compiling.cop_warnings);
#else /* !QHAVE_WARNINGS_AS_SV */
	SAVECOMPILEWARNINGS();
#endif /* !QHAVE_WARNINGS_AS_SV */
	PL_compiling.cop_warnings =
		warnings_from_sv(safe_av_fetch(enva, ENV_WARNINGS));
#if QHAVE_WARNINGS_AS_SV
	if(!specialWARN(PL_compiling.cop_warnings))
		SAVEFREESV(PL_compiling.cop_warnings);
#endif /* QHAVE_WARNINGS_AS_SV */
#if QHAVE_COP_ARYBASE
	SAVEI32(PL_compiling.cop_arybase);
	PL_compiling.cop_arybase =
		iv_from_sv(safe_av_fetch(enva, ENV_ARYBASE));
#endif /* QHAVE_COP_ARYBASE */
#if QHAVE_COP_IO
	SAVESPTR(PL_compiling.cop_io);
	PL_compiling.cop_io = iohint_from_sv(safe_av_fetch(enva, ENV_IOHINT));
	if(PL_compiling.cop_io) SAVEFREESV(PL_compiling.cop_io);
#endif /* QHAVE_COP_IO */
	PL_hints |= HINT_LOCALIZE_HH;
	SAVEHINTS();
	PL_hints = uv_from_sv(safe_av_fetch(enva, ENV_HINTBITS)) |
		HINT_BLOCK_SCOPE;
	{
		HV *old_hh = GvHV(PL_hintgv);
		GvHV(PL_hintgv) =
			hinthash_from_sv(safe_av_fetch(enva, ENV_HINTHASH));
		if(old_hh) SvREFCNT_dec(old_hh);
	}
#if QHAVE_COP_HINTS_HASH
	{
		struct refcounted_he *old_cophh = PL_compiling.cop_hints_hash;
		PL_compiling.cop_hints_hash =
			cophh_from_sv(safe_av_fetch(enva, ENV_COPHINTHASH));
		if(old_cophh) refcounted_he_free(old_cophh);
	}
#endif /* QHAVE_COP_HINTS_HASH */
#if QHAVE_COP_HINTS
	SAVEI32(PL_compiling.cop_hints);
	PL_compiling.cop_hints = PL_hints;
#endif /* QHAVE_COP_HINTS */
#if QHAVE_COP_LABEL
	SAVEPPTR(PL_compiling.cop_label);
	PL_compiling.cop_label = NULL;
#endif /* QHAVE_COP_LABEL */
	SAVEVPTR(PL_curcop);
	PL_curcop = &PL_compiling;
	/* initialise PL_compcv and related state */
	SAVEGENERICSV(PL_compcv);
	PL_compcv = (CV*)newSV_type(SVt_PVCV);
	CvANON_on(PL_compcv);
	CvSTASH(PL_compcv) = PL_curstash;
	CvGV_set(PL_compcv, PL_curstash ?
		gv_fetchpvs("__ANON__", GV_ADDMULTI, SVt_PVCV) :
		gv_fetchpvs("__ANON__::__ANON__", GV_ADDMULTI, SVt_PVCV));
	CvOUTSIDE(PL_compcv) =
		function_from_sv(safe_av_fetch(enva, ENV_OUTSIDECV));
	CvOUTSIDE_SEQ(PL_compcv) =
		uv_from_sv(safe_av_fetch(enva, ENV_OUTSIDESEQ));
	CvPADLIST(PL_compcv) = pad_new(padnew_SAVE);
	/* initialise other parser state */
	SAVEOP();
	PL_op = NULL;
	SAVEGENERICSV(PL_beginav);
	PL_beginav = newAV();
#if QHAVE_UNITCHECK
	SAVEGENERICSV(PL_unitcheckav);
	PL_unitcheckav = newAV();
#endif /* QHAVE_UNITCHECK */
	SAVEVPTR(PL_eval_root);
	PL_eval_root = NULL;
	SAVEVPTR(PL_eval_start);
	PL_eval_start = NULL;
	/* parse */
	{
		int parse_fail;
		U8 old_in_eval;
		SAVEI8(PL_in_eval);
		old_in_eval = PL_in_eval;
		PL_in_eval = EVAL_INEVAL;
		lex_start_simple(source);
		parse_fail = yyparse();
		lex_end();
		PL_in_eval = old_in_eval;
		if(parse_fail || PL_error_count || !PL_eval_root ||
				PL_eval_root->op_type != OP_LEAVEEVAL) {
			if(PL_eval_root) {
				op_free(PL_eval_root);
				PL_eval_root = NULL;
				PL_eval_start = NULL;
			}
			if(!(SvPOK(ERRSV) && SvCUR(ERRSV) != 0))
				sv_setpvs(ERRSV, "Compilation error");
			Perl_die(aTHX_ NULL);
		}
	}
	/* construct and return result */
	PL_eval_root->op_type = OP_LEAVESUB;
	PL_eval_root->op_ppaddr = PL_ppaddr[OP_LEAVESUB];
	PL_eval_root->op_flags &= OPf_KIDS|OPf_PARENS;
	CvROOT(PL_compcv) = PL_eval_root;
	CvSTART(PL_compcv) = PL_eval_start;
	if(CvCLONE(PL_compcv)) {
		populate_pad();
		close_pad(PL_compcv,
			array_from_sv(safe_av_fetch(enva, ENV_OUTSIDEPAD)));
		CvCLONE_off(PL_compcv);
	}
	pad_tidy(padtidy_SUB);
#if QHAVE_UNITCHECK
	if(PL_unitcheckav) call_list(PL_scopestack_ix, PL_unitcheckav);
#endif /* QHAVE_UNITCHECK */
	RETVAL = (CV*)SvREFCNT_inc((SV*)PL_compcv);
	FREETMPS;
	LEAVE;
OUTPUT:
	RETVAL

MODULE = Parse::Perl PACKAGE = Parse::Perl::CopHintsHash

void
DESTROY(SV *sv)
PREINIT:
#if QHAVE_COP_HINTS_HASH
	SV *usv;
	struct refcounted_he *cophh;
#endif /* QHAVE_COP_HINTS_HASH */
CODE:
#if QHAVE_COP_HINTS_HASH
	if(!(SvROK(sv) && (usv = SvRV(sv), 1) &&
			SvOBJECT(usv) && SvSTASH(usv) == stash_cophh &&
			SvIOK(usv)))
		Perl_croak(aTHX_ "malformed cop_hints_hash");
	cophh = (struct refcounted_he *)SvUV(usv);
	refcounted_he_free(cophh);
#endif /* QHAVE_COP_HINTS_HASH */
