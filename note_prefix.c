/*
 * note_prefix.c
 *
 * Planner hook that lets byte-prefix searches of the form
 *
 *     substring(<bytea expr> from 1 for N) = <value>
 *
 * use a btree expression index on substring(<bytea expr> from 1 for K)
 * for any N, not only N = K.
 *
 * PostgreSQL only considers an index for a clause when the indexed
 * expression is a *direct* operand of the clause's operator (see
 * match_opclause_to_indexcol() in indxpath.c).  Here the indexed expression
 * is nested inside substring(), so no opclass or support function ever gets
 * asked.  This module therefore rewrites the Query before planning:
 *
 *     substring(x,1,N) = B
 *  => <derived conditions on substring(x,1,K)> AND substring(x,1,N) = B
 *
 * With P = substring(x,1,K) the derived conditions are:
 *
 *   N > K :  P = substring(B,1,K)           (also works for Param B)
 *            Lossy: the original clause is kept as a recheck filter.
 *   N = K :  P = B                          (only when the call is spelled
 *            differently from the index expression, e.g. substr() or
 *            FROM 0 FOR K+1; otherwise the planner matches it directly)
 *   N < K :  len(B) <  N : P = B            (x must equal B exactly)
 *            len(B) =  N : P >= B AND P < byte_successor(B)
 *                          (upper bound dropped when B is all 0xFF)
 *            len(B) >  N : as for N > K (the clause is always false)
 *
 * For N <= K the derived conditions are an *exact* three-valued equivalent
 * of the original clause (bytea order is memcmp-then-length, so "starts
 * with B" is precisely the half-open range [B, successor(B))), and the
 * original clause is dropped.  That matters for costing: a retained
 * redundant clause would be multiplied in at default selectivity and
 * underestimate the row count by orders of magnitude.
 *
 * The N < K case needs the value of B at plan time; for an unbound Param
 * (generic plan) nothing is derived, which leaves that plan expensive and
 * makes the plan cache stick to custom plans, exactly like LIKE 'foo%'.
 *
 * Which K to use is taken from the indexes that actually exist on the
 * referenced table, so no configuration has to be kept in sync with DDL.
 *
 * Load via shared_preload_libraries (or session_preload_libraries for one
 * role).  Disable at runtime with SET pg_algorand.prefix_rewrite = off.
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/relation.h"
#include "catalog/pg_operator_d.h"
#include "catalog/pg_type_d.h"
#include "fmgr.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/params.h"
#include "optimizer/clauses.h"
#include "optimizer/optimizer.h"
#include "optimizer/planner.h"
#include "parser/parsetree.h"
#include "rewrite/rewriteManip.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "varatt.h"

void		_PG_init(void);

static planner_hook_type prev_planner_hook = NULL;
static bool prefix_rewrite_enabled = true;

/*
 * Added to the total cost of a plan built without the value of an external
 * parameter that a N < K prefix clause needed (i.e. a plan cache generic
 * plan).  Such a plan cannot use the prefix index, and since the planner has
 * no value to estimate with, the unindexed plan looks cheap (LIMIT over a
 * primary-key scan at default selectivity).  plancache.c compares the generic
 * plan's cost with the average custom plan cost, so inflating it keeps the
 * statement on custom plans, where the value is known and the index is used.
 */
#define PREFIX_UNBOUND_PARAM_PENALTY	1.0e10

typedef struct PrefixCtx
{
	Query	   *query;			/* Query level whose rtable level-0 Vars use */
	ParamListInfo boundParams;	/* bound values for custom plans, or NULL */
	int			nrewrites;
	bool		unbound_below_k;	/* N < K clause with a Param lacking a value */
} PrefixCtx;

typedef struct VarnoCtx
{
	int			varno;
	bool		ok;
} VarnoCtx;

/*
 * Recognize substring(x, s, l) / substr(x, s, l) on bytea where s and l are
 * int4 Consts describing a prefix (s <= 1).  Returns the effective prefix
 * length (>= 1) and sets *x, or returns -1 if the node is not such a call.
 */
static int
match_bytea_prefix_call(Node *node, Node **x)
{
	FuncExpr   *f;
	Const	   *sc;
	Const	   *lc;
	int64		s;
	int64		l;
	int64		n;

	if (node == NULL || !IsA(node, FuncExpr))
		return -1;
	f = (FuncExpr *) node;
	if (f->funcid != F_SUBSTRING_BYTEA_INT4_INT4 &&
		f->funcid != F_SUBSTR_BYTEA_INT4_INT4)
		return -1;
	if (list_length(f->args) != 3)
		return -1;
	if (!IsA(lsecond(f->args), Const) || !IsA(lthird(f->args), Const))
		return -1;
	sc = (Const *) lsecond(f->args);
	lc = (Const *) lthird(f->args);
	if (sc->constisnull || lc->constisnull ||
		sc->consttype != INT4OID || lc->consttype != INT4OID)
		return -1;
	s = DatumGetInt32(sc->constvalue);
	l = DatumGetInt32(lc->constvalue);
	if (s > 1 || l < 1)
		return -1;
	/* SQL semantics: positions s .. s+l-1, clipped to start at 1 */
	n = s + l - 1;
	if (n < 1 || n > PG_INT32_MAX)
		return -1;
	*x = (Node *) linitial(f->args);
	return (int) n;
}

/*
 * Collect the single varno referenced by an expression.  Fails (ok = false)
 * on outer-level Vars, more than one rel, or anything that is not a plain
 * scalar expression.
 */
static bool
collect_varno_walker(Node *node, VarnoCtx *c)
{
	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var		   *v = (Var *) node;

		if (v->varlevelsup != 0)
		{
			c->ok = false;
			return true;
		}
		if (c->varno == 0)
			c->varno = v->varno;
		else if (c->varno != (int) v->varno)
		{
			c->ok = false;
			return true;
		}
		return false;
	}
	if (IsA(node, Query) || IsA(node, SubLink) || IsA(node, SubPlan) ||
		IsA(node, Aggref) || IsA(node, GroupingFunc) ||
		IsA(node, WindowFunc) || IsA(node, PlaceHolderVar))
	{
		c->ok = false;
		return true;
	}
	return expression_tree_walker(node, collect_varno_walker, c);
}

/* Is it safe to evaluate this expression twice? */
static bool
expr_is_duplicable(Node *node)
{
	return !contain_volatile_functions(node) &&
		!expression_returns_set(node) &&
		!checkExprHasSubLink(node) &&
		!contain_agg_clause(node) &&
		!contain_window_function(node);
}

static Const *
make_int4_const(int32 v)
{
	return makeConst(INT4OID, -1, InvalidOid, sizeof(int32),
					 Int32GetDatum(v), false, true);
}

static Const *
make_bytea_const(const unsigned char *data, int len)
{
	bytea	   *b = (bytea *) palloc(VARHDRSZ + len);

	SET_VARSIZE(b, VARHDRSZ + len);
	if (len > 0)
		memcpy(VARDATA(b), data, len);
	return makeConst(BYTEAOID, -1, InvalidOid, -1,
					 PointerGetDatum(b), false, false);
}

/* First min(len, k) bytes of a bytea Const. */
static Const *
const_prefix(Const *b, int k)
{
	bytea	   *v = (bytea *) DatumGetPointer(b->constvalue);
	int			len = VARSIZE_ANY_EXHDR(v);

	return make_bytea_const((unsigned char *) VARDATA_ANY(v), Min(len, k));
}

/*
 * Smallest bytea greater than every bytea that starts with b: increment the
 * last byte that is not 0xFF and truncate after it.  NULL if b is empty or
 * all 0xFF (then "starts with b" has no upper bound).
 */
static Const *
bytea_successor(Const *b)
{
	bytea	   *v = (bytea *) DatumGetPointer(b->constvalue);
	int			len = VARSIZE_ANY_EXHDR(v);
	const unsigned char *src = (const unsigned char *) VARDATA_ANY(v);
	int			i;

	for (i = len - 1; i >= 0; i--)
	{
		if (src[i] != 0xFF)
		{
			unsigned char *buf = (unsigned char *) palloc(i + 1);
			Const	   *result;

			memcpy(buf, src, i + 1);
			buf[i]++;
			result = make_bytea_const(buf, i + 1);
			pfree(buf);
			return result;
		}
	}
	return NULL;
}

static Node *
make_bytea_opclause(Oid opno, Oid opfuncid, Node *left, Node *right)
{
	OpExpr	   *op = (OpExpr *) make_opclause(opno, BOOLOID, false,
											  (Expr *) left, (Expr *) right,
											  InvalidOid, InvalidOid);

	op->opfuncid = opfuncid;
	return (Node *) op;
}

/* Clear varnullingrels on every Var of an (already copied) expression. */
static bool
strip_nullingrels_walker(Node *node, void *ctx)
{
	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		((Var *) node)->varnullingrels = NULL;
		return false;
	}
	return expression_tree_walker(node, strip_nullingrels_walker, ctx);
}

/*
 * substring(x, 1, k) built from the query's own x, so its Vars carry the
 * same varnullingrels as the original clause; the planner const-folds it
 * into the same form as the stored index expression.
 */
static Node *
make_prefix_call(Node *x, int k)
{
	return (Node *) makeFuncExpr(F_SUBSTRING_BYTEA_INT4_INT4, BYTEAOID,
								 list_make3(copyObject(x),
											make_int4_const(1),
											make_int4_const(k)),
								 InvalidOid, InvalidOid,
								 COERCE_EXPLICIT_CALL);
}

/*
 * If b is a Const, or an external Param whose bound value the planner is
 * allowed to treat as a constant (custom plan), return it as a Const.
 * Mirrors the Param handling in eval_const_expressions_mutator().
 */
static Const *
resolve_const(Node *b, PrefixCtx *ctx)
{
	Param	   *param;
	ParamListInfo paramLI = ctx->boundParams;
	ParamExternData *prm;
	ParamExternData prmdata;
	int16		typLen;
	bool		typByVal;
	Datum		pval;

	if (IsA(b, Const))
		return (Const *) b;
	if (!IsA(b, Param))
		return NULL;
	param = (Param *) b;
	if (param->paramkind != PARAM_EXTERN || paramLI == NULL ||
		param->paramid <= 0 || param->paramid > paramLI->numParams)
		return NULL;
	if (paramLI->paramFetch != NULL)
		prm = paramLI->paramFetch(paramLI, param->paramid, true, &prmdata);
	else
		prm = &paramLI->params[param->paramid - 1];
	if (!OidIsValid(prm->ptype) || prm->ptype != param->paramtype ||
		!(prm->pflags & PARAM_FLAG_CONST))
		return NULL;
	get_typlenbyval(param->paramtype, &typLen, &typByVal);
	if (prm->isnull || typByVal)
		pval = prm->value;
	else
		pval = datumCopy(prm->value, typByVal, typLen);
	return makeConst(param->paramtype, param->paramtypmod, param->paramcollid,
					 (int) typLen, pval, prm->isnull, typByVal);
}

/*
 * Look through the valid indexes of the relation behind varno for expression
 * columns of the form substring(x', 1, K) with x' equal to xpre, other than
 * the query's own (const-folded, nulling-rels-stripped) call callpre.
 * Returns the list of distinct K found.
 */
static List *
find_prefix_indexes(PrefixCtx *ctx, int varno, Node *callpre, Node *xpre)
{
	RangeTblEntry *rte;
	Relation	rel;
	List	   *indexoids;
	List	   *klist = NIL;
	ListCell   *lc;

	if (varno <= 0 || varno > list_length(ctx->query->rtable))
		return NIL;
	rte = rt_fetch(varno, ctx->query->rtable);
	if (rte->rtekind != RTE_RELATION)
		return NIL;
	if (rte->relkind != RELKIND_RELATION &&
		rte->relkind != RELKIND_MATVIEW &&
		rte->relkind != RELKIND_PARTITIONED_TABLE)
		return NIL;

	/* The parser already locked the table; indexes get the same lock mode. */
	rel = relation_open(rte->relid, NoLock);
	indexoids = RelationGetIndexList(rel);
	foreach(lc, indexoids)
	{
		Relation	irel = index_open(lfirst_oid(lc), rte->rellockmode);

		if (irel->rd_index->indisvalid)
		{
			List	   *exprs = RelationGetIndexExpressions(irel);
			ListCell   *lc2;

			foreach(lc2, exprs)
			{
				Node	   *e = (Node *) lfirst(lc2);
				Node	   *ix;
				int			k;

				ChangeVarNodes(e, 1, varno, 0);
				k = match_bytea_prefix_call(e, &ix);
				/*
				 * Skip expressions identical to the query's call: the
				 * planner matches those on its own.
				 */
				if (k > 0 && equal(ix, xpre) && !equal(callpre, e) &&
					!list_member_int(klist, k))
					klist = lappend_int(klist, k);
			}
		}
		index_close(irel, NoLock);
	}
	list_free(indexoids);
	relation_close(rel, NoLock);
	return klist;
}

/*
 * op is a bytea equality whose arguments have already been mutated.  Return
 * op itself, the exactly-equivalent derived condition(s), or
 * (derived AND ... AND op) when the derivation is lossy.
 */
static Node *
rewrite_bytea_eq(OpExpr *op, PrefixCtx *ctx)
{
	Node	   *x = NULL;
	Node	   *call;
	Node	   *callpre;
	Node	   *xpre;
	Node	   *b;
	Const	   *bconst;
	int			n;
	VarnoCtx	vc;
	List	   *klist;
	List	   *derived = NIL;
	bool		keep_orig = false;
	ListCell   *lk;

	if (list_length(op->args) != 2)
		return (Node *) op;

	call = (Node *) linitial(op->args);
	n = match_bytea_prefix_call(call, &x);
	if (n > 0)
		b = (Node *) lsecond(op->args);
	else
	{
		call = (Node *) lsecond(op->args);
		n = match_bytea_prefix_call(call, &x);
		if (n <= 0)
			return (Node *) op;
		b = (Node *) linitial(op->args);
	}

	vc.varno = 0;
	vc.ok = true;
	(void) collect_varno_walker(x, &vc);
	if (!vc.ok || vc.varno == 0)
		return (Node *) op;
	if (!expr_is_duplicable(x) || !expr_is_duplicable(b))
		return (Node *) op;

	bconst = resolve_const(b, ctx);
	if (bconst != NULL && bconst->constisnull)
		return (Node *) op;		/* clause is NULL anyway */

	/*
	 * Index expressions come back const-folded; fold a copy of the call the
	 * same way so equal() compares like with like.
	 */
	callpre = eval_const_expressions(NULL, copyObject(call));
	if (match_bytea_prefix_call(callpre, &xpre) != n)
		return (Node *) op;
	/* index expressions never carry nulling rels; compare without them */
	(void) strip_nullingrels_walker(callpre, NULL);

	klist = find_prefix_indexes(ctx, vc.varno, callpre, xpre);
	if (klist == NIL)
		return (Node *) op;

	foreach(lk, klist)
	{
		int			k = lfirst_int(lk);
		int			blen = -1;

		if (bconst != NULL)
			blen = VARSIZE_ANY_EXHDR(DatumGetPointer(bconst->constvalue));

		if (n == k)
		{
			/*
			 * Same value as the index expression, merely spelled differently
			 * (substr(), FROM 0 FOR k+1, ...): P = B is exactly equivalent.
			 */
			derived = lappend(derived,
							  make_bytea_opclause(ByteaEqualOperator,
												  F_BYTEAEQ,
												  make_prefix_call(x, k),
												  copyObject(b)));
		}
		else if (n > k || blen > n)
		{
			/*
			 * substring(x,1,n) = B  =>  substring(x,1,k) = substring(B,1,k).
			 * Lossy (or, for len(B) > n, vacuous): keep the original clause.
			 */
			Node	   *rhs;

			if (bconst != NULL)
				rhs = (Node *) const_prefix(bconst, k);
			else
				rhs = (Node *) makeFuncExpr(F_SUBSTRING_BYTEA_INT4_INT4,
											BYTEAOID,
											list_make3(copyObject(b),
													   make_int4_const(1),
													   make_int4_const(k)),
											InvalidOid, InvalidOid,
											COERCE_EXPLICIT_CALL);
			derived = lappend(derived,
							  make_bytea_opclause(ByteaEqualOperator,
												  F_BYTEAEQ,
												  make_prefix_call(x, k),
												  rhs));
			keep_orig = true;
		}
		else if (bconst == NULL)
		{
			/* n < k: need the value to bound the range */
			if (IsA(b, Param) && ((Param *) b)->paramkind == PARAM_EXTERN)
				ctx->unbound_below_k = true;
			continue;
		}
		else if (blen < n)
		{
			/* substring(x,1,n) = B with len(B) < n  <=>  x = B  <=>  P = B */
			derived = lappend(derived,
							  make_bytea_opclause(ByteaEqualOperator,
												  F_BYTEAEQ,
												  make_prefix_call(x, k),
												  (Node *) copyObject(bconst)));
		}
		else
		{
			/* len(B) = n < k: x starts with B  <=>  B <= P < successor(B) */
			Const	   *succ = bytea_successor(bconst);

			derived = lappend(derived,
							  make_bytea_opclause(ByteaGreaterEqualOperator,
												  F_BYTEAGE,
												  make_prefix_call(x, k),
												  (Node *) copyObject(bconst)));
			if (succ != NULL)
				derived = lappend(derived,
								  make_bytea_opclause(ByteaLessOperator,
													  F_BYTEALT,
													  make_prefix_call(x, k),
													  (Node *) succ));
		}
	}

	if (derived == NIL)
		return (Node *) op;

	ctx->nrewrites++;
	if (keep_orig)
		derived = lappend(derived, op);
	if (list_length(derived) == 1)
		return (Node *) linitial(derived);
	return (Node *) make_andclause(derived);
}

static Node *
prefix_mutator(Node *node, PrefixCtx *ctx)
{
	if (node == NULL)
		return NULL;
	if (IsA(node, Query))
	{
		Query	   *saved = ctx->query;
		Query	   *result;

		ctx->query = (Query *) node;
		result = query_tree_mutator((Query *) node, prefix_mutator, ctx, 0);
		ctx->query = saved;
		return (Node *) result;
	}
	if (IsA(node, OpExpr) && ((OpExpr *) node)->opno == ByteaEqualOperator)
	{
		OpExpr	   *op = (OpExpr *) expression_tree_mutator(node,
															prefix_mutator,
															ctx);

		return rewrite_bytea_eq(op, ctx);
	}
	return expression_tree_mutator(node, prefix_mutator, ctx);
}

/* Cheap pre-check so the vast majority of queries never get copied. */
static bool
has_candidate_walker(Node *node, void *ctx)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
		return query_tree_walker((Query *) node, has_candidate_walker, ctx, 0);
	if (IsA(node, OpExpr))
	{
		OpExpr	   *op = (OpExpr *) node;
		Node	   *x;

		if (op->opno == ByteaEqualOperator && list_length(op->args) == 2 &&
			(match_bytea_prefix_call(linitial(op->args), &x) > 0 ||
			 match_bytea_prefix_call(lsecond(op->args), &x) > 0))
			return true;
	}
	return expression_tree_walker(node, has_candidate_walker, ctx);
}

static PlannedStmt *
pg_algorand_planner(Query *parse, const char *query_string,
					int cursorOptions, ParamListInfo boundParams)
{
	PlannedStmt *result;
	bool		penalize = false;

	if (prefix_rewrite_enabled && parse->commandType != CMD_UTILITY &&
		query_tree_walker(parse, has_candidate_walker, NULL, 0))
	{
		PrefixCtx	ctx;

		ctx.query = parse;
		ctx.boundParams = boundParams;
		ctx.nrewrites = 0;
		ctx.unbound_below_k = false;
		parse = query_tree_mutator(parse, prefix_mutator, &ctx, 0);
		if (ctx.nrewrites > 0)
			elog(DEBUG1, "pg_algorand: derived prefix-index conditions for %d clause(s)",
				 ctx.nrewrites);
		penalize = ctx.unbound_below_k;
	}

	if (prev_planner_hook)
		result = prev_planner_hook(parse, query_string, cursorOptions,
								   boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions,
								  boundParams);

	if (penalize && result != NULL && result->planTree != NULL)
	{
		elog(DEBUG1, "pg_algorand: prefix clause with unbound parameter, "
			 "marking plan as expensive for the plan cache");
		result->planTree->total_cost += PREFIX_UNBOUND_PARAM_PENALTY;
	}
	return result;
}

void
_PG_init(void)
{
	DefineCustomBoolVariable("pg_algorand.prefix_rewrite",
							 "Derive index conditions for substring(bytea_expr, 1, N) = value quals.",
							 "When on, the planner adds conditions on any existing "
							 "substring(bytea_expr, 1, K) expression index so byte-prefix "
							 "searches can use it for every N.",
							 &prefix_rewrite_enabled,
							 true,
							 PGC_USERSET,
							 0,
							 NULL, NULL, NULL);
	MarkGUCPrefixReserved("pg_algorand");

	prev_planner_hook = planner_hook;
	planner_hook = pg_algorand_planner;
}
