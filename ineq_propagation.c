/*
 * ineq_propagation.c
 *
 * Propagate range conditions across join equalities before planning.
 *
 * PostgreSQL derives equalities through equivalence classes (a = b AND
 * a = 5 gives b = 5) but never inequalities.  For
 *
 *     FROM txn t JOIN block_header h ON t.round = h.round
 *     WHERE t.round >= $1
 *     ORDER BY t.round, t.intra LIMIT n
 *
 * nothing tells the planner that h.round >= $1.  A plan that drives the
 * join from block_header therefore scans that index from its first key and
 * probes txn for every round below $1, finding nothing.  As soon as the
 * per-round probe is costed accurately (a correct n_distinct on round) that
 * plan is the cheapest LIMIT plan on paper and by far the slowest one in
 * practice: tens of millions of empty probes instead of a few hundred rows.
 *
 * This module adds, for every conjunct of the form
 *
 *     v OP expr        or        expr OP v
 *
 * where v is a plain column reference, OP is a btree <, <=, >= or > and expr
 * contains no column of the same query level, the same condition on every
 * column w that is connected to v through btree equalities  v = w  of the
 * same type, collation and operator family.  Only conditions that hold for
 * every output row are used and produced: the WHERE clause and the ON
 * clauses of inner joins that are not below the nullable side of an outer
 * join.  The derived conditions are appended to the WHERE clause, so a
 * result row can never be lost or gained: every derived condition is implied
 * by conditions that already had to hold for that row.
 *
 * expr is copied, so it must be safe to evaluate twice: no volatile
 * functions, no set-returning functions, no aggregates or window functions.
 * An uncorrelated sub-select is allowed and becomes a second init plan.
 *
 * Disable at runtime with SET pg_algorand.propagate_inequalities = off.
 */
#include "postgres.h"

#include "access/cmptype.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "optimizer/clauses.h"
#include "optimizer/optimizer.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"

#include "ineq_propagation.h"

/* Safety valve against pathological queries; real queries derive 1 to 3. */
#define MAX_DERIVED_PER_LEVEL	32

static bool ineq_propagation_enabled = true;

typedef struct EqClause
{
	Var		   *a;
	Var		   *b;
	List	   *families;		/* opfamily OIDs in which the operator is = */
} EqClause;

typedef struct IneqClause
{
	OpExpr	   *op;
	int			varpos;			/* 0: v OP expr, 1: expr OP v */
	List	   *families;		/* opfamily OIDs in which the operator is a range op */
} IneqClause;

static bool
same_column(const Var *a, const Var *b)
{
	return a->varno == b->varno && a->varattno == b->varattno;
}

static bool
plain_column(Node *n, Var **v)
{
	if (n != NULL && IsA(n, Var))
	{
		Var		   *var = (Var *) n;

		if (var->varlevelsup == 0 && var->varattno > 0)
		{
			*v = var;
			return true;
		}
	}
	return false;
}

/*
 * Opfamilies in which opno is equality (want_eq) or a range operator.
 */
static List *
operator_families(Oid opno, bool want_eq)
{
	List	   *interps = get_op_index_interpretation(opno);
	List	   *result = NIL;
	ListCell   *lc;

	foreach(lc, interps)
	{
		OpIndexInterpretation *oi = (OpIndexInterpretation *) lfirst(lc);
		bool		match;

		if (want_eq)
			match = (oi->cmptype == COMPARE_EQ);
		else
			match = (oi->cmptype == COMPARE_LT || oi->cmptype == COMPARE_LE ||
					 oi->cmptype == COMPARE_GE || oi->cmptype == COMPARE_GT);
		if (match && !list_member_oid(result, oi->opfamily_id))
			result = lappend_oid(result, oi->opfamily_id);
	}
	list_free_deep(interps);
	return result;
}

/* Flatten a qual expression into its top-level conjuncts. */
static void
add_conjuncts(Node *qual, List **quals)
{
	if (qual == NULL)
		return;
	if (IsA(qual, BoolExpr) && ((BoolExpr *) qual)->boolop == AND_EXPR)
	{
		ListCell   *lc;

		foreach(lc, ((BoolExpr *) qual)->args)
			add_conjuncts((Node *) lfirst(lc), quals);
		return;
	}
	*quals = lappend(*quals, qual);
}

/*
 * Collect the conjuncts that hold for every row of the query level: the
 * WHERE clause and inner-join ON clauses, but nothing at or below the
 * nullable side of an outer join.
 */
static void
collect_inner_quals(Node *jtnode, bool inner, List **quals)
{
	if (jtnode == NULL)
		return;
	if (IsA(jtnode, FromExpr))
	{
		FromExpr   *f = (FromExpr *) jtnode;
		ListCell   *lc;

		foreach(lc, f->fromlist)
			collect_inner_quals((Node *) lfirst(lc), inner, quals);
		if (inner)
			add_conjuncts(f->quals, quals);
	}
	else if (IsA(jtnode, JoinExpr))
	{
		JoinExpr   *j = (JoinExpr *) jtnode;

		switch (j->jointype)
		{
			case JOIN_INNER:
				collect_inner_quals(j->larg, inner, quals);
				collect_inner_quals(j->rarg, inner, quals);
				if (inner)
					add_conjuncts(j->quals, quals);
				break;
			case JOIN_LEFT:
			case JOIN_SEMI:
			case JOIN_ANTI:
				collect_inner_quals(j->larg, inner, quals);
				collect_inner_quals(j->rarg, false, quals);
				break;
			case JOIN_RIGHT:
				collect_inner_quals(j->larg, false, quals);
				collect_inner_quals(j->rarg, inner, quals);
				break;
			default:
				collect_inner_quals(j->larg, false, quals);
				collect_inner_quals(j->rarg, false, quals);
				break;
		}
	}
	/* RangeTblRef: nothing to collect */
}

/* Is expr safe to duplicate and free of this level's columns? */
static bool
expr_is_propagable(Node *expr)
{
	return !contain_vars_of_level(expr, 0) &&
		!contain_volatile_functions(expr) &&
		!expression_returns_set(expr) &&
		!contain_agg_clause(expr) &&
		!contain_window_function(expr);
}

static bool
clause_present(Node *clause, List *quals, List *derived)
{
	ListCell   *lc;

	foreach(lc, quals)
		if (equal(clause, lfirst(lc)))
			return true;
	foreach(lc, derived)
		if (equal(clause, lfirst(lc)))
			return true;
	return false;
}

/*
 * Columns reachable from v through equalities that are = in opfamily
 * family.  Returns a list of Var nodes (excluding v itself).
 */
static List *
connected_columns(Var *v, List *eqs, Oid family)
{
	List	   *reached = list_make1(v);
	List	   *result = NIL;
	int			i;

	/* reached grows while we iterate; index-based loop is intended */
	for (i = 0; i < list_length(reached); i++)
	{
		Var		   *cur = (Var *) list_nth(reached, i);
		ListCell   *lc;

		foreach(lc, eqs)
		{
			EqClause   *eq = (EqClause *) lfirst(lc);
			Var		   *other = NULL;
			ListCell   *lr;
			bool		seen = false;

			if (!list_member_oid(eq->families, family))
				continue;
			if (same_column(eq->a, cur))
				other = eq->b;
			else if (same_column(eq->b, cur))
				other = eq->a;
			else
				continue;
			foreach(lr, reached)
			{
				if (same_column((Var *) lfirst(lr), other))
				{
					seen = true;
					break;
				}
			}
			if (!seen)
			{
				reached = lappend(reached, other);
				result = lappend(result, other);
			}
		}
	}
	list_free(reached);
	return result;
}

/* Process one query level.  Returns the number of conditions added. */
static int
propagate_level(Query *q)
{
	List	   *quals = NIL;
	List	   *eqs = NIL;
	List	   *ineqs = NIL;
	List	   *derived = NIL;
	ListCell   *lc;

	if (q->jointree == NULL || q->setOperations != NULL)
		return 0;
	if (list_length(q->rtable) < 2)
		return 0;

	collect_inner_quals((Node *) q->jointree, true, &quals);

	foreach(lc, quals)
	{
		Node	   *n = (Node *) lfirst(lc);
		OpExpr	   *op;
		Node	   *a0;
		Node	   *a1;
		Var		   *va = NULL;
		Var		   *vb = NULL;

		if (!IsA(n, OpExpr))
			continue;
		op = (OpExpr *) n;
		if (list_length(op->args) != 2)
			continue;
		a0 = (Node *) linitial(op->args);
		a1 = (Node *) lsecond(op->args);

		if (plain_column(a0, &va) && plain_column(a1, &vb))
		{
			List	   *fams;

			if (va->varno == vb->varno ||
				va->vartype != vb->vartype ||
				va->varcollid != vb->varcollid)
				continue;
			fams = operator_families(op->opno, true);
			if (fams != NIL)
			{
				EqClause   *eq = palloc(sizeof(EqClause));

				eq->a = va;
				eq->b = vb;
				eq->families = fams;
				eqs = lappend(eqs, eq);
			}
		}
		else if ((plain_column(a0, &va) && expr_is_propagable(a1)) ||
				 (plain_column(a1, &vb) && expr_is_propagable(a0)))
		{
			List	   *fams = operator_families(op->opno, false);

			if (fams != NIL)
			{
				IneqClause *iq = palloc(sizeof(IneqClause));

				iq->op = op;
				iq->varpos = (va != NULL) ? 0 : 1;
				iq->families = fams;
				ineqs = lappend(ineqs, iq);
			}
		}
	}

	if (eqs == NIL || ineqs == NIL)
		return 0;

	foreach(lc, ineqs)
	{
		IneqClause *iq = (IneqClause *) lfirst(lc);
		Var		   *v = (Var *) list_nth(iq->op->args, iq->varpos);
		ListCell   *lf;

		foreach(lf, iq->families)
		{
			List	   *others = connected_columns(v, eqs, lfirst_oid(lf));
			ListCell   *lo;

			foreach(lo, others)
			{
				Var		   *w = (Var *) lfirst(lo);
				OpExpr	   *d;

				if (list_length(derived) >= MAX_DERIVED_PER_LEVEL)
					break;
				d = copyObject(iq->op);
				if (iq->varpos == 0)
					linitial(d->args) = copyObject(w);
				else
					lsecond(d->args) = copyObject(w);
				d->location = -1;
				if (clause_present((Node *) d, quals, derived))
					continue;
				derived = lappend(derived, d);
			}
			list_free(others);
		}
	}

	foreach(lc, derived)
		q->jointree->quals = make_and_qual(q->jointree->quals,
										   (Node *) lfirst(lc));

	return list_length(derived);
}

static bool
propagate_walker(Node *node, int *count)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;

		if (q->commandType == CMD_SELECT || q->commandType == CMD_UPDATE ||
			q->commandType == CMD_DELETE || q->commandType == CMD_MERGE ||
			q->commandType == CMD_INSERT)
			*count += propagate_level(q);
		return query_tree_walker(q, propagate_walker, count, 0);
	}
	return expression_tree_walker(node, propagate_walker, count);
}

/*
 * Entry point for the planner hook.  Modifies parse (and its sub-queries) in
 * place; returns the number of conditions added.
 */
int
propagate_inequalities(Query *parse)
{
	int			count = 0;

	if (!ineq_propagation_enabled || parse->commandType == CMD_UTILITY)
		return 0;
	(void) propagate_walker((Node *) parse, &count);
	return count;
}

void
ineq_propagation_init(void)
{
	DefineCustomBoolVariable("pg_algorand.propagate_inequalities",
							 "Propagate range conditions across join equalities before planning.",
							 "When on, a condition  column OP value  (OP one of <, <=, >=, >) "
							 "is also applied to every column joined to it with = in the "
							 "WHERE clause or an inner join, so both sides of the join can "
							 "use the range.",
							 &ineq_propagation_enabled,
							 true,
							 PGC_USERSET,
							 0,
							 NULL, NULL, NULL);
}
