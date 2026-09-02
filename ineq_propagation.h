#ifndef PG_ALGORAND_INEQ_PROPAGATION_H
#define PG_ALGORAND_INEQ_PROPAGATION_H

#include "nodes/parsenodes.h"

extern void ineq_propagation_init(void);
extern int	propagate_inequalities(Query *parse);

#endif
