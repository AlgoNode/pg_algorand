MODULE_big = pg_algorand
OBJS = sha512_256.o algoaddr.o nfd_lsig.o note_prefix.o ineq_propagation.o pg_algorand.o
override with_llvm = no
PG_CFLAGS = -Wno-declaration-after-statement

#-march=native -O3 -ffast-math -funroll-loops

EXTENSION = pg_algorand
DATA = pg_algorand--2.2.sql pg_algorand--2.1--2.2.sql pg_algorand--2.1.sql pg_algorand--2.0--2.1.sql pg_algorand--2.0.sql pg_algorand--1.0--2.0.sql pg_algorand--1.0.sql pg_algorand--0.2--1.0.sql
PGFILEDESC = "Algorand extension for postgresql"

REGRESS = pg_algorand note_prefix ineq_propagation

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
