MODULE_big = pg_algorand
OBJS = sha512_256.o algoaddr.o nfd_lsig.o pg_algorand.o
override with_llvm = no
PG_CFLAGS = -Wno-declaration-after-statement

#-march=native -O3 -ffast-math -funroll-loops

EXTENSION = pg_algorand
DATA = pg_algorand--2.0.sql pg_algorand--1.0--2.0.sql pg_algorand--1.0.sql pg_algorand--0.2--1.0.sql
PGFILEDESC = "Algorand extension for postgresql"

REGRESS = pg_algorand

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
