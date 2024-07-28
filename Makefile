MODULE_big = pg_algorand
OBJS = pg_algorand.o functions.a
override with_llvm = no
EXTRA_CLEAN = pg_algorand.o pg_algorand.so functions.a functions.h
PG_CFLAGS = -Wno-declaration-after-statement

EXTENSION = pg_algorand
DATA = pg_algorand--1.0.sql
PGFILEDESC = "Algorand extension for postgresql"

REGRESS = pg_algorand

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
