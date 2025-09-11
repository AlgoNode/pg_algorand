MODULE_big = pg_algorand
OBJS = sha512_256.o algoaddr.o pg_algorand.o functions.a
override with_llvm = no
EXTRA_CLEAN = sha512_256.o algoaddr.o pg_algorand.o pg_algorand.so functions.a functions.h
PG_CFLAGS = -Wno-declaration-after-statement 

#-march=native -O3 -ffast-math -funroll-loops

EXTENSION = pg_algorand
DATA = pg_algorand--1.0.sql
PGFILEDESC = "Algorand extension for postgresql"

REGRESS = pg_algorand

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

.DEFAULT_GOAL := our-default

our-default: pre-step all

pre-step:
	@echo "Building GO functions..."
	CGO_ENABLED=1 go build -buildmode=c-archive functions.go

.PHONY: our-default pre-step