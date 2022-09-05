#!/bin/bash
plgo
cd build
/bin/mkdir -p '/usr/share/postgresql/14/extension'
/bin/mkdir -p '/usr/lib/postgresql/14/lib'
/usr/bin/install -c -m 644 ./pg_algorand.control '/usr/share/postgresql/14/extension/'
/usr/bin/install -c -m 644 ./pg_algorand--0.1.sql  '/usr/share/postgresql/14/extension/'
/usr/bin/install -c -m 755  pg_algorand.so '/usr/lib/postgresql/14/lib/'
