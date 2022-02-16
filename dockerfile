FROM citusdata/citus:latest

COPY build /build
COPY ext_install.sh /build
RUN /build/ext_install.sh
