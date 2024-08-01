FROM citusdata/citus:latest

COPY * /build
RUN /build/build.sh
