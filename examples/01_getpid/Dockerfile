FROM ctfhacker/snapchange_base_target as target
COPY harness/ /opt/
RUN cd /opt/ && ls && make
RUN apk add --no-cache --initramfs-diskless-boot python3 gdb curl tar build-base perf musl-dbg

FROM ctfhacker/snapchange_snapshot
COPY --from=target / "$SNAPSHOT_INPUT"

ENV SNAPSHOT_ENTRYPOINT=/opt/example1
