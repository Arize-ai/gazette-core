################################################################################
# Gazette broker image.

FROM cgr.dev/arize.com/custom-gazette-base:latest AS broker

ARG TARGETARCH

COPY ${TARGETARCH}/gazette ${TARGETARCH}/gazctl /usr/local/bin/

# Run as non-privileged "gazette" user.
RUN adduser -D -h /home/gazette -s /sbin/nologin gazette
USER gazette
WORKDIR /home/gazette
