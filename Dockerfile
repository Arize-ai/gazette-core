################################################################################
# Gazette broker image (SaaS / Ubuntu).

FROM ubuntu:24.04 AS broker

ARG TARGETARCH

RUN apt-get update -y \
 && apt-get upgrade -y \
 && apt-get install --no-install-recommends -y \
      ca-certificates \
      curl \
 && rm -rf /var/lib/apt/lists/*

COPY ${TARGETARCH}/gazette ${TARGETARCH}/gazctl /usr/local/bin/

# Run as non-privileged "gazette" user.
RUN useradd gazette --create-home --shell /usr/sbin/nologin
USER gazette
WORKDIR /home/gazette

################################################################################
# Gazette broker image (on-prem / Chainguard).

FROM cgr.dev/arize.com/custom-gazette-base:latest AS broker-onprem

ARG TARGETARCH

COPY ${TARGETARCH}/gazette ${TARGETARCH}/gazctl /usr/local/bin/

# Run as non-privileged "gazette" user.
RUN adduser -D -h /home/gazette -s /sbin/nologin gazette
USER gazette
WORKDIR /home/gazette
