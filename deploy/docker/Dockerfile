# Packs the binary built by goreleaser (dist/dotvpn-core_linux_<arch>), so the
# image holds exactly the signed release artifact. Build from the repo root:
#   docker buildx build -f deploy/docker/Dockerfile --platform linux/amd64,linux/arm64 .
# The base is pinned by digest; bump it deliberately, never use a floating tag.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
COPY dist/dotvpn-core_linux_${TARGETARCH} /usr/local/bin/dotvpn-core

# Pre-own the mount point so a fresh named volume is writable by nonroot (65532).
COPY --chown=65532:65532 deploy/docker/data /data

# Config and keys live in the volume; nothing is baked in.
VOLUME /data
EXPOSE 443/tcp 443/udp
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/dotvpn-core", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/dotvpn-core"]
CMD ["version"]
