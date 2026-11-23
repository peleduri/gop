# Release image for gop. goreleaser (dockers_v2 in .goreleaser.yaml) builds the
# binaries first and puts them in the build context as <os>/<arch>/gop, so this
# file only copies one in: there is no compiler, shell or package manager in
# the image. The base is pinned by digest; Dependabot proposes digest updates.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/gop /gop
USER 65532:65532
ENTRYPOINT ["/gop"]
