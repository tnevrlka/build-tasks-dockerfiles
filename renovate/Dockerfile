ARG version=37.74.1
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:c77792b8084ce5946c68f39024fa460ef7769c0eef3fce995e70299e21a7e166

LABEL name="renovate"
LABEL org.opencontainers.image.source="https://github.com/renovatebot/renovate" \
  org.opencontainers.image.url="https://renovatebot.com"

RUN microdnf -y install nodejs npm docker shadow-utils git python make g++ && \
    groupadd -r renovate -g 1000 && \
    useradd -u 1000 -r -g root -G renovate -m -d /home/renovate -s /sbin/nologin -c "Renovate user" renovate && \
    chmod 0770 /home/renovate

ENV PATH="$PATH:/home/renovate/node_modules/.bin"
WORKDIR /home/renovate
USER 1000
RUN npm install renovate@$RENOVATE_VERSION re2

ENV RENOVATE_X_IGNORE_NODE_WARN=true

ENTRYPOINT ["renovate"]

RUN set -ex; \
  renovate --version; \
  renovate-config-validator; \
  node -e "new require('re2')('.*').exec('test')"; \
  true

LABEL org.opencontainers.image.version="${RENOVATE_VERSION}"
