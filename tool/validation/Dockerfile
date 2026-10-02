# Host-independent validation only. No browser/provider qualification.
FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS node
FROM dart:3.12.2-sdk@sha256:5ac89dbcae4327278b257920e2786df0f22c87adc630017266b67cfcceef8348
COPY --from=node /usr/local/bin/node /usr/local/bin/node
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /keypass
COPY . ./
RUN dart --suppress-analytics pub get --enforce-lockfile
RUN dart --suppress-analytics analyze --fatal-infos
RUN dart --suppress-analytics test -r expanded
RUN node --test test/browser/ceremony.test.mjs test/browser/failure.test.mjs test/browser/gesture.test.mjs test/browser/deadline.test.mjs
RUN mkdir -p build && dart --suppress-analytics compile exe tool/browser_probe.dart -o build/keypass-browser-probe
CMD ["build/keypass-browser-probe", "--help"]
