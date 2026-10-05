FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS node
FROM dart:3.12.2-sdk@sha256:5ac89dbcae4327278b257920e2786df0f22c87adc630017266b67cfcceef8348
COPY --from=node /usr/local/bin/node /usr/local/bin/node
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libudev-dev libcbor-dev zlib1g-dev curl ca-certificates python3 patchelf \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location https://github.com/Yubico/libfido2/archive/refs/tags/1.17.0.tar.gz -o /tmp/fido.tar.gz \
    && echo 'ace062d14a482ff9325410ff63d06c8b5fe87e79ebc18dda07add2bc0188c77f  /tmp/fido.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/fido.tar.gz -C /tmp \
    && cmake -S /tmp/libfido2-1.17.0 -B /tmp/fido-build -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_MANPAGES=OFF \
    && cmake --build /tmp/fido-build -j 4 && cmake --install /tmp/fido-build \
    && ldconfig && rm -rf /tmp/fido.tar.gz /tmp/fido-build /tmp/libfido2-1.17.0
WORKDIR /keypass
COPY . ./
RUN dart --suppress-analytics pub get --enforce-lockfile
RUN cmake -S native/hardware -B build/hardware -DCMAKE_BUILD_TYPE=Debug \
    && cmake --build build/hardware -j4 && ctest --test-dir build/hardware --output-on-failure
RUN dart --suppress-analytics analyze --fatal-infos \
    && dart --suppress-analytics test --reporter expanded \
    && python3 tool/test_build_hooks.py \
    && dart --suppress-analytics compile exe -Dkeypass.hardware.manual_bundle=true tool/hardware_demo.dart -o build/hardware/keypass-hardware-demo
RUN build/hardware/keypass-hardware-demo check 2> /tmp/check-error; \
    test $? -eq 1 && grep -Fx 'Operation stopped: deviceUnavailable.' /tmp/check-error
CMD ["build/hardware/keypass-hardware-demo"]
