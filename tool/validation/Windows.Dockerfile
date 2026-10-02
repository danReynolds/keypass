FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends g++-mingw-w64-x86-64-posix ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY native/windows/keypass.cpp /source/keypass.cpp
COPY build/native/windows-deps /source/deps
RUN x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -Werror -Wno-cast-function-type -DNOMINMAX -DWIN32_LEAN_AND_MEAN -isystem deps -shared keypass.cpp -o /keypass.dll -lcrypt32 -luser32 -static-libgcc -static-libstdc++
