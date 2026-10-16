# Образ для тестов zig/ и thor/ (tests/zig/run.sh, tests/thor/run.sh): Void с заголовками
# для сборки xbps, gcc для эталонов на C и Zig (архив проверен tests/docker/build.sh).
FROM ghcr.io/void-linux/void-glibc-full:latest
RUN xbps-install -Syu xbps && xbps-install -Syu && xbps-install -Sy openssl-devel libarchive-devel \
	zlib-devel pkgconf make xz patch libcap-progs gcc libxcrypt-devel python3 zstd lz4 bash openssl
ARG ZIG_TARBALL
COPY ${ZIG_TARBALL} /tmp/
RUN mkdir -p /opt && tar -xJf /tmp/${ZIG_TARBALL} -C /opt && rm /tmp/${ZIG_TARBALL} \
	&& ln -s /opt/${ZIG_TARBALL%.tar.xz}/zig /usr/local/bin/zig
ENV ZIG=/usr/local/bin/zig
