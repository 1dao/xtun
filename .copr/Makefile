# Copr SCM: select "make srpm" and Spec File "xtun.spec".
# Archive tracked files only, and resolve core at the superproject's pinned
# gitlink. Windows-only submodules and personal configuration are excluded.
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
spec ?= $(ROOT)/xtun.spec

.PHONY: srpm
srpm:
	set -eu; \
	test -n "$(outdir)"; \
	missing=""; \
	for entry in git:git-core rpmbuild:rpm-build curl:curl-minimal tar:tar gzip:gzip; do \
		tool=$${entry%%:*}; package=$${entry#*:}; \
		if ! command -v "$$tool" >/dev/null 2>&1; then missing="$$missing $$package"; fi; \
	done; \
	if test -n "$$missing"; then \
		command -v dnf >/dev/null 2>&1 || { echo "Missing SRPM tools; install:$$missing" >&2; exit 1; }; \
		dnf -y install $$missing; \
	fi; \
	mkdir -p "$(outdir)"; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	git -C "$(ROOT)" submodule update --init -- core; \
	version=$$(awk '/^Version:/ {print $$2; exit}' "$(spec)"); \
	prefix="xtun-$$version"; \
	mkdir -p "$$work/tree/$$prefix" "$$work/rpm/SOURCES" "$$work/rpm/SPECS"; \
	git -C "$(ROOT)" archive HEAD Makefile src tests examples README.md LICENSE | tar -x -C "$$work/tree/$$prefix"; \
	mkdir -p "$$work/tree/$$prefix/core"; \
	git -C "$(ROOT)/core" archive HEAD LICENSE xargs.c xargs.h xudp.c xudp.h xpoll.c xpoll.h xhash.h xsock.c xsock.h xlog.c xlog.h xdaemon.c xdaemon.h xmacro.h 3rd/mbedtls3 | tar -x -C "$$work/tree/$$prefix/core"; \
	tar -czf "$$work/rpm/SOURCES/$$prefix.tar.gz" -C "$$work/tree" "$$prefix"; \
	curl --fail --location --retry 3 https://raw.githubusercontent.com/Mbed-TLS/mbedtls/mbedtls-3.6.5/LICENSE -o "$$work/rpm/SOURCES/LICENSE"; \
	cp "$(spec)" "$$work/rpm/SPECS/xtun.spec"; \
	rpmbuild -bs --define "_topdir $$work/rpm" --define "_srcrpmdir $(abspath $(outdir))" "$$work/rpm/SPECS/xtun.spec"
