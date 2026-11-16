# Copr SCM: select "make srpm" and Spec File "xtun.spec".
# Archive tracked files only, and resolve core at the superproject's pinned
# gitlink. Windows-only submodules and personal configuration are excluded.
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
spec ?= $(ROOT)/xtun.spec

.PHONY: srpm
srpm:
	set -eu; \
	command -v git >/dev/null && command -v rpmbuild >/dev/null && command -v curl >/dev/null; \
	test -n "$(outdir)"; \
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
	snapshot=$$(git -C "$(ROOT)" show -s --format=%cd --date=format:%Y%m%d%H%M%S HEAD).git$$(git -C "$(ROOT)" rev-parse --short=12 HEAD); \
	printf '%%global snapshot %s\n' "$$snapshot" > "$$work/rpm/SPECS/xtun.spec"; \
	cat "$(spec)" >> "$$work/rpm/SPECS/xtun.spec"; \
	rpmbuild -bs --define "_topdir $$work/rpm" --define "_srcrpmdir $(abspath $(outdir))" "$$work/rpm/SPECS/xtun.spec"
