# Built by the SCM "make srpm" method using .copr/Makefile.
# Version 0 is a snapshot baseline until the project has a release version.
Name:           xtun
Version:        0
Release:        0.%{?snapshot:%{snapshot}}%{!?snapshot:1}%{?dist}
Summary:        Experimental encrypted IPv4 tunnel with client and server modes

License:        BSD-2-Clause AND Apache-2.0
URL:            https://github.com/1dao/xtun
Source0:        xtun-%{version}.tar.gz
Source1:        https://raw.githubusercontent.com/Mbed-TLS/mbedtls/mbedtls-3.6.5/LICENSE

ExclusiveArch:  x86_64
BuildRequires:  gcc
BuildRequires:  make
Provides:       bundled(mbedtls) = 3.6.5

%description
XTun is an experimental encrypted IPv4 tunnel using a custom protocol over
DTLS 1.2 with pre-shared key authentication. One executable provides both
client and server modes using Linux TUN. Root privileges are required to
create tunnel interfaces and configure routes.

%prep
%setup -q
cp %{SOURCE1} LICENSE-mbedtls
cp core/LICENSE LICENSE-core
test -f LICENSE

%build
# Command-line overrides also retain the dependency-generation flags used by
# the project's Makefile. Build bundled TLS without network access.
make %{?_smp_mflags} CC="%{__cc}" \
    CFLAGS="%{optflags} -std=gnu11 -Wall -Wextra -MMD -MP" \
    LDFLAGS="%{?build_ldflags}"

%check
make %{?_smp_mflags} test CC="%{__cc}" \
    CFLAGS="%{optflags} -std=gnu11 -Wall -Wextra -MMD -MP" \
    LDFLAGS="%{?build_ldflags}"

%install
install -Dpm0755 bin/xtun %{buildroot}%{_bindir}/xtun
# Examples deliberately contain no PSK. Runtime configuration is still read
# from the working directory, not from /etc/xtun.

%files
%license LICENSE LICENSE-core LICENSE-mbedtls
%doc README.md examples/client.cfg examples/client-tagged.cfg examples/server.cfg
%{_bindir}/xtun

%changelog
