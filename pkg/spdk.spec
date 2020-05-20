# Build documentation package
%bcond_with doc

%global commit b55b20430118c18def733be838f57c6304585c92

Name: spdk
Version: %{commit}
Release: 0%{?dist}
Epoch: 0
URL: http://spdk.io

Source: https://github.com/spdk/spdk/archive/%{commit}.tar.gz
Summary: Set of libraries and utilities for high performance user-mode storage

%define package_version %{epoch}:%{version}-%{release}

%define install_datadir %{buildroot}/%{_datadir}/%{name}
%define install_sbindir %{buildroot}/%{_sbindir}
%define install_docdir %{buildroot}/%{_docdir}/%{name}

License: BSD

# Only x86_64 is supported
ExclusiveArch: x86_64

BuildRequires: gcc gcc-c++ make
BuildRequires: dpdk-devel, numactl-devel
BuildRequires: libiscsi-devel, libaio-devel, openssl-devel, libuuid-devel
BuildRequires: libibverbs-devel, librdmacm-devel
%if %{with doc}
BuildRequires: doxygen mscgen graphviz
%endif
BuildRequires: muser

# Install dependencies

# FIXME not required if using internal DPDK 
Requires: dpdk >= 17.11

Requires: numactl-libs, openssl-libs

# FIXME not required if not built with libiscsi
#Requires: libiscsi

Requires: libaio, libuuid
# NVMe over Fabrics
Requires: librdmacm, librdmacm
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
The Storage Performance Development Kit provides a set of tools
and libraries for writing high performance, scalable, user-mode storage
applications.


%package devel
Summary: Storage Performance Development Kit development files
Requires: %{name}%{?_isa} = %{package_version}
Provides: %{name}-static%{?_isa} = %{package_version}

%description devel
This package contains the headers and other files needed for
developing applications with the Storage Performance Development Kit.


%package tools
Summary: Storage Performance Development Kit tools files
Requires: %{name}%{?_isa} = %{package_version} python3 python3-configshell python3-pexpect
BuildArch: noarch

%description tools
%{summary}


%if %{with doc}
%package doc
Summary: Storage Performance Development Kit documentation
BuildArch: noarch

%description doc
%{summary}
%endif


%prep
# add -q
%autosetup -n spdk-%{version}


%build
./configure --prefix=%{_usr} \
	--enable-debug \
	--disable-tests \
	--without-igb-uio-driver \
	--without-crypto \
	--without-fio \
	--without-vhost \
	--without-virtio \
	--without-reduce \
	--without-vpp \
	--without-rbd \
	--without-rdma \
	--without-fc \
	--with-shared \
	--without-iscsi-initiator \
	--without-vtune \
	--without-ocf \
	--without-isal \
	--without-uring \
	--without-fuse \
	--without-nvme-cuse

make -j`nproc` all

%if %{with doc}
make -C doc
%endif

%install
%make_install -j`nproc` prefix=%{_usr} libdir=%{_libdir} datadir=%{_datadir}

# Install tools
mkdir -p %{install_datadir}
find scripts -type f -regextype egrep -regex '.*(spdkcli|rpc).*[.]py' \
	-exec cp --parents -t %{install_datadir} {} ";"

# env is banned - replace '/usr/bin/env anything' with '/usr/bin/anything'
find %{install_datadir}/scripts -type f -regextype egrep -regex '.*([.]py|[.]sh)' \
	-exec sed -i -E '1s@#!/usr/bin/env (.*)@#!/usr/bin/\1@' {} +

# synlinks to tools
mkdir -p %{install_sbindir}
ln -sf -r %{install_datadir}/scripts/rpc.py %{install_sbindir}/%{name}-rpc
ln -sf -r %{install_datadir}/scripts/spdkcli.py %{install_sbindir}/%{name}-cli

%if %{with doc}
# Install doc
mkdir -p %{install_docdir}
mv doc/output/html/ %{install_docdir}
%endif


%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%files
%{_bindir}/spdk_*
%{_libdir}/*.so.*


%files devel
%{_includedir}/%{name}
%{_libdir}/*.a
%{_libdir}/*.so


%files tools
%{_datadir}/%{name}/scripts
%{_sbindir}/%{name}-rpc
%{_sbindir}/%{name}-cli

%if %{with doc}
%files doc
%{_docdir}/%{name}
%endif


%changelog
* Tue Sep 18 2018 Pawel Wodkowski <pawelx.wodkowski@intel.com> - 0:18.07-3
- Initial RPM release
