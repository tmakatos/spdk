# Build documentation package
%bcond_with doc
%bcond_with rdma

# no dashes
%global git_branch vfio_over_socket

Name: spdk
Version: %{git_branch}
Release: 0%{?dist}
Epoch: 0
URL: http://spdk.io

#Source: https://github.com/spdk/spdk/archive/%{commit}.tar.gz
# FIXME this file ends up in SOURCES, it's probably the AHV build system
# putting it there, figure out how to use it
Source: spdk-%{git_branch}-git%{githash}.tar.gz
Summary: Set of libraries and utilities for high performance user-mode storage

%define package_version %{epoch}:%{version}-%{release}

%define install_datadir %{buildroot}/%{_datadir}/%{name}
%define install_sbindir %{buildroot}/%{_sbindir}
%define install_docdir %{buildroot}/%{_docdir}/%{name}

%define libiscsi_tmp_inst /tmp/libiscsi-1.19.0
%define libiscsi_inst %{buildroot}/opt/libiscsi-1.19.0/lib

License: BSD

# Only x86_64 is supported
ExclusiveArch: x86_64

BuildRequires: gcc gcc-c++ make python3
BuildRequires: dpdk-devel, numactl-devel
#BuildRequires: libiscsi-devel
#BuildRequires: libaio-devel, openssl-devel, libuuid-devel
#BuildRequires: libibverbs-devel, librdmacm-devel
#BuildRequires: ncurses-devel
%if %{with doc}
BuildRequires: doxygen mscgen graphviz
%endif

BuildRequires: libvfio-user
BuildRequires: autoconf automake libtool

# Install dependencies

# FIXME not required if using internal DPDK 
#Requires: dpdk >= 17.11

#Requires: numactl-libs, openssl-libs

# FIXME not required if not built with libiscsi
#Requires: libiscsi

#Requires: libaio, libuuid
# NVMe over Fabrics
#Requires: librdmacm, librdmacm
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
Requires: %{name}%{?_isa} = %{package_version} python3
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
(cd libiscsi && ./autogen.sh && ./configure --prefix=%{libiscsi_tmp_inst} && make && make install)

# flags for DPDK
export LDFLAGS="-L%{libiscsi_tmp_inst}/lib"
export CFLAGS="-I%{libiscsi_tmp_inst}/include/ -mno-bmi2" # FIXME should be ivybridge/core2
export CPPFLAGS="-I%{libiscsi_tmp_inst}/include/"
export CXXFLAGS="-I%{libiscsi_tmp_inst}/include/"

./configure --prefix=%{_usr} \
  --disable-tests \
  --disable-unit-tests \
  --disable-examples \
  --without-crypto \
  --without-fio \
  --without-vhost \
  --without-virtio \
  --with-vfio-user \
  --without-pmdk \
  --without-reduce \
  --without-rbd \
  --without-rdma \
  --without-fc \
  --with-shared \
  --with-iscsi-initiator \
  --without-vtune \
  --without-ocf \
  --without-isal \
  --without-uring \
  --without-fuse \
  --without-nvme-cuse \
  --without-raid5

make V=1 -j`nproc` all

%if %{with doc}
make -C doc
%endif

%install
%make_install -j`nproc` prefix=%{_usr} libdir=%{_libdir} datadir=%{_datadir}

# Install tools
mkdir -p %{install_datadir}
find scripts -type f -regextype egrep -regex '.*(spdkcli|rpc).*[.]py' \
	-exec cp --parents -t %{install_datadir} {} ";"
install -m 755 scripts/vNVMe.py %{install_datadir}/scripts

# env is banned - replace '/usr/bin/env anything' with '/usr/bin/anything'
find %{install_datadir}/scripts -type f -regextype egrep -regex '.*([.]py|[.]sh)' \
	-exec sed -i -E '1s@#!/usr/bin/env (.*)@#!/usr/bin/\1@' {} +

# symlinks to tools
mkdir -p %{install_sbindir}
ln -sf -r %{install_datadir}/scripts/rpc.py %{install_sbindir}/%{name}-rpc
ln -sf -r %{install_datadir}/scripts/spdkcli.py %{install_sbindir}/%{name}-cli

%if %{with doc}
# Install doc
mkdir -p %{install_docdir}
mv doc/output/html/ %{install_docdir}
%endif

cp -r pkg/systemd/* %{buildroot}/


mkdir -p %{libiscsi_inst}
cp %{libiscsi_tmp_inst}/lib/libiscsi.so* %{libiscsi_inst}/


%post
/sbin/ldconfig
%systemd_post nvmf_tgt.service

%preun
%systemd_preun nvmf_tgt.service

%postun
/sbin/ldconfig
%systemd_postun_with_restart nvmf_tgt.service


%files
%{_bindir}/spdk_*
%{_libdir}/*.so.*
/opt/libiscsi-1.19.0/lib/*.so*

%{_bindir}/nvmf_tgt
/etc/systemd/system/nvmf_tgt.service
/etc/systemd/nvmf_tgt.conf
/usr/local/bin/nvmf_tgt.sh


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
