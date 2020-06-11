#!/bin/bash

set -e
set -x

declare -r muser_dir="/var/run/muser"

declare -r spdk_sock="/var/tmp/spdk.sock"

declare -r muser_shm_dir="/dev/shm/muser"

rm -rf ${muser_dir} ${muser_shm_dir}
mkdir -p ${muser_shm_dir}

# FIXME permissions and context
mkdir --context=system_u:object_r:tmp_t:s0 -p -m 777 ${muser_dir}/{iommu_group,domain}

# FIXME permissions
chmod 777 ${muser_shm_dir}
chmod 777 ${muser_dir}

rm -f ${spdk_sock}
LD_LIBRARY_PATH=/opt/libiscsi-1.19.0/lib nvmf_tgt -L nvme -L nvmf -L nvmf_muser &
while [ ! -S ${spdk_sock} ]; do
	sleep 1
done

# FIXME permissions
chmod 777 ${spdk_sock}
chcon -t svirt_tmp_t ${spdk_sock}

/usr/share/spdk/scripts/rpc.py nvmf_create_transport -t MUSER
wait
