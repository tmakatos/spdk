#!/bin/bash

set -e
set -x

echo "waiting for hugepages to initialize"
while (( ! ($(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) > 0))); do sleep 1; done

rm -rf ${muser_dir} ${muser_shm_dir}
mkdir -p ${muser_shm_dir}

# FIXME permissions and context
mkdir --context=system_u:object_r:tmp_t:s0 -p -m 777 ${muser_dir}/{iommu_group,domain}

# FIXME permissions
chmod 777 ${muser_shm_dir}
chmod 777 ${muser_dir}

rm -f ${spdk_sock}
if ${debug}; then
	log_args="-L nvme -L nvmf -L nvmf_muser"
else
	log_args="--silence-noticelog"
fi
LD_LIBRARY_PATH=${libiscsi} nvmf_tgt ${log_args} &
while [ ! -S ${spdk_sock} ]; do
	sleep 1
done

# FIXME permissions
chmod 777 ${spdk_sock}
chcon -t svirt_tmp_t ${spdk_sock}

/usr/share/spdk/scripts/rpc.py nvmf_create_transport -t MUSER
wait
