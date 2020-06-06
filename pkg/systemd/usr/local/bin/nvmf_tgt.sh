#!/bin/bash

set -e
set -x

rm -rf /var/run/muser /dev/shm/muser
mkdir -p /dev/shm/muser
chmod 777 /dev/shm/muser
mkdir -p -m 777 /var/run/muser/{iommu_group,domain}
chmod 777 /var/run/muser
rm -f /var/tmp/spdk.sock
LD_LIBRARY_PATH=/opt/libiscsi-1.19.0/lib nvmf_tgt -L nvme -L nvmf -L nvmf_muser &
while [ ! -S /var/tmp/spdk.sock ]; do
	sleep 1
done
chmod 777 /var/tmp/spdk.sock
/usr/share/spdk/scripts/rpc.py nvmf_create_transport -t MUSER
wait
