#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=512
MALLOC_BLOCK_SIZE=512

rpc_py="$rootdir/scripts/rpc.py"

export TEST_TRANSPORT=vfio-user

rm -rf /var/run/muser
rm -rf /dev/shm/muser

mkdir -p /var/run/muser
mkdir -p /var/run/muser/iommu_group
mkdir -p /var/run/muser/domain/muser0/8
mkdir -p /dev/shm/muser/muser0

# Start the target
"${NVMF_APP[@]}" -m 0x1 -L nvme -L nvmf -L nvmf_vfio &
nvmfpid=$!
echo "Process pid: $nvmfpid"

waitforlisten $nvmfpid

sleep 1

$rpc_py nvmf_create_transport -t vfio-user

$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode0 -a -s SPDK0
$rpc_py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode0 Malloc0
$rpc_py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode0 -t vfio-user -a "/var/run/muser/domain/muser0/8" -s 0

ln -s /var/run/muser/domain/muser0/8 /var/run/muser/domain/muser0/8/iommu_group
ln -s /var/run/muser/domain/muser0/8 /var/run/muser/iommu_group/8
ln -s /var/run/muser/domain/muser0/8/bar0 /dev/shm/muser/muser0/bar0

exit

$SPDK_EXAMPLE_DIR/identify -r 'trtype:CUSTOM traddr:/var/run/muser/domain/muser0/8' -d 128 -g -L nvme -L nvme_vfio -L vfio_pci
sleep 1
$SPDK_EXAMPLE_DIR/perf -r 'trtype:CUSTOM traddr:/var/run/muser/domain/muser0/8' -s 256 -g -q 128 -o 4096 -w read -t 10 -c 0x2
sleep 1
$SPDK_EXAMPLE_DIR/perf -r 'trtype:CUSTOM traddr:/var/run/muser/domain/muser0/8' -s 256 -g -q 128 -o 4096 -w write -t 10 -c 0x2

killprocess $nvmfpid

rm -rf /var/run/muser
rm -rf /dev/shm/muser

trap - SIGINT SIGTERM EXIT
