#!/usr/bin/env bash

set -x

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=64
MALLOC_BLOCK_SIZE=512
NUM_DEVICES=2

rpc_py="$rootdir/scripts/rpc.py"

export TEST_TRANSPORT=VFIOUSER

rm -rf /var/run/muser
rm -rf /dev/shm/muser

# Start the target
("${NVMF_APP[@]}" -m 0x1 -L vfio_user -L nvmf_vfio -L nvmf_vfio |& tee spdk.log) &
nvmfpid=$!
echo "Process pid: $nvmfpid"

#trap 'killprocess $nvmfpid; exit 1' SIGINT SIGTERM EXIT
waitforlisten $nvmfpid

sleep 1

$rpc_py nvmf_create_transport -t VFIOUSER

mkdir -p /var/run/muser
mkdir -p /var/run/muser/iommu_group

for i in $(seq 1 $NUM_DEVICES); do
	mkdir -p /var/run/muser/domain/muser$i/$i
	mkdir -p /dev/shm/muser/muser$i

	$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc$i
	$rpc_py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode$i -a -s SPDK$i
	$rpc_py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode$i Malloc$i
	$rpc_py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode$i -t VFIOUSER -a "/var/run/muser/domain/muser$i/$i" -s 0

	ln -s /var/run/muser/domain/muser$i/$i /var/run/muser/domain/muser$i/$i/iommu_group
	ln -s /var/run/muser/domain/muser$i/$i /var/run/muser/iommu_group/$i
	ln -s /var/run/muser/domain/muser$i/$i/bar0 /dev/shm/muser/muser$i/bar0
done

for i in $(seq 1 $NUM_DEVICES); do
	$SPDK_EXAMPLE_DIR/identify -r "trtype:VFIOUSER traddr:/var/run/muser/domain/muser$i/$i" -g -L nvme -L nvme_vfio -L vfio_pci
	sleep 1
	$SPDK_EXAMPLE_DIR/perf -r "trtype:VFIOUSER traddr:/var/run/muser/domain/muser$i/$i" -s 256 -g -q 128 -o 4096 -w read -t 5 -c 0x2
	sleep 1
	$SPDK_EXAMPLE_DIR/perf -r "trtype:VFIOUSER traddr:/var/run/muser/domain/muser$i/$i" -s 256 -g -q 128 -o 4096 -w write -t 5 -c 0x2
	sleep 1
	$SPDK_EXAMPLE_DIR/reconnect -r "trtype:VFIOUSER traddr:/var/run/muser/domain/muser$i/$i" -g -q 32 -o 4096 -w randrw -M 50 -t 5 -c 0xE
	sleep 1
done

killprocess $nvmfpid

rm -rf /var/run/muser
rm -rf /dev/shm/muser

trap - SIGINT SIGTERM EXIT
