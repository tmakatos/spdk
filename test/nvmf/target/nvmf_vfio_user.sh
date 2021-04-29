#!/usr/bin/env bash

set -x
set -e

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=512
MALLOC_BLOCK_SIZE=512

rpc_py="$rootdir/scripts/rpc.py"

export TEST_TRANSPORT=VFIOUSER

dir="/var/tmp"
rm -f ${dir}/{cntrl,bar0}

rm -f /var/run/vfio-user.sock

# Start the target
("${NVMF_APP[@]}" -m 0x1 -L vfio_user -L nvmf_vfio -L nvmf_vfio |& tee spdk.log) &
nvmfpid=$!
echo "Process pid: $nvmfpid"

waitforlisten $nvmfpid

sleep 1

$rpc_py nvmf_create_transport -t VFIOUSER

$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode0 -a -s SPDK0
$rpc_py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode0 Malloc0
$rpc_py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode0 -t VFIOUSER -a ${dir} -s 0

ln -sf "${dir}/cntrl" "/var/run/vfio-user.sock"
chmod 777 ${dir}/{cntrl,bar0}

#ln -s /var/run/muser/domain/muser0/8/bar0 /dev/shm/muser/muser0/bar0
