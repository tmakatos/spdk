#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
source $rootdir/scripts/common.sh
source $rootdir/test/common/autotest_common.sh

NVME_CMD=/usr/local/src/nvme-cli/nvme
rpc_py=$rootdir/scripts/rpc.py

$rootdir/app/spdk_tgt/spdk_tgt -m 0x3 &
spdk_tgt_pid=$!
trap 'kill -9 ${spdk_tgt_pid}; exit 1' SIGINT SIGTERM EXIT

waitforlisten $spdk_tgt_pid

bdf=$(iter_pci_class_code 01 08 02 | head -1)

$rpc_py bdev_nvme_attach_controller -b Nvme0 -t PCIe -a ${bdf}
$rpc_py bdev_nvme_cuse_register -n Nvme0

sleep 5

if [ ! -c /dev/spdk/nvme0 ]; then
	exit 1
fi

$rpc_py bdev_get_bdevs
$rpc_py bdev_nvme_get_controllers

for ns in /dev/spdk/nvme?n?; do
	${NVME_CMD} get-ns-id $ns
	${NVME_CMD} id-ns $ns

	# list-ns: INVALID FIELD (00/02) sqid:0 cid:95 cdw0:0 sqhd:0013 p:1 m:0 dnr:1
	${NVME_CMD} list-ns $ns || true
done

for ctrlr in /dev/spdk/nvme?; do
	${NVME_CMD} id-ctrl $ctrlr

	# list-ctrl: INVALID FIELD (00/02) sqid:0 cid:95 cdw0:0 sqhd:0011 p:1 m:0 dnr:1
	${NVME_CMD} list-ctrl $ctrlr || true
	${NVME_CMD} fw-log $ctrlr
	${NVME_CMD} smart-log $ctrlr
	${NVME_CMD} error-log $ctrlr

	# get-feature: INVALID FIELD (00/02) sqid:0 cid:95 cdw0:0 sqhd:0018 p:1 m:0 dnr:1
	${NVME_CMD} get-feature $ctrlr -f 1 -s 1 -l 100 || true
	${NVME_CMD} get-log $ctrlr -i 1 -l 100
	${NVME_CMD} reset $ctrlr
done

if [ ! -c /dev/spdk/nvme0 ]; then
	exit 1
fi

$rpc_py bdev_nvme_cuse_unregister -n Nvme0
sleep 1
if [ -c /dev/spdk/nvme0 ]; then
	exit 1
fi

$rpc_py bdev_nvme_cuse_register -n Nvme0
sleep 1

if [ ! -c /dev/spdk/nvme0 ]; then
	exit 1
fi

$rpc_py bdev_nvme_detach_controller Nvme0
sleep 1
if [ -c /dev/spdk/nvme0 ]; then
	exit 1
fi

trap - SIGINT SIGTERM EXIT
killprocess $spdk_tgt_pid
