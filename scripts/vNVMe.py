#!/usr/bin/python

import os
import subprocess
import fcntl
import errno
import shutil
import argparse
import re
import signal

class NVMeNamespace(object):

  def __init__(self, qdev_id, iqn, portal, lun):
    self.qdev_id = qdev_id
    self.iqn = iqn
    self.portal = portal
    self.lun = lun
    self.bdev = None

  def __str__(self):
    return "qdev=%s IQN=%s portal=%s LUN=%s bdev=%s" % \
      (self.qdev_id, self.iqn, self.portal, self.lun, self.bdev)



class vNVMeController(object):


  _RPC = "/usr/share/spdk/scripts/rpc.py"
  _MUSER_DIR = "/var/run/muser"

  # TODO can't use /dev/vfio because cgroups don't allow access to this file
  # TODO MUSER dirs are duplicated in libvfio, they should be defined in a
  # single place 
  _IOMMU_DIR = "%s/iommu_group" % _MUSER_DIR
  _DOMAIN_DIR = "%s/domain" % _MUSER_DIR

  @classmethod
  def makedirs(cls):
    for d in [cls._MUSER_DIR, cls._IOMMU_DIR, cls._DOMAIN_DIR]:
      try:
        os.mkdir(d)
      except OSError, e:
        if e.errno != errno.EEXIST:
          raise
    

  @classmethod
  def _spdk_rpc(cls, cmd, check=True):
    rpc = [cls._RPC] + cmd
    if check:
      subprocess.check_call(rpc, stdout=None, stderr=None)
    else:
      return subprocess.Popen(rpc)


  @classmethod
  def _spdk_nvmf_subsystem_create(cls, nqn):
    cls._spdk_rpc(["nvmf_subsystem_create", "-a", nqn])


  @classmethod
  def _spdk_bdev_iscsi_create(cls, ns):
    cls._spdk_rpc(["bdev_iscsi_create", "-b", ns.bdev, "-i", ns.iqn, "--url", \
      "iscsi://%s/%s/%s" % (ns.portal, ns.iqn, ns.lun)])


  @classmethod
  def _spdk_nvmf_subsystem_add_ns(cls, nsid, nqn, bdev):
    cls._spdk_rpc(["nvmf_subsystem_add_ns", "-n", str(nsid), nqn, bdev])


  @classmethod
  def _spdk_nvmf_subsystem_add_listener(cls, muser_dir, nqn):
    return cls._spdk_rpc(["nvmf_subsystem_add_listener", "-t", \
      "MUSER", "-a", muser_dir, "-s", "0", nqn], False)


  @classmethod
  def _spdk_delete_nvmf_subsystem(cls, nqn):
    cls._spdk_rpc(["delete_nvmf_subsystem", nqn])


  @classmethod
  def _spdk_bdev_iscsi_delete(cls, bdev):
    cls._spdk_rpc(["bdev_iscsi_delete", bdev])


 
  # TODO when multiple NVMe controllers are used we should allocate all IOMMU
  # groups in one go
  # TODO break this function down into smaller functions
  @classmethod 
  def _alloc_iommu_group(cls):
    iommu_groups = []
    for dentry in os.listdir(cls._IOMMU_DIR):
      try:
        iommu_groups.append(int(os.path.basename(dentry)))
      except ValueError:
        pass
    iommu_groups = sorted(iommu_groups)
    if not len(iommu_groups) or iommu_groups[0] > 0:
      return 0
    prev_iommu_group = iommu_groups[0]
    iommu_group = None
    for cur_iommu_group in iommu_groups[1:]:
      if cur_iommu_group > prev_iommu_group + 1:
        return prev_iommu_group + 1
      prev_iommu_group = cur_iommu_group
    return iommu_groups[-1] + 1
 

  @classmethod 
  def _domain_path(cls, uuid, iommu_group):
    return "%s/%s/%s" % (cls._DOMAIN_DIR, uuid, iommu_group)


  @classmethod 
  def _iommu_path(cls, iommu_group):
    return "%s/%d" % (cls._IOMMU_DIR, iommu_group)


  # TODO break this function down into smaller functions
  @classmethod  
  def _get_iommu_group(cls, uuid):
    fd = os.open(cls._IOMMU_DIR, os.O_RDONLY)
    try:
      while True:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
          iommu_group = cls._alloc_iommu_group()
          try:
            os.symlink(cls._domain_path(uuid, iommu_group), \
              cls._iommu_path(iommu_group))
            return iommu_group
          except OSError, e:
            if e.errno != errno.EEXIST:
              raise
        finally:
          fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
      os.close(fd)


  def __init__(self, uuid):
    # TODO make all these members private
    self.uuid = uuid
    self.namespaces = []


  def setup(self):
    mask = os.umask(0000)
    self.iommu_group = self._get_iommu_group(self.uuid)
    self.muser_parent_dir = "%s/%s" % (self._DOMAIN_DIR, self.uuid)
    self.muser_dir = "%s/%d" % (self.muser_parent_dir, self.iommu_group)
    self.shm_parent_dir = "/dev/shm/muser/%s" % self.uuid
    self.shm_dir = "%s/%d" % (self.shm_parent_dir, self.iommu_group)
    os.makedirs(self.muser_dir, 0777)
    os.symlink(self.muser_dir, "%s/iommu_group" % self.muser_dir)
    os.makedirs(self.shm_dir, 0777)
    os.symlink("%s/bar0" % self.shm_dir, "%s/bar0" % self.muser_dir)
    os.umask(mask)

    self.nqn = "nqn.2019-07.io.spdk.muser:%s" % self.muser_dir
    self._spdk_nvmf_subsystem_create(self.nqn)
    i = 1
    for ns in self.namespaces:
      ns.bdev = "%s_%s" % (self.uuid, ns.qdev_id) # FIXME should be done in NVMeNamespace ctor
      self._spdk_bdev_iscsi_create(ns)
      self._spdk_nvmf_subsystem_add_ns(i, self.nqn, ns.bdev)
      i += 1
    p = self._spdk_nvmf_subsystem_add_listener(self.muser_dir, self.nqn)

    p.poll()
    assert p.returncode == None
    return self._to_qdev()


  def _to_qdev(self):
    return "vfio-pci,sysfsdev=%s" % self._domain_path(self.uuid, self.iommu_group)


  def tear_down(self):
    self._spdk_delete_nvmf_subsystem(self.nqn)
    for ns in self.namespaces:
      self._spdk_bdev_iscsi_delete(ns.bdev)
    os.unlink(self._iommu_path(self.iommu_group))
    shutil.rmtree(self.shm_parent_dir)
    shutil.rmtree(self.muser_parent_dir)


def main():

  def signal_handler(sig, frame):
     pass

  signal.signal(signal.SIGINT, signal_handler)

  parser = argparse.ArgumentParser()
  parser.add_argument("uuid", type=str, help="guest UUID")
  parser.add_argument("namespaces", nargs="+", \
    help="iSCSI devices in the format iscsi://portal/iqn/lun")
  args = parser.parse_args()

  vNVMeController.makedirs()

  i = 0
  ctrlr = vNVMeController(args.uuid)
  for ns in args.namespaces:
    mo = re.match("iscsi://(.*)/(.*)/(.*)", ns)
    if not mo:
      raise Exception("bad namespace %s" % ns)
    ctrlr.namespaces += [NVMeNamespace(i, mo.group(2), mo.group(1), mo.group(3))]
    i += 1

  print ctrlr.setup()
  signal.pause()
  ctrlr.tear_down()


if __name__ == "__main__":
  main()
