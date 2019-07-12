/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <muser/muser.h>

#include "spdk/barrier.h"
#include "spdk/stdinc.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvme_spec.h"
#include "spdk/nvmf.h"
#include "spdk/nvmf_spec.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "nvmf_internal.h"
#include "transport.h"

#include "spdk_internal/log.h"

#include "muser-nvme_pci.h"

#define MUSER_DEFAULT_MAX_QUEUE_DEPTH 128
#define MUSER_DEFAULT_AQ_DEPTH 32
#define MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR 64
#define MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE 0
#define MUSER_DEFAULT_MAX_IO_SIZE 131072
#define MUSER_DEFAULT_IO_UNIT_SIZE 131072
#define MUSER_DEFAULT_NUM_SHARED_BUFFERS 512 /* internal buf size */
#define MUSER_DEFAULT_BUFFER_CACHE_SIZE 0

#define NVME_REG_CFG_SIZE       0x1000
#define NVME_REG_BAR0_SIZE      0x4000

#define NVME_IRQ_INTX_NUM       1
#define NVME_IRQ_MSIX_NUM       32

/* TODO 36 comes from a real NVMe device, does it have to be 36? */
#define NVME_REG_OFFSET         (1UL << 36)

enum muser_nvmf_dir {
	MUSER_NVMF_INVALID,
	MUSER_NVMF_READ,
	MUSER_NVMF_WRITE
};

struct muser_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			*rsp;
	struct spdk_nvme_cmd			*cmd;

	TAILQ_ENTRY(muser_req)			link;
};

struct muser_nvmf_prop_req {
	enum muser_nvmf_dir			dir;
	sem_t					wait;
	char					*buf;
	size_t					count;
	loff_t					pos;
	ssize_t					ret;
};

struct muser_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_muser_poll_group	*group;
	struct muser_dev			*dev;
	struct muser_nvmf_prop_req		prop_req;
	struct muser_req			*reqs_internal;
	union nvmf_h2c_msg			*cmds_internal;
	union nvmf_c2h_msg			*rsps_internal;
	TAILQ_HEAD(, muser_req)			reqs;
	TAILQ_ENTRY(muser_qpair)		link;
};

struct muser_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	TAILQ_HEAD(, muser_qpair)		qps;
};

struct muser_dev {
	struct spdk_nvme_transport_id		trid;
	struct muser_qpair			admin_qp;
	char					uuid[37];
	pthread_t				lm_thr;
	lm_ctx_t				*lm_ctx;
	bool					setup;
	lm_pci_config_space_t			*pci_config_space;

	/* TODO group admin queues in a struct? */
	union spdk_nvme_aqa_register		aqa;
	uint64_t				asq;
	void					*asq_addr;
	uint64_t				acq;

	TAILQ_ENTRY(muser_dev)			link;
};

struct muser_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	TAILQ_HEAD(, muser_dev)			devs;
};

static int
muser_destroy(struct spdk_nvmf_transport *transport)
{
	struct muser_transport *muser_transport;

	muser_transport = (struct muser_transport *)transport;

	(void)pthread_mutex_destroy(&muser_transport->lock);

	free(muser_transport);

	return 0;
}

static struct spdk_nvmf_transport *
muser_create(struct spdk_nvmf_transport_opts *opts)
{
	struct muser_transport *muser_transport;
	int err;

	muser_transport = calloc(1, sizeof(*muser_transport));
	if (muser_transport == NULL) {
		SPDK_ERRLOG("Transport alloc fail: %m\n");
		return NULL;
	}

	err = pthread_mutex_init(&muser_transport->lock, NULL);
	if (err != 0) {
		SPDK_ERRLOG("Pthread initialisation failed (%d)\n", err);
		goto err;
	}

	TAILQ_INIT(&muser_transport->devs);

	return &muser_transport->transport;

err:
	free(muser_transport);

	return NULL;
}

#define MDEV_CREATE_PATH "/sys/class/muser/muser/mdev_supported_types/muser-1/create"

static void
mdev_remove(const char *uuid)
{ /* TODO: Implement me */ }

static int
mdev_create(const char *uuid)
{
	int fd;
	int err;

	fd = open(MDEV_CREATE_PATH, O_WRONLY);
	if (fd == -1) {
		SPDK_ERRLOG("Error opening '%s': %m\n", MDEV_CREATE_PATH);
		return -1;
	}

	err = write(fd, uuid, strlen(uuid));
	if (err != (int)strlen(uuid)) {
		SPDK_ERRLOG("Error creating device '%s': %m\n", uuid);
		err = -1;
	} else {
		err = 0;
	}

	(void)close(fd);

	sleep(1);

	/* TODO: Wait until dev appears on /dev/muser/<uuid> */

	return err;
}

static ssize_t
read_cap(struct muser_dev const * const dev, char * const buf,
         const size_t count, loff_t pos)
{
	/*
	 * FIXME need to validate count and pos
	 * FIXME is it OK to read it like that? Do we need to submit a request
	 * to the NVMf layer?
	 * TODO this line is far too long
	 */
	assert(dev);
	memcpy(buf, ((uint8_t*)&dev->admin_qp.qpair.ctrlr->vcprop.cap.raw) + pos - offsetof(struct spdk_nvme_registers, cap), count);
	return 0;
}

static bool
is_cap(const loff_t pos)
{
	const size_t off = offsetof(struct spdk_nvme_registers, cap);
	return (size_t)pos >= off && (size_t)pos < off + sizeof(uint64_t);
}

/*
 * FIXME read_bar0 and write_bar0 are very similar, merge
 */
static ssize_t
read_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_dev *muser_dev = pvt;
	int err;

	SPDK_NOTICELOG("dev: %p, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, count, pos);

	/*
	 * CAP is 8 bytes long however the driver reads it 4 bytes at a time.
	 * NVMf doesn't like this.
	 */
	if (is_cap(pos))
		return read_cap(muser_dev, buf, count, pos);

	muser_dev->admin_qp.prop_req.buf = buf;
	/* TODO: count must never be more than 8, otherwise we need to split it */
	muser_dev->admin_qp.prop_req.count = count;
	muser_dev->admin_qp.prop_req.pos = pos;
	spdk_wmb();
	muser_dev->admin_qp.prop_req.dir = MUSER_NVMF_READ;

	do {
		err = sem_wait(&muser_dev->admin_qp.prop_req.wait);
	} while (err != 0 && errno != EINTR);

	return muser_dev->admin_qp.prop_req.ret;
}

static ssize_t
aqa_write(union spdk_nvme_aqa_register * const to,
          union spdk_nvme_aqa_register const * const from)
{
	to->raw = from->raw;
	SPDK_NOTICELOG("write to AQA %x\n", to->raw);
	return 0;
}

static void
write_partial(uint8_t const * const buf, const loff_t pos, const size_t count,
              const size_t reg_off, uint64_t * const reg)
{
	memcpy(reg, buf + pos - reg_off, count);
}

static ssize_t
asq_or_acq_write(uint8_t const * const buf, const loff_t pos,
                 const size_t count, uint64_t * const reg, const size_t reg_off)
{
	/*
	 * The NVMe driver seems to write those only in 4 upper/lower bytes.
	 */
	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("bad write count %zu\n", count);
		return -EINVAL;
	}

	if ((size_t)pos != reg_off && (size_t)pos != reg_off + sizeof(uint32_t)) {
		SPDK_ERRLOG("bad write offset 0x%lx\n", pos);
		return -EINVAL;
	}

	write_partial(buf, pos, count, reg_off, reg);

	return 0;
}

static ssize_t
asq_write(uint64_t * const asq, uint8_t const * const buf,
          const loff_t pos, const size_t count)
{
	int ret = asq_or_acq_write(buf, pos, count, asq,
	                           offsetof(struct spdk_nvme_registers, asq));
	SPDK_NOTICELOG("ASQ=0x%lx\n", *asq);
	return ret;
}

static ssize_t
acq_write(uint64_t * const acq, uint8_t const * const buf,
          const loff_t pos, const size_t count)
{
	return asq_or_acq_write(buf, pos, count, acq,
	                        offsetof(struct spdk_nvme_registers, acq));
}

#define REGISTER_RANGE(name, size) \
	offsetof(struct spdk_nvme_registers, name) ... \
		offsetof(struct spdk_nvme_registers, name) + size - 1

#define ASQ \
	REGISTER_RANGE(asq, sizeof(uint64_t))

#define ACQ \
	REGISTER_RANGE(acq, sizeof(uint64_t))

#define ADMIN_QUEUES \
	offsetof(struct spdk_nvme_registers, aqa) ... \
		offsetof(struct spdk_nvme_registers, acq) + sizeof(uint64_t) - 1

#define SQ0TBDL \
	offsetof(struct spdk_nvme_registers, doorbell[0].sq_tdbl)

static ssize_t
admin_queue_write(struct muser_dev * const dev, uint8_t const * const buf,
                  const size_t count, const loff_t pos)
{
	switch (pos) {
		case offsetof(struct spdk_nvme_registers, aqa):
			return aqa_write((union spdk_nvme_aqa_register*)buf,
			                 &dev->aqa);
		case ASQ:
			return asq_write(&dev->asq, buf, pos, count);
		case ACQ:
			return acq_write(&dev->acq, buf, pos, count);
		default:
			break;
	}
	SPDK_ERRLOG("bad admin queue write offset 0x%lx\n", pos);
	return -EINVAL;
}

static int
asq_map(struct muser_dev * const dev)
{
	dma_scattergather_t sg[1];
	struct iovec iov;
	int ret;

	assert(dev);
	assert(!dev->asq_addr);
	assert(dev->asq);

	/* FIXME this is the number of entries, need to figure out size of memory */
	ret = lm_addr_to_sg(dev->lm_ctx, dev->asq, dev->aqa.bits.acqs + 1, sg,
	                    1);
	if (ret != 1) {
		SPDK_ERRLOG("failed to map SQ 0x%lx: %d\n", dev->asq, ret);
		return -1;
	}

	ret = lm_map_sg(dev->lm_ctx, PROT_READ | PROT_WRITE, sg, &iov, 1);
	if (ret != 0) {
		SPDK_ERRLOG("failed to map segment: %d\n", ret);
		return -1;
	}

	dev->asq_addr = iov.iov_base;
	return 0;
}

static int
consume_admin_req(struct spdk_nvme_cmd * const asq, const uint32_t index)
{
	struct spdk_nvme_cmd *cmd = asq + index;	
	return 0;
}

/*
 * Callback that gets triggered when the driver writes to the admin submission
 * queue doorbell.
 */
static ssize_t
sq0tbdl_write(struct muser_dev * const dev, char const * const buf,
         const size_t count, const loff_t pos)
{
	int ret;
	uint32_t index;

	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("bad write SQ size %zu\n", count);
		return -EINVAL;
	}
	index = *(uint32_t*)buf;
	SPDK_NOTICELOG("write to SQ 0x%x\n", index);

	/*
	 * TODO we should be mapping the queue when ASQ gets written, however
	 * the NVMe driver writes it in two steps and this complicates things,
	 * e.g. is it guaranteed to write both upper and lower portions?
	 */
	if (!dev->asq_addr) {
		ret = asq_map(dev);
		if (ret) {
			SPDK_ERRLOG("failed to map SQ: %d\n", ret);
			return -1;
		}
	}

	ret = consume_admin_req((struct spdk_nvme_cmd*)dev->asq_addr, index);

	return ret;
}

static ssize_t
write_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_dev *muser_dev = pvt;
	int err;

	SPDK_NOTICELOG("dev: %p, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, count, pos);
	spdk_log_dump(stdout, "muser_write", buf, count);

	switch (pos) {
		case ADMIN_QUEUES:
			return admin_queue_write(muser_dev, buf, count, pos);
		case SQ0TBDL:
			return sq0tbdl_write(muser_dev, buf, count, pos);
		default:
			break;
	}

	muser_dev->admin_qp.prop_req.buf = buf;
	muser_dev->admin_qp.prop_req.count = count;
	muser_dev->admin_qp.prop_req.pos = pos;
	spdk_wmb();
	muser_dev->admin_qp.prop_req.dir = MUSER_NVMF_WRITE;

	do {
		err = sem_wait(&muser_dev->admin_qp.prop_req.wait);
	} while (err != 0 && errno != EINTR);

	return muser_dev->admin_qp.prop_req.ret;
}

static ssize_t
access_bar_fn(void *pvt, const int region_index, char * const buf, size_t count,
              loff_t offset, const bool is_write)
{
	ssize_t ret;

	if (region_index != LM_DEV_BAR0_REG_IDX) {
		SPDK_WARNLOG("unsupported access to BAR%d, dev: %p, count=%zu, pos=%"PRIX64"\n",
		       region_index, pvt, count, offset);
		return -1;
	}	

	if (is_write)
		ret = write_bar0(pvt, buf, count, offset);
	else
		ret = read_bar0(pvt, buf, count, offset);

	if (ret != 0) {
		SPDK_WARNLOG("failed to %s %lx@%lx BAR0: %zu\n",
			       is_write ? "write" : "read", offset, count, ret);
		return -1;
	}
	return count;
}

/* 
 * NVMe driver reads 4096 bytes, which is the extended PCI configuration space 
 * available on PCI-X 2.0 and PCI Express buses
 */
static ssize_t
access_pci_config(void *pvt, char *buf, size_t count, loff_t offset,
                  const bool is_write)
{
    struct muser_dev * const muser_dev = (struct muser_dev*)pvt;

    if (is_write) {
        switch (offset) {
            case offsetof(struct nvme_config_space, pci_expr_cap.pxdc):
		if (count != sizeof (union pxdc)) {
			SPDK_WARNLOG("bad write size to PXDC %zu\n", count);
			return -EINVAL;
		} 
                SPDK_NOTICELOG("writing to PXDC 0x%hx\n",
		               ((union pxdc*)buf)->raw);
                return count;
        }

        fprintf(stderr, "writes non supported\n");
        return -EINVAL;
    }

    if (offset + count > PCI_EXTENDED_CONFIG_SPACE_SIZEOF) {
        fprintf(stderr, "access past end of extended PCI configuration space, want=%ld+%ld, max=%d\n",
                offset, count, PCI_EXTENDED_CONFIG_SPACE_SIZEOF);
        return -ERANGE;
    }

    memcpy(buf, ((unsigned char*)muser_dev->pci_config_space) + offset, count);

    return count;
}

static void
nvme_reg_info_fill(lm_reg_info_t *reg_info)
{
    int i;

    assert(reg_info != NULL);

    memset(reg_info, 0, sizeof(*reg_info) * LM_DEV_NUM_REGS);

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        reg_info[i].offset = i * NVME_REG_OFFSET;
    }

    reg_info[LM_DEV_BAR0_REG_IDX].flags = LM_REG_FLAG_RW;
    reg_info[LM_DEV_BAR0_REG_IDX].size  = NVME_REG_BAR0_SIZE;

    reg_info[LM_DEV_CFG_REG_IDX].flags = LM_REG_FLAG_RW;
    reg_info[LM_DEV_CFG_REG_IDX].size  = NVME_REG_CFG_SIZE;
}

static void
nvme_log(void *pvt, char const * const msg) {
    fprintf(stderr, "%s", msg);
}

static void
nvme_dev_info_fill(lm_dev_info_t *dev_info, lm_fops_t *fops,
                   struct muser_dev *muser_dev)
{
	assert(dev_info != NULL);
	assert(muser_dev != NULL);

	dev_info->pvt = muser_dev;

	dev_info->uuid = muser_dev->uuid;

	dev_info->id.vid = 0x4e58;     // TODO: LE ?
	dev_info->id.did = 0x0001;

	/* controller uses the NVM Express programming interface */
	dev_info->cc.pi = 0x02;

	/* non-volatile memory controller */
	dev_info->cc.scc = 0x08;

	/* mass storage controller */
	dev_info->cc.bcc = 0x01;

	if (fops)
		dev_info->fops = *fops;

	dev_info->irq_count[LM_DEV_INTX_IRQ_IDX] = NVME_IRQ_INTX_NUM;
	dev_info->irq_count[LM_DEV_MSIX_IRQ_IDX] = NVME_IRQ_MSIX_NUM;

	dev_info->nr_dma_regions = 0x10;

	dev_info->bar_fn = &access_bar_fn;
	dev_info->pci_config_fn = &access_pci_config;

	dev_info->extended = true;

	nvme_reg_info_fill(dev_info->reg_info);

	dev_info->log = nvme_log;
	dev_info->log_lvl = LM_DBG;
}

static void *
drive(void *arg)
{
	lm_ctx_t *lm_ctx = arg;

	lm_ctx_drive(lm_ctx);

	return NULL;
}

static void
init_pci_config_space(struct nvme_config_space * const p)
{
    mlbar_t *mlbar;
    nvme_bar2_t *nvme_bar2;

    /* MLBAR */
    mlbar = (mlbar_t*)&p->hdr.bars[0].raw;
    mlbar->raw = 0x0; /* initialize register to 0 */

    /* MUBAR */
    p->hdr.bars[1].raw = 0x0;

    /*
     * BAR2, index/data pair register base address or vendor specific (optional)
     */
    nvme_bar2 = (nvme_bar2_t*)&p->hdr.bars[2].raw;
    nvme_bar2->raw = 0x0;
    nvme_bar2->rte = 0x1;

    /* vendor specific, let's set them to zero for now */
    p->hdr.bars[3].raw = 0x0;
    p->hdr.bars[4].raw = 0x0;
    p->hdr.bars[5].raw = 0x0;

    p->hdr.intr.ipin = 0x1;

    /* enables capabilities */
    p->hdr.sts.cl = 0x1;

    /*
     * TODO add function that adds a capability (takes care of updating the
     * next pointers etc.)
     */
   
    p->hdr.cap = offsetof(struct nvme_config_space, pmcap); 
    assert(p->hdr.cap = 0x40);
    /* initialize PMCAP */
    p->pmcap.pid.cid = 0x1; /* PCI power management capability */
    p->pmcap.pmcs.nsfrst = 0x1;

    p->pmcap.pid.next = offsetof(struct nvme_config_space, pci_expr_cap);
    /* initialize PXCAP */
    p->pci_expr_cap.pxid.cid = 0x10; /* PCI Express capability */
    p->pci_expr_cap.pxcap.ver = 0x2;
    p->pci_expr_cap.pxdcap.per = 0x1;
    p->pci_expr_cap.pxdcap.flrc = 0x1;
    p->pci_expr_cap.pxdcap2.ctds = 0x1;
}

static int
muser_listen(struct spdk_nvmf_transport *transport,
	     const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_dev *muser_dev;
	lm_dev_info_t dev_info = { 0 };
	int i;
	int err;

	muser_transport = (struct muser_transport *)transport;

	err = mdev_create(trid->traddr);
	if (err == -1) {
		return -1;
	}

	muser_dev = calloc(1, sizeof(*muser_dev));
	if (muser_dev == NULL) {
		SPDK_ERRLOG("Error allocating dev: %m\n");
		goto err;
	}
	memcpy(muser_dev->uuid, trid->traddr, sizeof(muser_dev->uuid));
	memcpy(&muser_dev->trid, trid, sizeof(muser_dev->trid));

	/* Admin QP setup */
	muser_dev->admin_qp.qpair.transport = transport;
	muser_dev->admin_qp.dev = muser_dev;

	TAILQ_INIT(&muser_dev->admin_qp.reqs);

	err = sem_init(&muser_dev->admin_qp.prop_req.wait, 0, 0);
	assert(err == 0);

	muser_dev->admin_qp.rsps_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(union nvmf_c2h_msg));
	if (muser_dev->admin_qp.rsps_internal == NULL) {
		SPDK_ERRLOG("Error allocating rsps: %m\n");
		goto err_free_dev;
	}

	muser_dev->admin_qp.cmds_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(union nvmf_h2c_msg));
	if (muser_dev->admin_qp.cmds_internal == NULL) {
		SPDK_ERRLOG("Error allocating cmds: %m\n");
		goto err_free_rsps;
	}

	muser_dev->admin_qp.reqs_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(struct muser_req));
	if (muser_dev->admin_qp.reqs_internal == NULL) {
		SPDK_ERRLOG("Error allocating reqs: %m\n");
		goto err_free_cmds;
	}

	for (i = 0; i < MUSER_DEFAULT_AQ_DEPTH; i++) {
		muser_dev->admin_qp.reqs_internal[i].req.qpair =
				&muser_dev->admin_qp.qpair;
		muser_dev->admin_qp.reqs_internal[i].req.rsp =
				&muser_dev->admin_qp.rsps_internal[i];
		muser_dev->admin_qp.reqs_internal[i].req.cmd =
				&muser_dev->admin_qp.cmds_internal[i];
		TAILQ_INSERT_TAIL(&muser_dev->admin_qp.reqs,
				  &muser_dev->admin_qp.reqs_internal[i],
				  link);
	}

	/* LM setup */
	nvme_dev_info_fill(&dev_info, NULL, muser_dev);
	muser_dev->lm_ctx = lm_ctx_create(&dev_info);
	if (muser_dev->lm_ctx == NULL) {
		/* TODO: lm_create doesn't set errno */
		SPDK_ERRLOG("Error creating libmuser ctx: %m\n");
		goto err_free_reqs;
	}


	muser_dev->pci_config_space = lm_get_pci_config_space(muser_dev->lm_ctx);
	init_pci_config_space((struct nvme_config_space*)muser_dev->pci_config_space);

	err = pthread_create(&muser_dev->lm_thr, NULL,
			     drive, muser_dev->lm_ctx);
	if (err != 0) {
		/* TODO: pthread_create doesn't set errno */
		SPDK_ERRLOG("Error creating lm_drive thread: %m\n");
		goto err_destroy;
	}

	TAILQ_INSERT_TAIL(&muser_transport->devs, muser_dev, link);

	return 0;

err_destroy:
	lm_ctx_destroy(muser_dev->lm_ctx);
err_free_reqs:
	free(muser_dev->admin_qp.reqs_internal);
err_free_cmds:
	free(muser_dev->admin_qp.cmds_internal);
err_free_rsps:
	free(muser_dev->admin_qp.rsps_internal);
err_free_dev:
	free(muser_dev);
err:
	mdev_remove(trid->traddr);

	return -1;
}

static int
muser_stop_listen(struct spdk_nvmf_transport *transport,
		  const struct spdk_nvme_transport_id *trid)
{
	return -1;
}

static void
muser_accept(struct spdk_nvmf_transport *transport, new_qpair_fn cb_fn)
{
	struct muser_transport *muser_transport;
	struct muser_dev *muser_dev;

	muser_transport = (struct muser_transport *)transport;

	TAILQ_FOREACH(muser_dev, &muser_transport->devs, link) {
		if (muser_dev->setup == false) {
			cb_fn(&muser_dev->admin_qp.qpair);
			muser_dev->setup = true;
		}
	}
}

static void
muser_discover(struct spdk_nvmf_transport *transport,
	       struct spdk_nvme_transport_id *trid,
	       struct spdk_nvmf_discovery_log_page_entry *entry)
{ }

static struct spdk_nvmf_transport_poll_group *
muser_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct muser_poll_group *muser_group;

	muser_group = calloc(1, sizeof(*muser_group));
	if (muser_group == NULL) {
		SPDK_ERRLOG("Error allocating poll group: %m");
		return NULL;
	}

	TAILQ_INIT(&muser_group->qps);

	return (struct spdk_nvmf_transport_poll_group *)muser_group;
}

static void
muser_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
    struct muser_poll_group *poll_group;

    poll_group = (struct muser_poll_group *)group;

    free(poll_group);
}

static int
muser_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
		     struct spdk_nvmf_qpair *qpair)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;
	struct muser_dev *muser_dev;

	muser_group = (struct muser_poll_group *)group;
	muser_qpair = (struct muser_qpair *)qpair;
	muser_dev = muser_qpair->dev;

	/* Admin QP */
	if (qpair->qid == 0) {
		struct spdk_nvmf_request *req;
		struct spdk_nvmf_fabric_connect_data *data;

		muser_req = TAILQ_FIRST(&muser_qpair->reqs);
		TAILQ_REMOVE(&muser_qpair->reqs, muser_req, link);

		req = &muser_req->req;
		req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
		req->cmd->connect_cmd.cid = 0;
		req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
		req->cmd->connect_cmd.recfmt = 0;
		req->cmd->connect_cmd.sqsize = MUSER_DEFAULT_AQ_DEPTH - 1;
		req->cmd->connect_cmd.qid = 0;

		req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
		req->data = calloc(1, req->length);
		assert(req->data != NULL);
		/* TODO: Pre-allocate memory */

		data = (struct spdk_nvmf_fabric_connect_data *)req->data;
		/* data->hostid = { 0 } */
		data->cntlid = 0xffff;
		snprintf(data->subnqn, sizeof(data->subnqn),
			 "nqn.2019-07.io.spdk.muser:%s", muser_dev->uuid);
		/* data->hostnqn = { 0 } */

		spdk_nvmf_request_exec(req);
	}

	TAILQ_INSERT_TAIL(&muser_group->qps, muser_qpair, link);

	return 0;
}

static int
muser_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	return -1;
}

static void
muser_req_done(struct spdk_nvmf_request *req)
{
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;

	muser_qpair = (struct muser_qpair *)req->qpair;
	muser_req = (struct muser_req *)req;

	if (req->cmd->connect_cmd.opcode == SPDK_NVME_OPC_FABRIC &&
	    req->cmd->connect_cmd.fctype == SPDK_NVMF_FABRIC_COMMAND_CONNECT) {
		free(req->data);
		req->data = NULL;
	}

	TAILQ_INSERT_TAIL(&muser_qpair->reqs, muser_req, link);
}

static int
muser_req_free(struct spdk_nvmf_request *req)
{
	muser_req_done(req);
	return 0;
}

static int
muser_req_complete(struct spdk_nvmf_request *req)
{
	if (req->cmd->connect_cmd.opcode != SPDK_NVME_OPC_FABRIC &&
	    req->cmd->connect_cmd.fctype != SPDK_NVMF_FABRIC_COMMAND_CONNECT) {
		/* TODO: do cqe business */
	}

	muser_req_done(req);

	return 0;
}

static void
muser_close_qpair(struct spdk_nvmf_qpair *qpair)
{ }

static int
muser_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	int err;

	muser_group = (struct muser_poll_group *)group;

	TAILQ_FOREACH(muser_qpair, &muser_group->qps, link) {
		spdk_rmb();
		if (muser_qpair->prop_req.dir != MUSER_NVMF_INVALID) {
			struct spdk_nvmf_request *req;
			struct muser_req *muser_req;

			muser_req = TAILQ_FIRST(&muser_qpair->reqs);
			TAILQ_REMOVE(&muser_qpair->reqs, muser_req, link);

			req = &muser_req->req;
			req->cmd->prop_set_cmd.opcode = SPDK_NVME_OPC_FABRIC;
			req->cmd->prop_set_cmd.cid = 0;
			if (muser_qpair->prop_req.dir == MUSER_NVMF_WRITE) {
				req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET;
				req->cmd->prop_set_cmd.value.u32.high = 0;
				req->cmd->prop_set_cmd.value.u32.low = *(uint32_t *)muser_qpair->prop_req.buf;
			} else {
				req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_GET;
			}
			req->cmd->prop_set_cmd.attrib.size = (muser_qpair->prop_req.count/4)-1;
			req->cmd->prop_set_cmd.ofst = muser_qpair->prop_req.pos;
		
			req->length = 0;
			req->data = NULL;
		
			spdk_nvmf_request_exec(req);

			/*
			 * The below should prob. be in complete or something
			 * This only works because the above will be sync
			 */

			if (muser_qpair->prop_req.dir == MUSER_NVMF_READ) {
				memcpy(muser_qpair->prop_req.buf,
				       &req->rsp->prop_get_rsp.value.u64,
				       muser_qpair->prop_req.count);
			}

			muser_qpair->prop_req.dir = MUSER_NVMF_INVALID;
			err = sem_post(&muser_qpair->prop_req.wait);
			assert(err == 0);
			(void)err;
		}
	}

	return 0;
}

static int
muser_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			   struct spdk_nvme_transport_id *trid)
{
	struct muser_qpair *muser_qpair;
	struct muser_dev *muser_dev;

	muser_qpair = (struct muser_qpair *)qpair;
	muser_dev = muser_qpair->dev;

	memcpy(trid, &muser_dev->trid, sizeof(*trid));
	return 0;
}

static int
muser_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			  struct spdk_nvme_transport_id *trid)
{
	return 0;
}

static int
muser_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			    struct spdk_nvme_transport_id *trid)
{
	struct muser_qpair *muser_qpair;
	struct muser_dev *muser_dev;

	muser_qpair = (struct muser_qpair *)qpair;
	muser_dev = muser_qpair->dev;

	memcpy(trid, &muser_dev->trid, sizeof(*trid));
	return 0;
}

static int
muser_qpair_set_sq_size(struct spdk_nvmf_qpair *qpair)
{
	return 0;
}

static void
muser_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth =		MUSER_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size =		MUSER_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		MUSER_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth =		MUSER_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers =	MUSER_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		MUSER_DEFAULT_BUFFER_CACHE_SIZE;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_muser = {
	.type = SPDK_NVME_TRANSPORT_MUSER,
	.opts_init = muser_opts_init,
	.create = muser_create,
	.destroy = muser_destroy,

	.listen = muser_listen,
	.stop_listen = muser_stop_listen,
	.accept = muser_accept,

	.listener_discover = muser_discover,

	.poll_group_create = muser_poll_group_create,
	.poll_group_destroy = muser_poll_group_destroy,
	.poll_group_add = muser_poll_group_add,
	.poll_group_remove = muser_poll_group_remove,
	.poll_group_poll = muser_poll_group_poll,

	.req_free = muser_req_free,
	.req_complete = muser_req_complete,

	.qpair_fini = muser_close_qpair,
	.qpair_get_local_trid = muser_qpair_get_local_trid,
	.qpair_get_peer_trid = muser_qpair_get_peer_trid,
	.qpair_get_listen_trid = muser_qpair_get_listen_trid,
	.qpair_set_sqsize = muser_qpair_set_sq_size,
};

SPDK_LOG_REGISTER_COMPONENT("nvmf_muser", SPDK_LOG_NVMF_MUSER)
