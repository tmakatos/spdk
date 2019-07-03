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

#include <muser.h>

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

struct muser_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			*rsp;
	struct spdk_nvme_cmd			*cmd;

	TAILQ_ENTRY(muser_req)			link;
};

struct muser_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_muser_poll_group	*group;

	TAILQ_ENTRY(muser_qpair)		link;
};

struct muser_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
};

struct muser_dev {
	struct spdk_nvme_transport_id		trid;
	char					uuid[37];
	pthread_t				lm_thr;
	lm_ctx_t				*lm_ctx;
	struct spdk_nvme_registers		*bar0;
	TAILQ_ENTRY(muser_dev)			link;
};

struct muser_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	TAILQ_HEAD(, muser_dev)			devs;
};

static int
muser_req_free(struct spdk_nvmf_request *req)
{
	return -1;
}

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
muser_read(void *pvt, const int index, char *buf, size_t count, loff_t pos)
{
	struct muser_dev *muser_dev = pvt;

	SPDK_NOTICELOG("dev: %p, idx=%d, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, index, count, pos);

	if (index == 0) {
	    /* TODO: Ensure pos/count is within boundaries */
	    memcpy(buf, muser_dev->bar0 + pos, count);
	}

	return count;
}

static ssize_t
muser_write(void *pvt, const int index, char *buf, size_t count, loff_t pos)
{
	struct muser_dev *muser_dev = pvt;
	union spdk_nvme_cc_register *cc;

	SPDK_NOTICELOG("dev: %p, idx=%d, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, index, count, pos);
	spdk_log_dump(stdout, "muser_write", buf, count);

	if (index == 0) {
		switch (pos) {
		case offsetof(struct spdk_nvme_registers, cc):
			if (count != 4) {
				errno = EINVAL;
				return -1;
			}
			cc = (union spdk_nvme_cc_register *)buf;
			if (cc->bits.en == 1) {
				SPDK_NOTICELOG("ENABLE SET TO 1\n");
			}
			break;
		default:
			errno = EINVAL;
			return -1;
		}
	}

	return count;
}

static void
dev_info_fill(lm_dev_info_t *dev_info, struct muser_dev *muser_dev)
{
	int i;

	dev_info->pvt = muser_dev;
	dev_info->uuid = muser_dev->uuid;
	dev_info->id.vid = 0x4e58;
	dev_info->id.did = 0x0001;
	dev_info->cc.pi = 0x02;
	dev_info->cc.scc = 0x08;
	dev_info->cc.bcc = 0x01;

	dev_info->fops.read = muser_read;
	dev_info->fops.write = muser_write;

	dev_info->irq_count[LM_DEV_INTX_IRQ_IDX] = 1;
	dev_info->irq_count[LM_DEV_MSI_IRQ_IDX]  = 1;
	dev_info->irq_count[LM_DEV_MSIX_IRQ_IDX] = 32;

	dev_info->nr_dma_regions = 0x10;

	for (i = 0; i < LM_DEV_NUM_REGS; i++) {
		dev_info->reg_info[i].offset = i * (1UL << 36);
	}

	dev_info->reg_info[LM_DEV_BAR0_REG_IDX].flags = LM_REG_FLAG_RW;
	dev_info->reg_info[LM_DEV_BAR0_REG_IDX].size  = 0x4000;

	dev_info->reg_info[LM_DEV_CFG_REG_IDX].flags  = LM_REG_FLAG_RW;
	dev_info->reg_info[LM_DEV_CFG_REG_IDX].size   = 0x1000;
}

static void *
drive(void *arg)
{
	lm_ctx_t *lm_ctx = arg;

	lm_ctx_drive(lm_ctx);

	return NULL;
}

static int
muser_listen(struct spdk_nvmf_transport *transport,
	     const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_dev *muser_dev;
	lm_dev_info_t dev_info = { 0 };
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

	muser_dev->bar0 = calloc(1, sizeof(*muser_dev->bar0));
	if (muser_dev->bar0 == NULL) {
		SPDK_ERRLOG("Error allocating bar0: %m\n");
		goto err_free;
	}

	dev_info_fill(&dev_info, muser_dev);
	muser_dev->lm_ctx = lm_ctx_create(&dev_info);
	if (muser_dev->lm_ctx == NULL) {
		/* TODO: lm_create doesn't set errno */
		SPDK_ERRLOG("Error creating libmuser ctx: %m\n");
		goto err_free_bar0;
	}

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
err_free_bar0:
	free(muser_dev->bar0);
err_free:
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
{ }

static void
muser_discover(struct spdk_nvmf_transport *transport,
	       struct spdk_nvme_transport_id *trid,
	       struct spdk_nvmf_discovery_log_page_entry *entry)
{ }

static struct spdk_nvmf_transport_poll_group *
muser_poll_group_create(struct spdk_nvmf_transport *transport)
{
    struct muser_poll_group *poll_group;

    poll_group = calloc(1, sizeof(*poll_group));
    if (poll_group == NULL) {
        SPDK_ERRLOG("Error allocating poll group: %m");
        return NULL;
    }

    return (struct spdk_nvmf_transport_poll_group *)poll_group;
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
	return -1;
}

static int
muser_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	return -1;
}

static int
muser_req_complete(struct spdk_nvmf_request *req)
{
	return -1;
}

static void
muser_close_qpair(struct spdk_nvmf_qpair *qpair)
{ }

static int
muser_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	return -1;
}

static int
muser_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			   struct spdk_nvme_transport_id *trid)
{
	return -1;
}

static int
muser_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			  struct spdk_nvme_transport_id *trid)
{
	return -1;
}

static int
muser_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			    struct spdk_nvme_transport_id *trid)
{
	return -1;
}

static int
muser_qpair_set_sq_size(struct spdk_nvmf_qpair *qpair)
{
	return -1;
}

#define MUSER_DEFAULT_MAX_QUEUE_DEPTH 128
#define MUSER_DEFAULT_AQ_DEPTH 128
#define MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR 64
#define MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE 0
#define MUSER_DEFAULT_MAX_IO_SIZE 131072
#define MUSER_DEFAULT_IO_UNIT_SIZE 131072
#define MUSER_DEFAULT_NUM_SHARED_BUFFERS 512 /* internal buf size */
#define MUSER_DEFAULT_BUFFER_CACHE_SIZE 0

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
