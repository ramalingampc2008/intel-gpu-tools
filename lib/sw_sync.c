/*
 * Copyright © 2016 Collabora, Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Robert Foss <robert.foss@collabora.com>
 */

#ifndef ANDROID
#define _GNU_SOURCE
#else
#include <libgen.h>
#endif
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/sync_file.h>
#include <sys/ioctl.h>

#include "igt_debugfs.h"
#include "sw_sync.h"
#include "drmtest.h"
#include "ioctl_wrappers.h"

#ifndef SW_SYNC_IOC_INC
struct sw_sync_create_fence_data {
	__u32	value;
	char	name[32];
	__s32	fence;
};

#define LOCAL_SW_SYNC_IOC_MAGIC		    'W'
#define LOCAL_SW_SYNC_IOC_CREATE_FENCE	_IOWR(LOCAL_SW_SYNC_IOC_MAGIC, 0,\
						                        struct sw_sync_create_fence_data)
#define LOCAL_SW_SYNC_IOC_INC			_IOW(LOCAL_SW_SYNC_IOC_MAGIC, 1, __u32)
#endif


static bool kernel_sw_sync_path(char *path, int length)
{
	snprintf(path, length, "%s", "/dev/sw_sync");
	if (access(path, R_OK | W_OK) == 0) {
	    return true;
	}

	snprintf(path, length, "%s", "/sys/kernel/debug/sync/sw_sync");
	if (access(path, R_OK | W_OK) == 0) {
	    return true;
	}

	snprintf(path, length, "%s/sw_sync", igt_debugfs_mount());
	if (access(path, R_OK | W_OK) == 0) {
	    return true;
	}

    return false;
}

static bool sw_sync_fd_is_valid(int fd)
{
	int status;

	if (fd < 0)
		return 0;

	status = fcntl(fd, F_GETFD, 0);
	return status >= 0;
}

int sw_sync_timeline_create(void)
{
	char buf[128];
	int fd;

	igt_assert_f(kernel_sw_sync_path(buf, sizeof(buf)),
	    "Unable to find valid path for sw_sync\n");

	fd = open(buf, O_RDWR);
	igt_assert_f(sw_sync_fd_is_valid(fd), "Created invalid timeline\n");

	return fd;
}

int __sw_sync_fence_create(int fd, uint32_t seqno)
{
	struct sw_sync_create_fence_data data = {0};
	data.value = seqno;

	if (igt_ioctl(fd, LOCAL_SW_SYNC_IOC_CREATE_FENCE, &data))
		return -errno;

	return data.fence;
}

int sw_sync_fence_create(int fd, uint32_t seqno)
{
	int fence = __sw_sync_fence_create(fd, seqno);

	igt_assert_f(sw_sync_fd_is_valid(fence), "Created invalid fence\n");

	return fence;
}

void sw_sync_timeline_inc(int fd, uint32_t count)
{
	uint32_t arg = count;

	do_ioctl(fd, LOCAL_SW_SYNC_IOC_INC, &arg);
}

int sync_merge(int fd1, int fd2)
{
	struct sync_merge_data data = {};
	int err;

	data.fd2 = fd2;

	err = ioctl(fd1, SYNC_IOC_MERGE, &data);
	if (err < 0)
		return -errno;

	return data.fence;
}

int sync_wait(int fd, int timeout)
{
	struct pollfd fds = {0};
	int ret;

	fds.fd = fd;
	fds.events = POLLIN;

	do {
		 ret = poll(&fds, 1, timeout);
		 if (ret > 0) {
			  if (fds.revents & (POLLERR | POLLNVAL)) {
				   errno = EINVAL;
				   return -1;
			  }
			  return 0;
		 } else if (ret == 0) {
			  errno = ETIME;
			  return -1;
		 }
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));

	return ret;
}

int sync_fence_count(int fd)
{
	struct sync_file_info info = {0};

	if (ioctl(fd, SYNC_IOC_FILE_INFO, &info))
		return -errno;

	return info.num_fences;
}

static int __sync_fence_count_status(int fd, int status)
{
	struct sync_file_info info = {0};
	struct sync_fence_info *fence_info;
	int count;
	int i;

	if (ioctl(fd, SYNC_IOC_FILE_INFO, &info))
		return -errno;

	fence_info = calloc(info.num_fences, sizeof(*fence_info));
	if (!fence_info)
		return -ENOMEM;

	info.sync_fence_info = (uintptr_t)fence_info;
	if (ioctl(fd, SYNC_IOC_FILE_INFO, &info)) {
		count = -errno;
	} else {
		count = 0;
		for (i = 0 ; i < info.num_fences ; i++)
			if (fence_info[i].status == status)
				count++;
	}

	free(fence_info);

	return count;
}

int sync_fence_count_status(int fd, int status)
{
	int count = __sync_fence_count_status(fd, status);
	igt_assert_f(count >= 0, "No fences with supplied status found\n");

	return count;
}