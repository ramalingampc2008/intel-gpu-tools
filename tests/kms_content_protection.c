/*
 * Copyright © 2018 Intel Corporation
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
 */

#include <poll.h>
#include <fcntl.h>
#include "igt.h"
#include "igt_sysfs.h"
#include "igt_kms.h"
#include "igt_kmod.h"

IGT_TEST_DESCRIPTION("Test content protection (HDCP)");

struct data {
	int drm_fd;
	igt_display_t display;
	struct igt_fb red, green;
} data;

#define CP_UNDESIRED				0
#define CP_DESIRED				1
#define CP_ENABLED				2

/*
 * CP_TYPE_0 can be handled on both HDCP1.4 and HDCP2.2. Where as CP_TYPE_1
 * can be handled only through HDCP2.2.
 */
#define CP_TYPE_0				0
#define CP_TYPE_1				1

#define LIC_PERIOD_MSEC				(4 * 1000)
/* Kernel retry count=3, Max time per authentication allowed = 6Sec */
#define KERNEL_AUTH_TIME_ALLOWED_MSEC		(3 *  6 * 1000)
#define KERNEL_DISABLE_TIME_ALLOWED_MSEC	(1 * 1000)
#define FLIP_EVENT_POLLING_TIMEOUT_MSEC		1000


#define DRM_MODE_HDCP_KSV_LEN			5
#define DRM_MODE_HDCP_MAX_DEVICE_CNT		127

#define DRM_MODE_HDCP14_IN_FORCE		(1<<0)
#define DRM_MODE_HDCP22_IN_FORCE		(1<<1)

struct cp_downstream_info {

	/* HDCP ver in force */
	__u32 ver_in_force;
	__u8 content_type;

	/* KSV of immediate HDCP Sink. In Little-Endian Format. */
	char bksv[DRM_MODE_HDCP_KSV_LEN];

	/* Whether Immediate HDCP sink is a repeater? */
	bool is_repeater;

	/* Depth received from immediate downstream repeater */
	__u8 depth;

	/* Device count received from immediate downstream repeater */
	__u32 device_count;

	/*
	 * Max buffer required to hold ksv list received from immediate
	 * repeater. In this array first device_count * DRM_MODE_HDCP_KSV_LEN
	 * will hold the valid ksv bytes.
	 * If authentication specification is
	 *      HDCP1.4 - each KSV's Bytes will be in Little-Endian format.
	 *      HDCP2.2 - each KSV's Bytes will be in Big-Endian format.
	 */
	char ksv_list[DRM_MODE_HDCP_KSV_LEN * DRM_MODE_HDCP_MAX_DEVICE_CNT];
};


__u8 facsimile_srm[] = {
	0x80, 0x0, 0x0, 0x05, 0x01, 0x0, 0x0, 0x36, 0x02, 0x51, 0x1E, 0xF2,
	0x1A, 0xCD, 0xE7, 0x26, 0x97, 0xF4, 0x01, 0x97, 0x10, 0x19, 0x92, 0x53,
	0xE9, 0xF0, 0x59, 0x95, 0xA3, 0x7A, 0x3B, 0xFE, 0xE0, 0x9C, 0x76, 0xDD,
	0x83, 0xAA, 0xC2, 0x5B, 0x24, 0xB3, 0x36, 0x84, 0x94, 0x75, 0x34, 0xDB,
	0x10, 0x9E, 0x3B, 0x23, 0x13, 0xD8, 0x7A, 0xC2, 0x30, 0x79, 0x84};

static void parse_downstream_info(struct cp_downstream_info *ds_info)
{
	char *ksvs;
	int i;

	if (ds_info->ver_in_force & DRM_MODE_HDCP14_IN_FORCE)
		igt_info("HDCP1.4 is Enabled\n");
	else if (ds_info->ver_in_force & DRM_MODE_HDCP22_IN_FORCE)
		igt_info("HDCP2.2 is Enabled. Type%d\n",
			 ds_info->content_type & CP_TYPE_1 ?
			 1 : 0);
	else
		return;

	igt_info("\tReceiver ID: %#04x %#04x %#04x %#04x %#04x\n",
			ds_info->bksv[0] & 0xFF, ds_info->bksv[1] & 0xFF,
			ds_info->bksv[2] & 0xFF, ds_info->bksv[3] & 0xFF,
			ds_info->bksv[4] & 0xFF);

	if (ds_info->is_repeater) {
		igt_info("\tHDCP sink is a Repeater\n");

		igt_info("\tDepth: %d, Device count: %d\n", ds_info->depth,
							ds_info->device_count);
		ksvs = ds_info->ksv_list;

		for (i = 0; i < ds_info->device_count; i++) {
			igt_info("\tksv-%d: %#04x %#04x %#04x %#04x %#04x\n", i,
					ksvs[0] & 0xFF, ksvs[1] & 0xFF,
					ksvs[2] & 0xFF, ksvs[3] & 0xFF,
					ksvs[4] & 0xFF);
			ksvs += DRM_MODE_HDCP_KSV_LEN;
		}
	} else {
		igt_info("\tHDCP sink is a Receiver\n");
	}
}

static void retrieve_downstream_info_prepare_srm(igt_output_t *output)
{
	drmModePropertyBlobRes *ds_info_prop = NULL;
	uint64_t downstream_blob_id;
	struct cp_downstream_info *ds_info;
	int i;

	igt_info("CP_downstream_info property is attached\n");

	downstream_blob_id = igt_output_get_prop(output,
				IGT_CONNECTOR_CP_DOWNSTREAM_INFO);

	igt_assert_f(downstream_blob_id,
				"Invalid downstream blob id\n");

	ds_info_prop = drmModeGetPropertyBlob(data.drm_fd,
						downstream_blob_id);

	igt_assert(ds_info_prop);
	igt_assert_eq(ds_info_prop->length,
				sizeof(struct cp_downstream_info));
	ds_info = ds_info_prop->data;

	parse_downstream_info(ds_info);

	for (i = 0; i < 5; i++)
		facsimile_srm[i + 9] = ds_info->bksv[i];
}

static void flip_handler(int fd, unsigned int sequence, unsigned int tv_sec,
			 unsigned int tv_usec, void *_data)
{
	igt_debug("Flip event received.\n");
}

static int wait_flip_event(void)
{
	int rc;
	drmEventContext evctx;
	struct pollfd pfd;

	evctx.version = 2;
	evctx.vblank_handler = NULL;
	evctx.page_flip_handler = flip_handler;

	pfd.fd = data.drm_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	rc = poll(&pfd, 1, FLIP_EVENT_POLLING_TIMEOUT_MSEC);
	switch (rc) {
	case 0:
		igt_info("Poll timeout. 1Sec.\n");
		rc = -ETIMEDOUT;
		break;
	case 1:
		rc = drmHandleEvent(data.drm_fd, &evctx);
		igt_assert_eq(rc, 0);
		rc = 0;
		break;
	default:
		igt_info("Unexpected poll rc %d\n", rc);
		rc = -1;
		break;
	}

	return rc;
}

static bool
wait_for_prop_value(igt_output_t *output, uint64_t expected,
		    uint32_t timeout_mSec)
{
	uint64_t val;
	int i;

	for (i = 0; i < timeout_mSec; i++) {
		val = igt_output_get_prop(output,
					  IGT_CONNECTOR_CONTENT_PROTECTION);
		if (val == expected)
			return true;
		usleep(1000);
	}
	igt_info("prop_value mismatch %" PRId64 " != %" PRId64 "\n",
		 val, expected);

	return false;
}

static void
commit_display_and_wait_for_flip(enum igt_commit_style s)
{
	int ret;
	uint32_t flag;

	if (s == COMMIT_ATOMIC) {
		flag = DRM_MODE_PAGE_FLIP_EVENT | DRM_MODE_ATOMIC_ALLOW_MODESET;
		igt_display_commit_atomic(&data.display, flag, NULL);

		ret = wait_flip_event();
		igt_assert_f(!ret, "wait_flip_event failed. %d\n", ret);
	} else {
		igt_display_commit2(&data.display, s);

		/* Wait for 50mSec */
		usleep(50 * 1000);
	}
}

static void modeset_with_fb(const enum pipe pipe, igt_output_t *output,
			    enum igt_commit_style s)
{
	igt_display_t *display = &data.display;
	drmModeModeInfo mode;
	igt_plane_t *primary;

	igt_assert(kmstest_get_connector_default_mode(
			display->drm_fd, output->config.connector, &mode));

	igt_output_override_mode(output, &mode);
	igt_output_set_pipe(output, pipe);

	igt_create_color_fb(display->drm_fd, mode.hdisplay, mode.vdisplay,
			    DRM_FORMAT_XRGB8888, LOCAL_DRM_FORMAT_MOD_NONE,
			    1.f, 0.f, 0.f, &data.red);
	igt_create_color_fb(display->drm_fd, mode.hdisplay, mode.vdisplay,
			    DRM_FORMAT_XRGB8888, LOCAL_DRM_FORMAT_MOD_NONE,
			    0.f, 1.f, 0.f, &data.green);

	primary = igt_output_get_plane_type(output, DRM_PLANE_TYPE_PRIMARY);
	igt_display_commit2(display, s);
	igt_plane_set_fb(primary, &data.red);

	/* Wait for Flip completion before starting the HDCP authentication */
	commit_display_and_wait_for_flip(s);
}

static bool test_cp_enable(igt_output_t *output, enum igt_commit_style s,
			   int content_type)
{
	igt_display_t *display = &data.display;
	igt_plane_t *primary;
	bool ret;

	primary = igt_output_get_plane_type(output, DRM_PLANE_TYPE_PRIMARY);

	igt_output_set_prop_value(output,
				  IGT_CONNECTOR_CONTENT_PROTECTION, CP_DESIRED);
	if (output->props[IGT_CONNECTOR_CP_CONTENT_TYPE])
		igt_output_set_prop_value(output, IGT_CONNECTOR_CP_CONTENT_TYPE,
					  content_type);
	igt_display_commit2(display, s);

	ret = wait_for_prop_value(output, CP_ENABLED,
				  KERNEL_AUTH_TIME_ALLOWED_MSEC);
	if (ret) {
		igt_plane_set_fb(primary, &data.green);
		igt_display_commit2(display, s);
	}

	return ret;
}

static void test_cp_disable(igt_output_t *output, enum igt_commit_style s)
{
	igt_display_t *display = &data.display;
	igt_plane_t *primary;
	bool ret;

	primary = igt_output_get_plane_type(output, DRM_PLANE_TYPE_PRIMARY);

	/*
	 * Even on HDCP enable failed scenario, IGT should exit leaving the
	 * "content protection" at "UNDESIRED".
	 */
	igt_output_set_prop_value(output, IGT_CONNECTOR_CONTENT_PROTECTION,
				  CP_UNDESIRED);
	igt_plane_set_fb(primary, &data.red);
	igt_display_commit2(display, s);

	/* Wait for HDCP to be disabled, before crtc off */
	ret = wait_for_prop_value(output, CP_UNDESIRED,
				  KERNEL_DISABLE_TIME_ALLOWED_MSEC);
	igt_assert_f(ret, "Content Protection not cleared\n");
}

static void test_cp_enable_with_retry(igt_output_t *output,
				      enum igt_commit_style s, int retry,
				      int content_type, bool expect_failure,
				      bool test_srm)
{
	bool ret;

	do {
		test_cp_disable(output, s);
		ret = test_cp_enable(output, s, content_type);

		if (!ret && --retry)
			igt_debug("Retry (%d/2) ...\n", 3 - retry);
	} while (retry && !ret);

	if (expect_failure)
		igt_assert_f(!ret,
			     "CP Enabled. Though it is expected to fail\n");
	else if (test_srm)
		igt_assert_f(!ret,
			     "CP Enabled. Though ID is revoked through SRM\n");
	else
		igt_assert_f(ret, "Content Protection not enabled\n");
}

static bool igt_pipe_is_free(igt_display_t *display, enum pipe pipe)
{
	int i;

	for (i = 0; i < display->n_outputs; i++)
		if (display->outputs[i].pending_pipe == pipe)
			return false;

	return true;
}

static void test_cp_lic(igt_output_t *output)
{
	bool ret;

	/* Wait for 4Secs (min 2 cycles of Link Integrity Check) */
	ret = wait_for_prop_value(output, CP_DESIRED, LIC_PERIOD_MSEC);
	igt_assert_f(!ret, "Content Protection LIC Failed\n");
}

static bool write_srm_into_sysfs(const char *srm, int len)
{
	int fd;
	bool ret = false;

	fd = igt_sysfs_open(data.drm_fd, NULL);
	if (fd > 0) {
		if (igt_sysfs_write(fd, "hdcp_srm", srm, len) == len)
			ret = true;
		close(fd);
	}
	return ret;
}

static void
test_content_protection_on_output(igt_output_t *output, enum igt_commit_style s,
				  bool dpms_test, int content_type,
				  bool mei_reload_test, bool test_srm)
{
	igt_display_t *display = &data.display;
	igt_plane_t *primary;
	enum pipe pipe;
	bool ret, srm_modified = false;
	int i;

	for_each_pipe(display, pipe) {
		if (!igt_pipe_connector_valid(pipe, output))
			continue;

		/*
		 * If previous subtest of connector failed, pipe
		 * attached to that connector is not released.
		 * Because of that we have to choose the non
		 * attached pipe for this subtest.
		 */
		if (!igt_pipe_is_free(display, pipe))
			continue;

		srm_modified = false;
		modeset_with_fb(pipe, output, s);
		test_cp_enable_with_retry(output, s, 3, content_type, false,
					  false);

		if (mei_reload_test) {
			igt_assert_f(!igt_kmod_unload("mei_hdcp", 0),
				     "mei_hdcp unload failed");

			/* Expected to fail */
			test_cp_enable_with_retry(output, s, 3,
						  content_type, false, true);

			igt_assert_f(!igt_kmod_load("mei_hdcp", NULL),
				     "mei_hdcp load failed");

			/* Expected to pass */
			test_cp_enable_with_retry(output, s, 3,
						  content_type, false, false);
		}

		test_cp_lic(output);

		if (output->props[IGT_CONNECTOR_CP_DOWNSTREAM_INFO] &&
		    test_srm) {
			retrieve_downstream_info_prepare_srm(output);
			srm_modified =
				write_srm_into_sysfs((const char *)facsimile_srm,
						     sizeof(facsimile_srm));
			igt_assert_f(srm_modified, "SRM update failed");
		}

		if (test_srm && srm_modified) {
			test_cp_disable(output, s);
			test_cp_enable_with_retry(output, s, 3, content_type,
						  false, test_srm);

			/* Removing the sink's Receiver ID from SRM Blob */
			for (i = 0; i < 5; i++)
				facsimile_srm[i + 9] = 0;

			srm_modified =
				write_srm_into_sysfs((const char *)facsimile_srm,
						     sizeof(facsimile_srm));
			igt_assert_f(srm_modified, "SRM update failed");

			test_cp_enable_with_retry(output, s, 1, content_type,
						  false, false);
		}

		if (dpms_test) {
			igt_pipe_set_prop_value(display, pipe,
						IGT_CRTC_ACTIVE, 0);
			igt_display_commit2(display, s);

			igt_pipe_set_prop_value(display, pipe,
						IGT_CRTC_ACTIVE, 1);
			igt_display_commit2(display, s);

			ret = wait_for_prop_value(output, CP_ENABLED,
						  KERNEL_AUTH_TIME_ALLOWED_MSEC);
			if (!ret)
				test_cp_enable_with_retry(output, s, 2,
							  content_type, false,
							  false);
		}

		test_cp_disable(output, s);
		primary = igt_output_get_plane_type(output,
						    DRM_PLANE_TYPE_PRIMARY);
		igt_plane_set_fb(primary, NULL);
		igt_output_set_pipe(output, PIPE_NONE);

		/*
		 * Testing a output with a pipe is enough for HDCP
		 * testing. No ROI in testing the connector with other
		 * pipes. So Break the loop on pipe.
		 */
		break;
	}
}

static void __debugfs_read(int fd, const char *param, char *buf, int len)
{
	len = igt_debugfs_simple_read(fd, param, buf, len);
	if (len < 0)
		igt_assert_eq(len, -ENODEV);
}

#define debugfs_read(fd, p, arr) __debugfs_read(fd, p, arr, sizeof(arr))

#define MAX_SINK_HDCP_CAP_BUF_LEN	5000

static bool sink_hdcp_capable(igt_output_t *output)
{
	char buf[MAX_SINK_HDCP_CAP_BUF_LEN];
	int fd;

	fd = igt_debugfs_connector_dir(data.drm_fd, output->name, O_RDONLY);
	if (fd < 0)
		return false;

	debugfs_read(fd, "i915_hdcp_sink_capability", buf);
	close(fd);

	igt_debug("Sink capability: %s\n", buf);

	return strstr(buf, "HDCP1.4");
}

static bool sink_hdcp2_capable(igt_output_t *output)
{
	char buf[MAX_SINK_HDCP_CAP_BUF_LEN];
	int fd;

	fd = igt_debugfs_connector_dir(data.drm_fd, output->name, O_RDONLY);
	if (fd < 0)
		return false;

	debugfs_read(fd, "i915_hdcp_sink_capability", buf);
	close(fd);

	igt_debug("Sink capability: %s\n", buf);

	return strstr(buf, "HDCP2.2");
}

static void
test_content_protection(enum igt_commit_style s, bool dpms_test,
			int content_type, bool mei_reload_test,
			bool test_srm)
{
	igt_display_t *display = &data.display;
	igt_output_t *output;
	int valid_tests = 0;

	if (mei_reload_test)
		igt_require_f(igt_kmod_is_loaded("mei_hdcp"),
			      "mei_hdcp module is not loaded\n");

	for_each_connected_output(display, output) {
		if (!output->props[IGT_CONNECTOR_CONTENT_PROTECTION])
			continue;

		if (!output->props[IGT_CONNECTOR_CP_CONTENT_TYPE] &&
		    content_type)
			continue;

		igt_info("CP Test execution on %s\n", output->name);

		if (content_type && !sink_hdcp2_capable(output)) {
			igt_info("\tSkip %s (Sink has no HDCP2.2 support)\n",
				 output->name);
			continue;
		} else if (!sink_hdcp_capable(output)) {
			igt_info("\tSkip %s (Sink has no HDCP support)\n",
				 output->name);
			continue;
		}

		test_content_protection_on_output(output, s, dpms_test,
						  content_type,
						  mei_reload_test, test_srm);
		valid_tests++;
	}

	igt_require_f(valid_tests, "No connector found with HDCP capability\n");
}

igt_main
{
	igt_fixture {
		igt_skip_on_simulation();

		data.drm_fd = drm_open_driver(DRIVER_ANY);

		igt_display_require(&data.display, data.drm_fd);
	}

	igt_subtest("legacy")
		test_content_protection(COMMIT_LEGACY, false, CP_TYPE_0,
					false, false);

	igt_subtest("atomic") {
		igt_require(data.display.is_atomic);
		test_content_protection(COMMIT_ATOMIC, false, CP_TYPE_0,
					false, false);
	}

	igt_subtest("atomic-dpms") {
		igt_require(data.display.is_atomic);
		test_content_protection(COMMIT_ATOMIC, true, CP_TYPE_0,
					false, false);
	}

	igt_subtest("Type1") {
		igt_require(data.display.is_atomic);
		test_content_protection(COMMIT_ATOMIC, false, CP_TYPE_1,
					false, false);
	}

	igt_subtest("type1_mei_interface") {
		igt_require(data.display.is_atomic);
		test_content_protection(COMMIT_ATOMIC, false, CP_TYPE_1,
					true, false);
	}

	/*
	 * SRM subtest perform the HDCP authentication, and then retrive the
	 * receiver id through downstream info.
	 *
	 * Using the receiver ID, facsimile SRM table is modified with
	 * receiver ID retrieved from teh downstream info. After modification
	 * SRM table is not intact as per DCP Signature.
	 *
	 * But Kernel believes userspace and doesn't verify the DCP signature.
	 * So we can exploite that trust to test the SRM and downstream info
	 * features.
	 *
	 * So when modified SRM is applied Authentication will fail due to
	 * receiver ID revocation.
	 *
	 * And Kernel attempts HDCP2.2 always and on failure of it HDCP1.4
	 * will be attempted. But their ID of the sink varies between 1.4 and
	 * 2.2 versions. So we need to stick to one version. Hence HDCP2.2 is
	 * choosen using Type 1.
	 */
	igt_subtest("srm") {
		igt_require(data.display.is_atomic);
		test_content_protection(COMMIT_ATOMIC, false, CP_TYPE_1,
					false, true);
	}


	igt_fixture
		igt_display_fini(&data.display);
}
