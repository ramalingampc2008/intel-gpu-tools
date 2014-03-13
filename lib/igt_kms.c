/*
 * Copyright © 2013 Intel Corporation
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <math.h>
#include <linux/kd.h>
#include "drm_fourcc.h"

#include "drmtest.h"
#include "igt_kms.h"

/* helpers to create nice-looking framebuffers */
static int create_bo_for_fb(int fd, int width, int height, int bpp,
			    bool tiled, uint32_t *gem_handle_ret,
			    unsigned *size_ret, unsigned *stride_ret)
{
	uint32_t gem_handle;
	int size;
	unsigned stride;

	if (tiled) {
		int v;

		/* Round the tiling up to the next power-of-two and the
		 * region up to the next pot fence size so that this works
		 * on all generations.
		 *
		 * This can still fail if the framebuffer is too large to
		 * be tiled. But then that failure is expected.
		 */

		v = width * bpp / 8;
		for (stride = 512; stride < v; stride *= 2)
			;

		v = stride * height;
		for (size = 1024*1024; size < v; size *= 2)
			;
	} else {
		/* Scan-out has a 64 byte alignment restriction */
		stride = (width * (bpp / 8) + 63) & ~63;
		size = stride * height;
	}

	gem_handle = gem_create(fd, size);

	if (tiled)
		gem_set_tiling(fd, gem_handle, I915_TILING_X, stride);

	*stride_ret = stride;
	*size_ret = size;
	*gem_handle_ret = gem_handle;

	return 0;
}

void kmstest_paint_color(cairo_t *cr, int x, int y, int w, int h,
			 double r, double g, double b)
{
	cairo_rectangle(cr, x, y, w, h);
	cairo_set_source_rgb(cr, r, g, b);
	cairo_fill(cr);
}

void kmstest_paint_color_alpha(cairo_t *cr, int x, int y, int w, int h,
			       double r, double g, double b, double a)
{
	cairo_rectangle(cr, x, y, w, h);
	cairo_set_source_rgba(cr, r, g, b, a);
	cairo_fill(cr);
}

void
kmstest_paint_color_gradient(cairo_t *cr, int x, int y, int w, int h,
		     int r, int g, int b)
{
	cairo_pattern_t *pat;

	pat = cairo_pattern_create_linear(x, y, x + w, y + h);
	cairo_pattern_add_color_stop_rgba(pat, 1, 0, 0, 0, 1);
	cairo_pattern_add_color_stop_rgba(pat, 0, r, g, b, 1);

	cairo_rectangle(cr, x, y, w, h);
	cairo_set_source(cr, pat);
	cairo_fill(cr);
	cairo_pattern_destroy(pat);
}

static void
paint_test_patterns(cairo_t *cr, int width, int height)
{
	double gr_height, gr_width;
	int x, y;

	y = height * 0.10;
	gr_width = width * 0.75;
	gr_height = height * 0.08;
	x = (width / 2) - (gr_width / 2);

	kmstest_paint_color_gradient(cr, x, y, gr_width, gr_height, 1, 0, 0);

	y += gr_height;
	kmstest_paint_color_gradient(cr, x, y, gr_width, gr_height, 0, 1, 0);

	y += gr_height;
	kmstest_paint_color_gradient(cr, x, y, gr_width, gr_height, 0, 0, 1);

	y += gr_height;
	kmstest_paint_color_gradient(cr, x, y, gr_width, gr_height, 1, 1, 1);
}

int kmstest_cairo_printf_line(cairo_t *cr, enum kmstest_text_align align,
				double yspacing, const char *fmt, ...)
{
	double x, y, xofs, yofs;
	cairo_text_extents_t extents;
	char *text;
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&text, fmt, ap);
	assert(ret >= 0);
	va_end(ap);

	cairo_text_extents(cr, text, &extents);

	xofs = yofs = 0;
	if (align & align_right)
		xofs = -extents.width;
	else if (align & align_hcenter)
		xofs = -extents.width / 2;

	if (align & align_top)
		yofs = extents.height;
	else if (align & align_vcenter)
		yofs = extents.height / 2;

	cairo_get_current_point(cr, &x, &y);
	if (xofs || yofs)
		cairo_rel_move_to(cr, xofs, yofs);

	cairo_text_path(cr, text);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_stroke_preserve(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_fill(cr);

	cairo_move_to(cr, x, y + extents.height + yspacing);

	free(text);

	return extents.width;
}

static void
paint_marker(cairo_t *cr, int x, int y)
{
	enum kmstest_text_align align;
	int xoff, yoff;

	cairo_move_to(cr, x, y - 20);
	cairo_line_to(cr, x, y + 20);
	cairo_move_to(cr, x - 20, y);
	cairo_line_to(cr, x + 20, y);
	cairo_new_sub_path(cr);
	cairo_arc(cr, x, y, 10, 0, M_PI * 2);
	cairo_set_line_width(cr, 4);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_stroke_preserve(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_set_line_width(cr, 2);
	cairo_stroke(cr);

	xoff = x ? -20 : 20;
	align = x ? align_right : align_left;

	yoff = y ? -20 : 20;
	align |= y ? align_bottom : align_top;

	cairo_move_to(cr, x + xoff, y + yoff);
	cairo_set_font_size(cr, 18);
	kmstest_cairo_printf_line(cr, align, 0, "(%d, %d)", x, y);
}

void kmstest_paint_test_pattern(cairo_t *cr, int width, int height)
{
	paint_test_patterns(cr, width, height);

	cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);

	/* Paint corner markers */
	paint_marker(cr, 0, 0);
	paint_marker(cr, width, 0);
	paint_marker(cr, 0, height);
	paint_marker(cr, width, height);

	assert(!cairo_status(cr));
}

void kmstest_paint_image(cairo_t *cr, const char *filename,
			 int dst_x, int dst_y, int dst_width, int dst_height)
{
	cairo_surface_t *image;
	int img_width, img_height;
	double scale_x, scale_y;

	image = cairo_image_surface_create_from_png(filename);
	assert(cairo_surface_status(image) == CAIRO_STATUS_SUCCESS);

	img_width = cairo_image_surface_get_width(image);
	img_height = cairo_image_surface_get_height(image);

	scale_x = (double)dst_width / img_width;
	scale_y = (double)dst_height / img_height;

	cairo_save(cr);

	cairo_translate(cr, dst_x, dst_y);
	cairo_scale(cr, scale_x, scale_y);
	cairo_set_source_surface(cr, image, 0, 0);
	cairo_paint(cr);

	cairo_surface_destroy(image);

	cairo_restore(cr);
}

#define DF(did, cid, _bpp, _depth)	\
	{ DRM_FORMAT_##did, CAIRO_FORMAT_##cid, # did, _bpp, _depth }
static struct format_desc_struct {
	uint32_t drm_id;
	cairo_format_t cairo_id;
	const char *name;
	int bpp;
	int depth;
} format_desc[] = {
	DF(RGB565,	RGB16_565,	16, 16),
	DF(RGB888,	INVALID,	24, 24),
	DF(XRGB8888,	RGB24,		32, 24),
	DF(XRGB2101010,	RGB30,		32, 30),
	DF(ARGB8888,	ARGB32,		32, 32),
};
#undef DF

#define for_each_format(f)	\
	for (f = format_desc; f - format_desc < ARRAY_SIZE(format_desc); f++)

static uint32_t bpp_depth_to_drm_format(int bpp, int depth)
{
	struct format_desc_struct *f;

	for_each_format(f)
		if (f->bpp == bpp && f->depth == depth)
			return f->drm_id;

	abort();
}

/* Return fb_id on success, 0 on error */
unsigned int kmstest_create_fb(int fd, int width, int height, int bpp,
			       int depth, bool tiled, struct kmstest_fb *fb)
{
	memset(fb, 0, sizeof(*fb));

	if (create_bo_for_fb(fd, width, height, bpp, tiled, &fb->gem_handle,
			       &fb->size, &fb->stride) < 0)
		return 0;

	if (drmModeAddFB(fd, width, height, depth, bpp, fb->stride,
			       fb->gem_handle, &fb->fb_id) < 0) {
		gem_close(fd, fb->gem_handle);

		return 0;
	}

	fb->width = width;
	fb->height = height;
	fb->tiling = tiled;
	fb->drm_format = bpp_depth_to_drm_format(bpp, depth);

	return fb->fb_id;
}

uint32_t drm_format_to_bpp(uint32_t drm_format)
{
	struct format_desc_struct *f;

	for_each_format(f)
		if (f->drm_id == drm_format)
			return f->bpp;

	abort();
}

unsigned int kmstest_create_fb2(int fd, int width, int height, uint32_t format,
			        bool tiled, struct kmstest_fb *fb)
{
	uint32_t handles[4];
	uint32_t pitches[4];
	uint32_t offsets[4];
	uint32_t fb_id;
	int bpp;
	int ret;

	memset(fb, 0, sizeof(*fb));

	bpp = drm_format_to_bpp(format);
	ret = create_bo_for_fb(fd, width, height, bpp, tiled, &fb->gem_handle,
			      &fb->size, &fb->stride);
	if (ret < 0)
		return ret;

	memset(handles, 0, sizeof(handles));
	handles[0] = fb->gem_handle;
	memset(pitches, 0, sizeof(pitches));
	pitches[0] = fb->stride;
	memset(offsets, 0, sizeof(offsets));
	if (drmModeAddFB2(fd, width, height, format, handles, pitches,
			  offsets, &fb_id, 0) < 0) {
		gem_close(fd, fb->gem_handle);

		return 0;
	}

	fb->width = width;
	fb->height = height;
	fb->tiling = tiled;
	fb->drm_format = format;
	fb->fb_id = fb_id;

	return fb_id;
}

unsigned int kmstest_create_color_fb(int fd, int width, int height,
				     uint32_t format, bool tiled,
				     double r, double g, double b,
				     struct kmstest_fb *fb /* out */)
{
	unsigned int fb_id;
	cairo_t *cr;

	fb_id = kmstest_create_fb2(fd, width, height, format, tiled, fb);
	igt_assert(fb_id);

	cr = kmstest_get_cairo_ctx(fd, fb);
	kmstest_paint_color(cr, 0, 0, width, height, r, g, b);
	igt_assert(cairo_status(cr) == 0);
	cairo_destroy(cr);

	return fb_id;
}

static cairo_format_t drm_format_to_cairo(uint32_t drm_format)
{
	struct format_desc_struct *f;

	for_each_format(f)
		if (f->drm_id == drm_format)
			return f->cairo_id;

	abort();
}

static void __kmstest_destroy_cairo_surface(void *arg)
{
	struct kmstest_fb *fb = arg;
	munmap(cairo_image_surface_get_data(fb->cairo_surface), fb->size);
}

cairo_surface_t *kmstest_get_cairo_surface(int fd, struct kmstest_fb *fb)
{
	if (fb->cairo_surface == NULL) {
		fb->cairo_surface =
			cairo_image_surface_create_for_data(gem_mmap(fd, fb->gem_handle, fb->size, PROT_READ | PROT_WRITE),
							    drm_format_to_cairo(fb->drm_format),
							    fb->width, fb->height, fb->stride);

		cairo_surface_set_user_data(fb->cairo_surface,
					    (cairo_user_data_key_t *)kmstest_get_cairo_surface,
					    fb, __kmstest_destroy_cairo_surface);
	}

	gem_set_domain(fd, fb->gem_handle,
		       I915_GEM_DOMAIN_CPU, I915_GEM_DOMAIN_CPU);

	igt_assert(cairo_surface_status(fb->cairo_surface) == CAIRO_STATUS_SUCCESS);
	return cairo_surface_reference(fb->cairo_surface);
}

cairo_t *kmstest_get_cairo_ctx(int fd, struct kmstest_fb *fb)
{
	cairo_surface_t *surface;
	cairo_t *cr;

	surface = kmstest_get_cairo_surface(fd, fb);
	cr = cairo_create(surface);
	cairo_surface_destroy(surface);

	igt_assert(cairo_status(cr) == CAIRO_STATUS_SUCCESS);

	return cr;
}

void kmstest_write_fb(int fd, struct kmstest_fb *fb, const char *filename)
{
	cairo_surface_t *surface;
	cairo_status_t status;

	surface = kmstest_get_cairo_surface(fd, fb);
	status = cairo_surface_write_to_png(surface, filename);
	cairo_surface_destroy(surface);

	igt_assert(status == CAIRO_STATUS_SUCCESS);
}

void kmstest_remove_fb(int fd, struct kmstest_fb *fb)
{
	cairo_surface_destroy(fb->cairo_surface);
	do_or_die(drmModeRmFB(fd, fb->fb_id));
	gem_close(fd, fb->gem_handle);
}

const char *kmstest_format_str(uint32_t drm_format)
{
	struct format_desc_struct *f;

	for_each_format(f)
		if (f->drm_id == drm_format)
			return f->name;

	return "invalid";
}

const char *kmstest_pipe_str(int pipe)
{
	const char *str[] = { "A", "B", "C" };

	if (pipe > 2)
		return "invalid";

	return str[pipe];
}

void kmstest_get_all_formats(const uint32_t **formats, int *format_count)
{
	static uint32_t *drm_formats;

	if (!drm_formats) {
		struct format_desc_struct *f;
		uint32_t *format;

		drm_formats = calloc(ARRAY_SIZE(format_desc),
				     sizeof(*drm_formats));
		format = &drm_formats[0];
		for_each_format(f)
			*format++ = f->drm_id;
	}

	*formats = drm_formats;
	*format_count = ARRAY_SIZE(format_desc);
}

struct type_name {
	int type;
	const char *name;
};

#define type_name_fn(res) \
const char * kmstest_##res##_str(int type) {		\
	unsigned int i;					\
	for (i = 0; i < ARRAY_SIZE(res##_names); i++) { \
		if (res##_names[i].type == type)	\
			return res##_names[i].name;	\
	}						\
	return "(invalid)";				\
}

struct type_name encoder_type_names[] = {
	{ DRM_MODE_ENCODER_NONE, "none" },
	{ DRM_MODE_ENCODER_DAC, "DAC" },
	{ DRM_MODE_ENCODER_TMDS, "TMDS" },
	{ DRM_MODE_ENCODER_LVDS, "LVDS" },
	{ DRM_MODE_ENCODER_TVDAC, "TVDAC" },
};

type_name_fn(encoder_type)

struct type_name connector_status_names[] = {
	{ DRM_MODE_CONNECTED, "connected" },
	{ DRM_MODE_DISCONNECTED, "disconnected" },
	{ DRM_MODE_UNKNOWNCONNECTION, "unknown" },
};

type_name_fn(connector_status)

struct type_name connector_type_names[] = {
	{ DRM_MODE_CONNECTOR_Unknown, "unknown" },
	{ DRM_MODE_CONNECTOR_VGA, "VGA" },
	{ DRM_MODE_CONNECTOR_DVII, "DVI-I" },
	{ DRM_MODE_CONNECTOR_DVID, "DVI-D" },
	{ DRM_MODE_CONNECTOR_DVIA, "DVI-A" },
	{ DRM_MODE_CONNECTOR_Composite, "composite" },
	{ DRM_MODE_CONNECTOR_SVIDEO, "s-video" },
	{ DRM_MODE_CONNECTOR_LVDS, "LVDS" },
	{ DRM_MODE_CONNECTOR_Component, "component" },
	{ DRM_MODE_CONNECTOR_9PinDIN, "9-pin DIN" },
	{ DRM_MODE_CONNECTOR_DisplayPort, "DP" },
	{ DRM_MODE_CONNECTOR_HDMIA, "HDMI-A" },
	{ DRM_MODE_CONNECTOR_HDMIB, "HDMI-B" },
	{ DRM_MODE_CONNECTOR_TV, "TV" },
	{ DRM_MODE_CONNECTOR_eDP, "eDP" },
};

type_name_fn(connector_type)

static const char *mode_stereo_name(const drmModeModeInfo *mode)
{
	switch (mode->flags & DRM_MODE_FLAG_3D_MASK) {
	case DRM_MODE_FLAG_3D_FRAME_PACKING:
		return "FP";
	case DRM_MODE_FLAG_3D_FIELD_ALTERNATIVE:
		return "FA";
	case DRM_MODE_FLAG_3D_LINE_ALTERNATIVE:
		return "LA";
	case DRM_MODE_FLAG_3D_SIDE_BY_SIDE_FULL:
		return "SBSF";
	case DRM_MODE_FLAG_3D_L_DEPTH:
		return "LD";
	case DRM_MODE_FLAG_3D_L_DEPTH_GFX_GFX_DEPTH:
		return "LDGFX";
	case DRM_MODE_FLAG_3D_TOP_AND_BOTTOM:
		return "TB";
	case DRM_MODE_FLAG_3D_SIDE_BY_SIDE_HALF:
		return "SBSH";
	default:
		return NULL;
	}
}

void kmstest_dump_mode(drmModeModeInfo *mode)
{
	const char *stereo = mode_stereo_name(mode);

	printf("  %s %d %d %d %d %d %d %d %d %d 0x%x 0x%x %d%s%s%s\n",
	       mode->name,
	       mode->vrefresh,
	       mode->hdisplay,
	       mode->hsync_start,
	       mode->hsync_end,
	       mode->htotal,
	       mode->vdisplay,
	       mode->vsync_start,
	       mode->vsync_end,
	       mode->vtotal,
	       mode->flags,
	       mode->type,
	       mode->clock,
	       stereo ? " (3D:" : "",
	       stereo ? stereo : "",
	       stereo ? ")" : "");
	fflush(stdout);
}

int kmstest_get_pipe_from_crtc_id(int fd, int crtc_id)
{
	struct drm_i915_get_pipe_from_crtc_id pfci;
	int ret;

	memset(&pfci, 0, sizeof(pfci));
	pfci.crtc_id = crtc_id;
	ret = drmIoctl(fd, DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID, &pfci);
	igt_assert(ret == 0);

	return pfci.pipe;
}

static signed long set_vt_mode(unsigned long mode)
{
	int fd;
	unsigned long prev_mode;

	fd = open("/dev/tty0", O_RDONLY);
	if (fd < 0)
		return -errno;

	prev_mode = 0;
	if (drmIoctl(fd, KDGETMODE, &prev_mode))
		goto err;
	if (drmIoctl(fd, KDSETMODE, (void *)mode))
		goto err;

	close(fd);

	return prev_mode;
err:
	close(fd);

	return -errno;
}

static unsigned long orig_vt_mode = -1UL;

static void restore_vt_mode_at_exit(int sig)
{
	if (orig_vt_mode != -1UL)
		set_vt_mode(orig_vt_mode);
}

/*
 * Set the VT to graphics mode and install an exit handler to restore the
 * original mode.
 */

void igt_set_vt_graphics_mode(void)
{
	long ret;

	igt_install_exit_handler(restore_vt_mode_at_exit);

	igt_disable_exit_handler();
	ret = set_vt_mode(KD_GRAPHICS);
	igt_enable_exit_handler();

	igt_assert(ret >= 0);
	orig_vt_mode = ret;
}

int kmstest_get_connector_default_mode(int drm_fd, drmModeConnector *connector,
				      drmModeModeInfo *mode)
{
	drmModeRes *resources;
	int i;

	resources = drmModeGetResources(drm_fd);
	if (!resources) {
		perror("drmModeGetResources failed");

		return -1;
	}

	if (!connector->count_modes) {
		fprintf(stderr, "no modes for connector %d\n",
			connector->connector_id);
		drmModeFreeResources(resources);

		return -1;
	}

	for (i = 0; i < connector->count_modes; i++) {
		if (i == 0 ||
		    connector->modes[i].type & DRM_MODE_TYPE_PREFERRED) {
			*mode = connector->modes[i];
			if (mode->type & DRM_MODE_TYPE_PREFERRED)
				break;
		}
	}

	drmModeFreeResources(resources);

	return 0;
}

int kmstest_get_connector_config(int drm_fd, uint32_t connector_id,
				 unsigned long crtc_idx_mask,
				 struct kmstest_connector_config *config)
{
	drmModeRes *resources;
	drmModeConnector *connector;
	drmModeEncoder *encoder;
	int i, j;

	resources = drmModeGetResources(drm_fd);
	if (!resources) {
		perror("drmModeGetResources failed");
		goto err1;
	}

	/* First, find the connector & mode */
	connector = drmModeGetConnector(drm_fd, connector_id);
	if (!connector)
		goto err2;

	if (connector->connection != DRM_MODE_CONNECTED)
		goto err3;

	if (!connector->count_modes) {
		fprintf(stderr, "connector %d has no modes\n", connector_id);
		goto err3;
	}

	if (connector->connector_id != connector_id) {
		fprintf(stderr, "connector id doesn't match (%d != %d)\n",
			connector->connector_id, connector_id);
		goto err3;
	}

	/*
	 * Find given CRTC if crtc_id != 0 or else the first CRTC not in use.
	 * In both cases find the first compatible encoder and skip the CRTC
	 * if there is non such.
	 */
	encoder = NULL;		/* suppress GCC warning */
	for (i = 0; i < resources->count_crtcs; i++) {
		if (!resources->crtcs[i] || !(crtc_idx_mask & (1 << i)))
			continue;

		/* Now get a compatible encoder */
		for (j = 0; j < connector->count_encoders; j++) {
			encoder = drmModeGetEncoder(drm_fd,
						    connector->encoders[j]);

			if (!encoder) {
				fprintf(stderr, "could not get encoder %d: %s\n",
					resources->encoders[j], strerror(errno));

				continue;
			}

			if (encoder->possible_crtcs & (1 << i))
				goto found;

			drmModeFreeEncoder(encoder);
		}
	}

	goto err3;

found:
	if (kmstest_get_connector_default_mode(drm_fd, connector,
				       &config->default_mode) < 0)
		goto err4;

	config->connector = connector;
	config->encoder = encoder;
	config->crtc = drmModeGetCrtc(drm_fd, resources->crtcs[i]);
	config->crtc_idx = i;
	config->pipe = kmstest_get_pipe_from_crtc_id(drm_fd,
						     config->crtc->crtc_id);

	drmModeFreeResources(resources);

	return 0;
err4:
	drmModeFreeEncoder(encoder);
err3:
	drmModeFreeConnector(connector);
err2:
	drmModeFreeResources(resources);
err1:
	return -1;
}

void kmstest_free_connector_config(struct kmstest_connector_config *config)
{
	drmModeFreeCrtc(config->crtc);
	drmModeFreeEncoder(config->encoder);
	drmModeFreeConnector(config->connector);
}

const char *plane_name(enum igt_plane p)
{
	static const char *names[] = {
		[IGT_PLANE_1] = "plane1",
		[IGT_PLANE_2] = "plane2",
		[IGT_PLANE_3] = "plane3",
		[IGT_PLANE_CURSOR] = "cursor",
	};

	igt_assert(p < ARRAY_SIZE(names) && names[p]);

	return names[p];
}

/*
 * A small modeset API
 */

#define LOG_SPACES		"    "
#define LOG_N_SPACES		(sizeof(LOG_SPACES) - 1)

#define LOG_INDENT(d, section)				\
	do {						\
		igt_display_log(d, "%s {\n", section);	\
		igt_display_log_shift(d, 1);		\
	} while (0)
#define LOG_UNINDENT(d)					\
	do {						\
		igt_display_log_shift(d, -1);		\
		igt_display_log(d, "}\n");		\
	} while (0)
#define LOG(d, fmt, ...)	igt_display_log(d, fmt, ## __VA_ARGS__)

static int  __attribute__((format(printf, 2, 3)))
igt_display_log(igt_display_t *display, const char *fmt, ...)
{
	va_list args;
	int n, i;

	if (igt_log_level > IGT_LOG_DEBUG)
		return 0;

	va_start(args, fmt);
	n = printf("display: ");
	for (i = 0; i < display->log_shift; i++)
		n += printf("%s", LOG_SPACES);
	n += vprintf(fmt, args);
	va_end(args);

	return n;
}

static void igt_display_log_shift(igt_display_t *display, int shift)
{
	display->log_shift += shift;
	igt_assert(display->log_shift >= 0);
}

static void igt_output_refresh(igt_output_t *output)
{
	igt_display_t *display = output->display;
	int ret;
	unsigned long crtc_idx_mask;

	/* we mask out the pipes already in use */
	crtc_idx_mask = output->pending_crtc_idx_mask & ~display->pipes_in_use;

	if (output->valid)
		kmstest_free_connector_config(&output->config);
	ret = kmstest_get_connector_config(display->drm_fd,
					   output->id,
					   crtc_idx_mask,
					   &output->config);
	if (ret == 0)
		output->valid = true;
	else
		output->valid = false;

	if (!output->valid)
		return;

	if (!output->name) {
		drmModeConnector *c = output->config.connector;

		asprintf(&output->name, "%s-%d",
			 kmstest_connector_type_str(c->connector_type),
			 c->connector_type_id);
	}

	LOG(display, "%s: Selecting pipe %c\n", output->name,
	    pipe_name(output->config.pipe));

	display->pipes_in_use |= 1 << output->config.pipe;
}

void igt_display_init(igt_display_t *display, int drm_fd)
{
	drmModeRes *resources;
	drmModePlaneRes *plane_resources;
	int i;

	LOG_INDENT(display, "init");

	display->drm_fd = drm_fd;

	resources = drmModeGetResources(display->drm_fd);
	igt_assert(resources);

	/*
	 * We cache the number of pipes, that number is a physical limit of the
	 * hardware and cannot change of time (for now, at least).
	 */
	display->n_pipes = resources->count_crtcs;

	plane_resources = drmModeGetPlaneResources(display->drm_fd);
	igt_assert(plane_resources);

	for (i = 0; i < display->n_pipes; i++) {
		igt_pipe_t *pipe = &display->pipes[i];
		igt_plane_t *plane;
		int p, j;

		pipe->display = display;
		pipe->pipe = i;

		/* primary plane */
		p = IGT_PLANE_PRIMARY;
		plane = &pipe->planes[p];
		plane->pipe = pipe;
		plane->index = p;
		plane->is_primary = true;

		/* add the planes that can be used with that pipe */
		for (j = 0; j < plane_resources->count_planes; j++) {
			drmModePlane *drm_plane;

			drm_plane = drmModeGetPlane(display->drm_fd,
						    plane_resources->planes[j]);
			igt_assert(drm_plane);

			if (!(drm_plane->possible_crtcs & (1 << i))) {
				drmModeFreePlane(drm_plane);
				continue;
			}

			p++;
			plane = &pipe->planes[p];
			plane->pipe = pipe;
			plane->index = p;
			plane->drm_plane = drm_plane;
		}

		/* cursor plane */
		p++;
		plane = &pipe->planes[p];
		plane->pipe = pipe;
		plane->index = p;
		plane->is_cursor = true;

		pipe->n_planes = ++p;

		/* make sure we don't overflow the plane array */
		igt_assert(pipe->n_planes <= IGT_MAX_PLANES);
	}

	/*
	 * The number of connectors is set, so we just initialize the outputs
	 * array in _init(). This may change when we need dynamic connectors
	 * (say DisplayPort MST).
	 */
	display->n_outputs = resources->count_connectors;
	display->outputs = calloc(display->n_outputs, sizeof(igt_output_t));
	igt_assert(display->outputs);

	for (i = 0; i < display->n_outputs; i++) {
		igt_output_t *output = &display->outputs[i];

		/*
		 * We're free to select any pipe to drive that output until
		 * a constraint is set with igt_output_set_pipe().
		 */
		output->pending_crtc_idx_mask = -1UL;
		output->id = resources->connectors[i];
		output->display = display;

		igt_output_refresh(output);
	}

	drmModeFreePlaneResources(plane_resources);
	drmModeFreeResources(resources);

	LOG_UNINDENT(display);
}

int igt_display_get_n_pipes(igt_display_t *display)
{
	return display->n_pipes;
}

static void igt_pipe_fini(igt_pipe_t *pipe)
{
	int i;

	for (i = 0; i < pipe->n_planes; i++) {
		igt_plane_t *plane = &pipe->planes[i];

		if (plane->drm_plane) {
			drmModeFreePlane(plane->drm_plane);
			plane->drm_plane = NULL;
		}
	}
}

static void igt_output_fini(igt_output_t *output)
{
	if (output->valid)
		kmstest_free_connector_config(&output->config);
	free(output->name);
}

void igt_display_fini(igt_display_t *display)
{
	int i;

	for (i = 0; i < display->n_pipes; i++)
		igt_pipe_fini(&display->pipes[i]);

	for (i = 0; i < display->n_outputs; i++)
		igt_output_fini(&display->outputs[i]);
	free(display->outputs);
	display->outputs = NULL;
}

static void igt_display_refresh(igt_display_t *display)
{
	int i, j;

	display->pipes_in_use = 0;

       /* Check that two outputs aren't trying to use the same pipe */
        for (i = 0; i < display->n_outputs; i++) {
                igt_output_t *a = &display->outputs[i];

                if (a->pending_crtc_idx_mask == -1UL)
                        continue;

                for (j = 0; j < display->n_outputs; j++) {
                        igt_output_t *b = &display->outputs[j];

                        if (i == j)
                                continue;

                        if (b->pending_crtc_idx_mask == -1UL)
                                continue;

                        igt_assert_f(a->pending_crtc_idx_mask !=
                                     b->pending_crtc_idx_mask,
                                     "%s and %s are both trying to use pipe %c\n",
                                     igt_output_name(a), igt_output_name(b),
                                     pipe_name(ffs(a->pending_crtc_idx_mask) - 1));
                }
        }

	/*
	 * The pipe allocation has to be done in two phases:
	 *   - first, try to satisfy the outputs where a pipe has been specified
	 *   - then, allocate the outputs with PIPE_ANY
	 */
	for (i = 0; i < display->n_outputs; i++) {
		igt_output_t *output = &display->outputs[i];

		if (output->pending_crtc_idx_mask == -1UL)
			continue;

		igt_output_refresh(output);
	}
	for (i = 0; i < display->n_outputs; i++) {
		igt_output_t *output = &display->outputs[i];

		if (output->pending_crtc_idx_mask != -1UL)
			continue;

		igt_output_refresh(output);
	}
}

static igt_pipe_t *igt_output_get_driving_pipe(igt_output_t *output)
{
	igt_display_t *display = output->display;
	enum pipe pipe;

	if (output->pending_crtc_idx_mask == -1UL) {
		/*
		 * The user hasn't specified a pipe to use, take the one
		 * configured by the last refresh()
		 */
		pipe = output->config.pipe;
	} else {
		/*
		 * Otherwise, return the pending pipe (ie the pipe that should
		 * drive this output after the commit()
		 */
		pipe = ffs(output->pending_crtc_idx_mask) - 1;
	}

	igt_assert(pipe >= 0 && pipe < display->n_pipes);

	return &display->pipes[pipe];
}

static igt_plane_t *igt_pipe_get_plane(igt_pipe_t *pipe, enum igt_plane plane)
{
	int idx;

	/* Cursor plane is always the upper plane */
	if (plane == IGT_PLANE_CURSOR)
		idx = pipe->n_planes - 1;
	else {
		igt_assert_f(plane >= 0 && plane < (pipe->n_planes),
			     "plane=%d\n", plane);
		idx = plane;
	}

	return &pipe->planes[idx];
}

static uint32_t igt_plane_get_fb_id(igt_plane_t *plane)
{
	if (plane->fb)
		return plane->fb->fb_id;
	else
		return 0;
}

static uint32_t igt_plane_get_fb_gem_handle(igt_plane_t *plane)
{
	if (plane->fb)
		return plane->fb->gem_handle;
	else
		return 0;
}

static int igt_cursor_commit(igt_plane_t *plane, igt_output_t *output)
{
	igt_display_t *display = output->display;
	uint32_t crtc_id = output->config.crtc->crtc_id;
	int ret;

	if (plane->position_changed) {
		int x = plane->crtc_x;
		int y = plane->crtc_y;

		LOG(display,
		    "%s: MoveCursor pipe %c, (%d, %d)\n",
		    igt_output_name(output),
		    pipe_name(output->config.pipe),
		    x, y);

		ret = drmModeMoveCursor(display->drm_fd, crtc_id, x, y);

		igt_assert(ret == 0);

		plane->position_changed = false;
	}

	return 0;
}

static int igt_drm_plane_commit(igt_plane_t *plane, igt_output_t *output)
{
	igt_display_t *display = output->display;
	igt_pipe_t *pipe;
	uint32_t fb_id, crtc_id;
	int ret;

	fb_id = igt_plane_get_fb_id(plane);
	crtc_id = output->config.crtc->crtc_id;
	pipe = igt_output_get_driving_pipe(output);

	if (plane->fb_changed && fb_id == 0) {
		LOG(display,
		    "%s: SetPlane pipe %c, plane %d, disabling\n",
		    igt_output_name(output),
		    pipe_name(output->config.pipe),
		    plane->index);

		ret = drmModeSetPlane(display->drm_fd,
				      plane->drm_plane->plane_id,
				      crtc_id,
				      fb_id,
				      0,    /* flags */
				      0, 0, /* crtc_x, crtc_y */
				      0, 0, /* crtc_w, crtc_h */
				      IGT_FIXED(0,0), /* src_x */
				      IGT_FIXED(0,0), /* src_y */
				      IGT_FIXED(0,0), /* src_w */
				      IGT_FIXED(0,0) /* src_h */);

		igt_assert(ret == 0);

		plane->fb_changed = false;
	} else if (plane->fb_changed || plane->position_changed) {
		LOG(display,
		    "%s: SetPlane %c.%d, fb %u, position (%d, %d)\n",
		    igt_output_name(output),
		    pipe_name(output->config.pipe),
		    plane->index,
		    fb_id,
		    plane->crtc_x, plane->crtc_y);

		ret = drmModeSetPlane(display->drm_fd,
				      plane->drm_plane->plane_id,
				      crtc_id,
				      fb_id,
				      0,    /* flags */
				      plane->crtc_x, plane->crtc_y,
				      plane->fb->width, plane->fb->height,
				      IGT_FIXED(0,0), /* src_x */
				      IGT_FIXED(0,0), /* src_y */
				      IGT_FIXED(plane->fb->width,0), /* src_w */
				      IGT_FIXED(plane->fb->height,0) /* src_h */);

		igt_assert(ret == 0);

		plane->fb_changed = false;
		plane->position_changed = false;
		pipe->need_wait_for_vblank = true;
	}

	return 0;
}

static int igt_plane_commit(igt_plane_t *plane, igt_output_t *output)
{
	if (plane->is_cursor) {
		igt_cursor_commit(plane, output);
	} else if (plane->is_primary) {
		/* state updated by SetCrtc */
	} else {
		igt_drm_plane_commit(plane, output);
	}

	return 0;
}

static int igt_output_commit(igt_output_t *output)
{
	igt_display_t *display = output->display;
	igt_pipe_t *pipe;
	int i;

	pipe = igt_output_get_driving_pipe(output);
	if (pipe->need_set_crtc) {
		igt_plane_t *primary = &pipe->planes[0];
		drmModeModeInfo *mode;
		uint32_t fb_id, crtc_id;
		int ret;

		crtc_id = output->config.crtc->crtc_id;
		fb_id = igt_plane_get_fb_id(primary);
		if (fb_id)
			mode = igt_output_get_mode(output);
		else
			mode = NULL;

		if (fb_id) {
			LOG(display,
			    "%s: SetCrtc pipe %c, fb %u, panning (%d, %d), "
			    "mode %dx%d\n",
			    igt_output_name(output),
			    pipe_name(output->config.pipe),
			    fb_id,
			    0, 0,
			    mode->hdisplay, mode->vdisplay);

			ret = drmModeSetCrtc(display->drm_fd,
					     crtc_id,
					     fb_id,
					     0, 0, /* x, y */
					     &output->id,
					     1,
					     mode);
		} else {
			LOG(display,
			    "%s: SetCrtc pipe %c, disabling\n",
			    igt_output_name(output),
			    pipe_name(output->config.pipe));

			ret = drmModeSetCrtc(display->drm_fd,
					     crtc_id,
					     fb_id,
					     0, 0, /* x, y */
					     NULL, /* connectors */
					     0,    /* n_connectors */
					     NULL  /* mode */);
		}

		igt_assert(ret == 0);

		pipe->need_set_crtc = false;
		primary->fb_changed = false;
	}

	if (pipe->need_set_cursor) {
		igt_plane_t *cursor;
		uint32_t gem_handle, crtc_id;
		int ret;

		cursor = igt_pipe_get_plane(pipe, IGT_PLANE_CURSOR);
		crtc_id = output->config.crtc->crtc_id;
		gem_handle = igt_plane_get_fb_gem_handle(cursor);

		if (gem_handle) {
			LOG(display,
			    "%s: SetCursor pipe %c, fb %u %dx%d\n",
			    igt_output_name(output),
			    pipe_name(output->config.pipe),
			    gem_handle,
			    cursor->fb->width, cursor->fb->height);

			ret = drmModeSetCursor(display->drm_fd, crtc_id,
					       gem_handle,
					       cursor->fb->width,
					       cursor->fb->height);
		} else {
			LOG(display,
			    "%s: SetCursor pipe %c, disabling\n",
			    igt_output_name(output),
			    pipe_name(output->config.pipe));

			ret = drmModeSetCursor(display->drm_fd, crtc_id,
					       0, 0, 0);
		}

		igt_assert(ret == 0);

		pipe->need_set_cursor = false;
		cursor->fb_changed = false;
	}

	for (i = 0; i < pipe->n_planes; i++) {
		igt_plane_t *plane = &pipe->planes[i];

		igt_plane_commit(plane, output);
	}

	if (pipe->need_wait_for_vblank) {
		igt_wait_for_vblank(display->drm_fd, pipe->pipe);
		pipe->need_wait_for_vblank = false;
	}

	return 0;
}

int igt_display_commit(igt_display_t *display)
{
	int i;

	LOG_INDENT(display, "commit");

	igt_display_refresh(display);

	for (i = 0; i < display->n_outputs; i++) {
		igt_output_t *output = &display->outputs[i];

		if (!output->valid)
			continue;

		igt_output_commit(output);
	}

	LOG_UNINDENT(display);

	if (getenv("IGT_DISPLAY_WAIT_AT_COMMIT"))
		igt_wait_for_keypress();

	return 0;
}

const char *igt_output_name(igt_output_t *output)
{
	return output->name;
}

drmModeModeInfo *igt_output_get_mode(igt_output_t *output)
{
	return &output->config.default_mode;
}

void igt_output_set_pipe(igt_output_t *output, enum pipe pipe)
{
	igt_display_t *display = output->display;

	if (pipe == PIPE_ANY) {
		LOG(display, "%s: set_pipe(any)\n", igt_output_name(output));
		output->pending_crtc_idx_mask = -1UL;
	} else {
		LOG(display, "%s: set_pipe(%c)\n", igt_output_name(output),
		    pipe_name(pipe));
		output->pending_crtc_idx_mask = 1 << pipe;
	}
}

igt_plane_t *igt_output_get_plane(igt_output_t *output, enum igt_plane plane)
{
	igt_pipe_t *pipe;

	pipe = igt_output_get_driving_pipe(output);
	return igt_pipe_get_plane(pipe, plane);
}

void igt_plane_set_fb(igt_plane_t *plane, struct kmstest_fb *fb)
{
	igt_pipe_t *pipe = plane->pipe;
	igt_display_t *display = pipe->display;

	LOG(display, "%c.%d: plane_set_fb(%d)\n", pipe_name(pipe->pipe),
	    plane->index, fb ? fb->fb_id : 0);

	plane->fb = fb;

	if (plane->is_primary)
		pipe->need_set_crtc = true;
	else if (plane->is_cursor)
		pipe->need_set_cursor = true;

	plane->fb_changed = true;
}

void igt_plane_set_position(igt_plane_t *plane, int x, int y)
{
	igt_pipe_t *pipe = plane->pipe;
	igt_display_t *display = pipe->display;

	/*
	 * XXX: Some platforms don't need the primary plane to cover the
	 * whole pipe. Of course this test becomes wrong when we support that.
	 */
	igt_assert(!plane->is_primary || (x == 0 && y == 0));

	LOG(display, "%c.%d: plane_set_position(%d,%d)\n",
	    pipe_name(pipe->pipe), plane->index, x, y);

	plane->crtc_x = x;
	plane->crtc_y = y;

	plane->position_changed = true;
}
