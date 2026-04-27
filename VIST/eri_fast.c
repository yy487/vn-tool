/*
 * eri_fast.c - C加速模块：ERI gamma解码 + 像素重建
 * 编译: gcc -O2 -shared -fPIC -o eri_fast.so eri_fast.c
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ─── Bit Reader ─── */
typedef struct {
    const uint8_t *data;
    int pos;          /* byte offset */
    int data_len;
    uint32_t buffer;
    int bits_left;
} BitReader;

static inline void br_fill(BitReader *br) {
    uint32_t w = 0;
    if (br->pos + 4 <= br->data_len) {
        memcpy(&w, br->data + br->pos, 4);
        br->pos += 4;
    } else {
        uint8_t tmp[4] = {0,0,0,0};
        int remain = br->data_len - br->pos;
        if (remain > 0) memcpy(tmp, br->data + br->pos, remain);
        memcpy(&w, tmp, 4);
        br->pos = br->data_len;
    }
    /* LE -> byte-swap to BE bit order */
    br->buffer = ((w >> 24) & 0xFF) | ((w >> 8) & 0xFF00) |
                 ((w << 8) & 0xFF0000) | ((w << 24) & 0xFF000000u);
    br->bits_left = 32;
}

static inline void br_init(BitReader *br, const uint8_t *data, int len) {
    br->data = data;
    br->pos = 0;
    br->data_len = len;
    br->buffer = 0;
    br->bits_left = 0;
    br_fill(br);
}

static inline int br_get_bit(BitReader *br) {
    int bit = (br->buffer >> 31) & 1;
    br->buffer <<= 1;
    if (--br->bits_left == 0) br_fill(br);
    return bit;
}

static inline int br_read_gamma(BitReader *br) {
    int value = 0, base = 2;
    for (;;) {
        int bit = (br->buffer >> 31) & 1;
        br->buffer <<= 1;
        if (--br->bits_left == 0) br_fill(br);
        if (bit == 0) {
            int fb = (br->buffer >> 31) & 1;
            br->buffer <<= 1;
            if (--br->bits_left == 0) br_fill(br);
            return value * 2 + fb + base - 1;
        } else {
            int db = (br->buffer >> 31) & 1;
            br->buffer <<= 1;
            if (--br->bits_left == 0) br_fill(br);
            value = value * 2 + db;
            base *= 2;
        }
    }
}

/* ─── ERI RunLength Gamma Decoder ─── */
int decode_eri_gamma_c(
    const uint8_t *comp_data, int comp_len,
    int32_t *output, int output_count)
{
    BitReader br;
    br_init(&br, comp_data, comp_len);

    memset(output, 0, output_count * sizeof(int32_t));
    int out_pos = 0;
    int phase_nonzero = br_get_bit(&br);

    while (out_pos < output_count) {
        if (phase_nonzero) {
            int count = br_read_gamma(&br);
            int end = out_pos + count;
            if (end > output_count) end = output_count;
            while (out_pos < end) {
                int sign = br_get_bit(&br);
                int mag = br_read_gamma(&br);
                output[out_pos++] = sign ? -mag : mag;
            }
        } else {
            int count = br_read_gamma(&br);
            int end = out_pos + count;
            if (end > output_count) end = output_count;
            /* zeros already set by memset */
            out_pos = end;
        }
        phase_nonzero = !phase_nonzero;
    }
    return output_count;
}

/* ─── Pixel Reconstruction (planar coefficients, delta coding) ─── */
void reconstruct_pixels_c(
    const int32_t *coefficients,
    uint8_t *pixels,
    int width, int height, int channels)
{
    int stride = width * channels;

    for (int ch = 0; ch < channels; ch++) {
        /* Row 0: horizontal accumulation */
        uint8_t acc = 0;
        for (int x = 0; x < width; x++) {
            int ci = ch * width + x;
            acc = (acc + (uint8_t)coefficients[ci]) & 0xFF;
            pixels[x * channels + ch] = acc;
        }
        /* Row 1+: horizontal accumulation + vertical prediction */
        for (int y = 1; y < height; y++) {
            acc = 0;
            for (int x = 0; x < width; x++) {
                int ci = y * stride + ch * width + x;
                uint8_t above = pixels[(y - 1) * stride + x * channels + ch];
                acc = (acc + (uint8_t)coefficients[ci]) & 0xFF;
                pixels[y * stride + x * channels + ch] = (above + acc) & 0xFF;
            }
        }
    }
}

/* ─── BGR bottom-up → RGB top-down conversion ─── */
void bgr_flip_to_rgb(
    const uint8_t *src, uint8_t *dst,
    int width, int height, int channels)
{
    int stride = width * channels;
    if (channels == 3) {
        for (int y = 0; y < height; y++) {
            int src_y = height - 1 - y;
            const uint8_t *sp = src + src_y * stride;
            uint8_t *dp = dst + y * width * 3;
            for (int x = 0; x < width; x++) {
                dp[x*3]     = sp[x*3+2]; /* R */
                dp[x*3+1]   = sp[x*3+1]; /* G */
                dp[x*3+2]   = sp[x*3];   /* B */
            }
        }
    } else if (channels == 4) {
        for (int y = 0; y < height; y++) {
            int src_y = height - 1 - y;
            const uint8_t *sp = src + src_y * stride;
            uint8_t *dp = dst + y * width * 4;
            for (int x = 0; x < width; x++) {
                dp[x*4]     = sp[x*4+2];
                dp[x*4+1]   = sp[x*4+1];
                dp[x*4+2]   = sp[x*4];
                dp[x*4+3]   = sp[x*4+3];
            }
        }
    } else if (channels == 1) {
        for (int y = 0; y < height; y++) {
            int src_y = height - 1 - y;
            memcpy(dst + y * width, src + src_y * width, width);
        }
    }
}
