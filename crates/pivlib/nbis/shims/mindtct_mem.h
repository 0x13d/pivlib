/*
 * mindtct_mem.h — FFI-safe header for Rust to include when linking mindtct_mem.c
 */

#ifndef MINDTCT_MEM_H
#define MINDTCT_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flat, FFI-safe minutia record.
 * Mirrors the Minutia struct in src/finger/incits378.rs.
 */
typedef struct {
    int           x;            /* pixel column */
    int           y;            /* pixel row    */
    unsigned char direction;    /* NBIS 1-degree steps (0-255) */
    unsigned char quality;      /* 0-100 */
    unsigned char minutia_type; /* 1 = ridge ending, 2 = bifurcation */
} MinutiaePoint;

/*
 * Run LFS minutiae detection on a raw 8-bit grayscale pixel buffer.
 * Returns 0 on success.  *out_points is malloc'd; free with mindtct_mem_free().
 */
/*
 * idata / iwidth / iheight — 8-bit grayscale pixel buffer from WSQ decode.
 * Calibrated for 500 ppi (lfsparms_V2 defaults). Pass a 500 ppi image.
 */
int mindtct_mem(const unsigned char *idata,
                int iwidth, int iheight,
                MinutiaePoint **out_points, int *out_count);

void mindtct_mem_free(MinutiaePoint *points);

#ifdef __cplusplus
}
#endif

#endif /* MINDTCT_MEM_H */
