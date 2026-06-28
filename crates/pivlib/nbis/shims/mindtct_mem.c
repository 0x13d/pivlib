/*
 * mindtct_mem.c — in-memory fingerprint minutiae extraction.
 *
 * lfs_detect_minutiae_V2() works directly on a raw pixel buffer,
 * so NO file I/O patch is needed for minutiae extraction.
 *
 * Actual signature (from lfs.h):
 *
 *   int lfs_detect_minutiae_V2(
 *       MINUTIAE        **ominutiae,
 *       int             **odmap,      // direction map
 *       int             **olmmap,     // low-flow map
 *       int             **ohmap,      // high-curve map
 *       int             **oqmap,      // quality map
 *       int              *omw,        // map width  (blocks)
 *       int              *omh,        // map height (blocks)
 *       unsigned char   **obdata,     // blocked image
 *       int              *obw,        // blocked image width
 *       int              *obh,        // blocked image height
 *       unsigned char    *idata,      // input pixels (writable copy)
 *       const int         iw,
 *       const int         ih,
 *       const LFSPARMS   *lfsparms);
 */

#include "mindtct_mem.h"
#include "lfs.h"
#include <stdlib.h>
#include <string.h>

int mindtct_mem(const unsigned char *idata,
                int iwidth, int iheight,
                MinutiaePoint **out_points, int *out_count)
{
    if (!idata || iwidth <= 0 || iheight <= 0 || !out_points || !out_count)
        return -1;

    *out_points = NULL;
    *out_count  = 0;

    /* LFS requires a writable pixel buffer */
    unsigned char *pixels = (unsigned char *)malloc((size_t)iwidth * iheight);
    if (!pixels)
        return -2;
    memcpy(pixels, idata, (size_t)iwidth * iheight);

    /* LFS output buffers */
    MINUTIAE      *minutiae = NULL;
    int           *dmap     = NULL;   /* direction map   */
    int           *lmmap    = NULL;   /* low-flow map    */
    int           *hmap     = NULL;   /* high-curve map  */
    int           *qmap     = NULL;   /* quality map     */
    int            mw = 0,  mh = 0;  /* map dimensions  */
    unsigned char *bdata    = NULL;   /* blocked image   */
    int            bw = 0,  bh = 0;  /* block dimensions*/

    int ret = lfs_detect_minutiae_V2(
                  &minutiae,
                  &dmap, &lmmap, &hmap, &qmap,
                  &mw, &mh,
                  &bdata, &bw, &bh,
                  pixels, iwidth, iheight,
                  &lfsparms_V2);

    free(pixels);

    if (ret != 0) {
        if (dmap)  free(dmap);
        if (lmmap) free(lmmap);
        if (hmap)  free(hmap);
        if (qmap)  free(qmap);
        if (bdata) free(bdata);
        return ret;
    }

    int n = minutiae->num;
    MinutiaePoint *pts = NULL;

    if (n > 0) {
        pts = (MinutiaePoint *)malloc((size_t)n * sizeof(MinutiaePoint));
        if (!pts) {
            free_minutiae(minutiae);
            free(dmap); free(lmmap); free(hmap); free(qmap); free(bdata);
            return -3;
        }

        for (int i = 0; i < n; i++) {
            MINUTIA *m = minutiae->list[i];
            pts[i].x            = m->x;
            pts[i].y            = m->y;
            pts[i].direction    = (unsigned char)m->direction;
            /* reliability is 0.0–1.0; scale to INCITS 378 quality 0–100 */
            pts[i].quality      = (unsigned char)(m->reliability * 100.0 + 0.5);
            pts[i].minutia_type = (unsigned char)m->type;
        }
    }

    *out_points = pts;
    *out_count  = n;

    free_minutiae(minutiae);
    free(dmap); free(lmmap); free(hmap); free(qmap); free(bdata);
    return 0;
}

void mindtct_mem_free(MinutiaePoint *points) {
    free(points);
}
