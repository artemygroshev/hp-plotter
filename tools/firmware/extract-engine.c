/* Offline CAB stream inspection only. Never executes the updater or contacts a printer.
 * Uses installed libmspack with its default strict MSZIP checks (no repair).
 * For MSI Compound archives, first reconstruct Data1.cab with a Compound reader.
 */
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "mspack.h"
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned char signature[4];
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 7;
    size_t read_count = fread(signature, 1, sizeof(signature), input);
    fclose(input);
    if (read_count != 4 || memcmp(signature, "MSCF", 4) != 0) {
        puts("input_must_be_an_extracted_CAB_stream_not_an_EXE_or_MSI");
        return 7;
    }
    struct mscab_decompressor *d = mspack_create_cab_decompressor(NULL);
    if (!d) return 3;
    struct mscabd_cabinet *root = d->open(d, argv[1]);
    if (!root) { printf("search_error=%d\n", d->last_error(d));
        mspack_destroy_cab_decompressor(d); return 4; }
    int found = 0, failed = 0;
    for (struct mscabd_cabinet *c = root; c; c = c->next) {
        printf("cab_offset=%lld length=%u\n", (long long)c->base_offset, c->length);
        for (struct mscabd_file *f = c->files; f; f = f->next) {
            if (strcmp(f->filename, "DJ500_A.04.02.fmw") != 0) continue;
            found++;
            printf("engine_name=%s listed_bytes=%u\n", f->filename, f->length);
            int rc = d->extract(d, f, argv[2]);
            printf("strict_extract_rc=%d\n", rc);
            if (rc) failed = 1;
        }
    }
    d->close(d, root);
    mspack_destroy_cab_decompressor(d);
    return failed ? 5 : found == 1 ? 0 : 6;
}
