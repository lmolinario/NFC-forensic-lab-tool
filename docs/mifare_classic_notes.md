# MIFARE Classic 1K Notes

MIFARE Classic 1K uses a sector/block memory model.

Typical structure:

- 16 sectors;
- 4 blocks per sector;
- 64 blocks total;
- 16 bytes per block;
- last block of each sector is the sector trailer.

Block roles:

- Block 0: manufacturer block;
- Blocks 1-2 of sector 0: data blocks;
- Block 3: sector trailer;
- Every block where `block % 4 == 3`: sector trailer.

The sector trailer may contain:

- Key A;
- access conditions;
- Key B or data depending on configuration.

Access to sector data normally requires authentication with Key A or Key B.
