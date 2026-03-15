# QRecreate

## Summary

The ZIP archive contains 100 PNG tiles that must be reassembled into a single QR code. The decoded QR payload then hides the actual flag in Base64.

## Solution

1. `TaxReports2008.zip` expands into directories like `output/MDAx/data/img.png`.
2. The directory names are Base64:

   - `MDAx` -> `001`
   - `MDEw` -> `010`
   - `MTAw` -> `100`

3. Sorting the decoded indices from `001` through `100` and placing the `74x74` PNGs in row-major order yields a `10x10` composite image.
4. The reconstructed QR does not decode cleanly until a white quiet zone is added around the outside.
5. After padding, the QR payload contains a long Lorem Ipsum paragraph with one embedded Base64 blob:

   `dXRmbGFne3MzY3IzdHNfQHJlX0Bsd0B5c193MXRoMW5fczNjcjN0c30=`

6. Base64-decoding that string gives the flag.

## Flag

`utflag{s3cr3ts_@re_@lw@ys_w1th1n_s3cr3ts}`
