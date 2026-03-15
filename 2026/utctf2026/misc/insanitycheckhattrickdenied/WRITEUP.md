# Insanity Check: Hat Trick Denied

## Summary

The flag is hidden in CTFd itself, but not on the challenge page. It lives in HTML comments on two disallowed `robots.txt` paths, and the final flag is the XOR of the two comment payloads.

## Solution

1. `robots.txt` exposes two interesting paths:

   - `/2065467898`
   - `/3037802467`

2. Both pages render as ordinary `404 Not Found` pages, but the `<h1>` tag on each page includes a hidden HTML comment.
3. The first page contains:

   `2, 7, 9, 7, 8, 13, 17, 39, 85, 4, 57, 4, 93, 30, 104, 27, 44, 23, 89, 8, 30, 68, 107, 112, 54, 0, 30, 11, 2, 92, 66, 23, 31`

4. The second page contains:

   `119, 115, 111, 107, 105, 106, 106, 110, 114, 105, 102, 106, 50, 106, 55, 122, 115, 101, 54, 106, 113, 48, 52, 57, 105, 112, 108, 100, 111, 53, 49, 114, 98`

5. XORing the corresponding values byte-for-byte yields:

   `utflag{I'm_not_a_robot_I_promise}`

## Flag

`utflag{I'm_not_a_robot_I_promise}`
