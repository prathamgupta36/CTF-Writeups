# Last Byte Standing

## Summary

The important anomaly is not in the bulk HTTP or ARP traffic. It is the extra trailing byte Wireshark reports on hundreds of DNS packets. Those trailing bytes are literal `0` and `1` bits.

## Solution

1. `tshark -z expert` reports:

   `440 DNS packets with Extraneous data`

2. Inspecting a DNS query in Wireshark shows:

   - normal DNS question
   - one extra byte after the DNS payload
   - the extra byte is either `30` or `31` (`'0'` / `'1'`)

3. There are three bit channels, one per query name:

   - `sync-cache.nexthop-lab.net`
   - `sync-cache-alpha.nexthop-lab.net`
   - `sync-cache-beta.nexthop-lab.net`

4. Concatenating the trailing bits in packet order for the main channel and decoding every 8 bits as ASCII yields:

   `utflag{d1g_t0_th3_l4st_byt3}`

5. The `alpha` and `beta` channels decode to junky repeating filler and are just noise.

## Flag

`utflag{d1g_t0_th3_l4st_byt3}`
