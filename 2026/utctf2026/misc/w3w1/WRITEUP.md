# W3W1 Writeup

## Challenge Info

- Name: `W3W1`
- Category: `Misc`
- Description: `The three words I would use to describe this location are...`
- Flag format: `utflag{word1.word2.word3}`
- Final flag: `utflag{similar.riots.hours}`

## Overview

This challenge is a landmark-to-what3words solve. The image shows a large stone church beside UT Austin campus buildings, so the job is:

1. Identify the landmark.
2. Figure out which side of the street the intended point is on.
3. Resolve the accepted 3m square.

## Key Observations

From [`W3W1.jpg`](./W3W1.jpg):

- The church facade is light limestone with a tall narrow spire.
- The front doors are red.
- A UT campus bus stop and UT-style lamp posts are visible.
- The left side of the frame looks like UT Austin campus architecture.

That combination matches `University Christian Church` across from UT Austin's South Mall / Littlefield Fountain area.

## Identification

The local helper artifacts already narrowed this correctly:

- [`church.png`](./church.png)
- [`commons_ucc.jpg`](./commons_ucc.jpg)
- [`ucc_site.png`](./ucc_site.png)
- [`osm_local_map.png`](./osm_local_map.png)

Those make the landmark identification straightforward:

- `University Christian Church`
- `Austin, Texas`

The remaining precision problem is whether the intended point is on the church side of the street or across from it.

## Exact Point

The accepted square is across from the church at the `Littlefield Fountain` side of the street, not on the church building itself.

Resolving the accepted three-word address gives:

- what3words: `similar.riots.hours`
- coordinates: `30.283730, -97.739654`
- nearest place: `Austin, Texas`

That lands on the Littlefield Fountain / South Mall side facing the church, which matches the image composition.

## Solution

The correct what3words address is:

- `similar.riots.hours`

So the flag is:

```text
utflag{similar.riots.hours}
```

## Summary

1. Use the church architecture and UT surroundings to identify `University Christian Church`.
2. Use the street layout to place the intended point across from the church.
3. Resolve the accepted square at the Littlefield Fountain side.
4. Submit `utflag{similar.riots.hours}`.
