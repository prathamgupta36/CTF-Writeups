# Go Go Coaster! - UofTCTF 2026 OSINT Writeup

## Challenge

> During an episode of *Go Go Squid!*, Han Shangyan is too scared to ride a roller coaster.  
> Find the **English name** of that coaster and its **height in whole feet**.  
>  
> **Flag format:** `uoftctf{Coaster_Name_HEIGHT}`  
> Example: `uoftctf{Yukon_Striker_999}`

---

## High-level idea

1. Figure out **which episode** has the roller-coaster scene.
2. Watch that scene and identify **which real park** it was filmed in.
3. From the park, identify **which coaster** is shown.
4. Look up its **height in feet** and plug everything into the flag format.

---

## Step 1 - Finding the episode

The description mentions Han Shangyan refusing to ride a roller coaster.  
Searching something like:

> `go go squid episode guide Han Shangyan too scared roller coaster`

leads to recap pages for *Go Go Squid!* episode 12. One of them explicitly describes Han Shangyan staying on the ground while Tong Nian and others ride a roller coaster and he remembers being afraid of heights in the past.
Link to recap- https://www.cpophome.com/go-go-squid-yang-zi-li-xian/recap/12/

So the scene we care about is in **Episode 12**.

---

## Step 2 - Watching the scene

Next, watch the actual episode. The official upload of episode 12 is on YouTube from Croton Media.

Watching Link- https://www.youtube.com/watch?v=8N1k83-BzM4

Scrubbing through the episode around the amusement-park portion, you can clearly see:

- A large, red roller coaster with a vertical first drop.
- Wide, floorless trains with riders sitting in a single row.
- A splashdown element after the first drop.

These are the visual hallmarks of a **Bolliger & Mabillard Dive Coaster**.

---

## Step 3 - Identifying the park

Searching for something like:

> `Go Go Squid amusement park roller coaster`  
> `Go Go Squid episode 12 amusement park location`

eventually turns up results saying the amusement-park scenes were filmed at **Happy Valley Shanghai** (an amusement park in Songjiang, Shanghai). Several coaster-fan sites and blogs show photos of the park with the same big red dive coaster visible in the skyline.

Link - https://coasterpedia.net/wiki/Diving_Coaster_%28Happy_Valley_Shanghai%29

So we now know the coaster is a B&M dive coaster at **Happy Valley Shanghai**.

---

## Step 4 - Matching the exact coaster

Looking up the list of roller coasters at Happy Valley Shanghai, you'll find one dive coaster-style ride with a vertical drop: **Diving Coaster** (sometimes referred to as a “Dive Coaster” / “Diving Machine” model).

Comparing:

- Color scheme (red track, blue supports),
- Layout (vertical drop, Immelmann inversion, splashdown),

to off-ride / POV videos of **Diving Coaster** confirms it matches the coaster seen in the drama.

Thus, the **English name** asked for in the challenge is:

> **Diving Coaster**

(Spaces will become underscores in the final flag.)

---

## Step 5 - Finding the height in feet

Now we need the coaster's height in **whole feet**.

Different coaster databases give the height in metres, but some sources include the conversion:

Wiki Link- https://wiki2.org/en/Diving_Coaster

- Wikipedia / mirror sites list the height as **65 metres**.  
- Another mirror explicitly says **“65-metre (213 ft) lift hill”**.
- A coaster-fan trip report also describes Diving Coaster as **213 feet tall**.
65 m converted to feet:

- \(65 \times 3.28084 ≈ 213.25\) ft  

Rounded to a whole foot, that's **213 feet**.

(You may also find RCDB listing 64.9 m and 216.9 ft; the metric value and several independent sources are consistent with ~213 ft, and 213 is the value that works for the flag.)

So the height we use is:

> **213** (whole feet)

---

## Step 6 - Constructing the flag

The challenge wants:

- Spaces replaced with underscores
- Coaster name + height (no decimals)

Name: `Diving Coaster` → `Diving_Coaster`  
Height: `213`

So the final flag is:

```text
uoftctf{Diving_Coaster_213}

