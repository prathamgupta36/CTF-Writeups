# Double Check

## Summary

The flag was not in the current site contents. It was briefly committed into the public Git history and then removed in the very next commit.

## Solution

1. The challenge points at `https://github.com/Jarpiano/utctf-profile`.
2. Inspecting the public commit history shows a suspicious commit:

   `a1546afedb6edeffa9227d70b1f5e110bda9f7e6  added key file to integrate with AWS`

3. Querying the commit details shows the newly added file:

   `static/fonts/secret-keys/AWS-key.txt`

4. The commit patch contains the full file contents directly:

   `+utflag{n07h1n6_70_h1d3}`

5. The following commit removes the same file, confirming it was an exposed secret that only survives in history.

## Flag

`utflag{n07h1n6_70_h1d3}`
