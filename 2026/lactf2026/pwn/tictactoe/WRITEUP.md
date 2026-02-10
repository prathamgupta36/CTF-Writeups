# tic-tac-no (pwn)

## Summary
The game claims a perfect minimax bot. The bug is in the input validation for the player's move: it only rejects moves when the computed index is in range **and** the square is occupied. Out-of-range indices are accepted, letting us write outside the `board` array and overwrite nearby globals. By overwriting the `computer` marker (`'O'`) with `'X'`, the bot starts playing as `X` too, and any bot win is treated as a player win, printing the flag.

## Vulnerability
In `playerMove()`:
```
int index = (x-1)*3+(y-1);
if(index >= 0 && index < 9 && board[index] != ' '){
    printf("Invalid move.\n");
}else{
    board[index] = player;
    break;
}
```
If `index` is out of bounds, the condition is false, so the code writes to `board[index]` anyway.

The globals are laid out as:
- `player` at `board - 24`
- `computer` at `board - 23`
So writing to `board[-23]` overwrites `computer`.

## Exploit
Pick `x = -7`, `y = 2`:
```
index = (x-1)*3 + (y-1) = (-8)*3 + 1 = -24 + 1 = -23
```
This stores `'X'` into `computer`. Now both `player` and `computer` are `'X'`.

On the next move, let the bot win (e.g. play `1,1`). The bot's diagonal `X` win causes:
```
winner == player
```
so the program prints the flag.

## Steps to Reproduce
Manual:
1) Enter row `-7`, column `2`
2) Enter row `1`, column `1`

Scripted:
```
python3 solve.py
```

## Notes
- The minimax is correct; the bug is purely input validation.
- Any move that makes `index == -23` works (other pairs can also hit this offset).
