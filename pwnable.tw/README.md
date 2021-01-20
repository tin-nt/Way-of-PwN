# pwnable.tw
## re-alloc [200pts]

I want to realloc my life :)

nc chall.pwnable.tw 10106

[re-alloc](https://pwnable.tw/static/chall/re-alloc)

[libc.so](https://pwnable.tw/static/libc/libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so)


### Analysis
Checksec:
```bash
$ checksec re-alloc
[*] '/home/tinnt/ctf/pwnable.tw/realloc/re-alloc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```
Source code:
```c
void heap[2] //probably

void main(){
  int choice; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]
  v4 = __readfsqword(0x28u);
  choice = 0;
  init_proc();
  while ( 1 ){
    while ( 1 ){
      menu();
      __isoc99_scanf("%d", &choice);
      if ( choice != 2 )
        break;
      reallocate();
    }
    if ( choice > 2 ){
      if ( choice == 3 ){
        rfree();
      }
      else{
        if ( choice == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else{
      if ( choice != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}

int allocate(){
  _BYTE *v0; // rax
  unsigned __int64 idx; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+18h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 || heap[idx] ){
    LODWORD(v0) = puts("Invalid !");
  }
  else{
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 ){
      ptr = realloc(0LL, size);
      if ( ptr ){
        heap[idx] = ptr;
        printf("Data:");
        v0 = (_BYTE *)(heap[idx] + read_input(heap[idx], size));
        *v0 = 0;
      }
      else{
        LODWORD(v0) = puts("alloc error");
      }
    }
    else{
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}

int reallocate(){
  unsigned __int64 idx; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *ptr; // [rsp+18h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 || !heap[idx] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  ptr = realloc((void *)heap[idx], size);
  if ( !ptr )
    return puts("alloc error");
  heap[idx] = ptr;
  printf("Data:");
  return read_input(heap[idx], size);
}

int rfree(){
  _QWORD *v0; // rax
  unsigned __int64 idx; // [rsp+8h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 ){
    LODWORD(v0) = puts("Invalid !");
  }
  else{
    realloc((void *)heap[idx], 0LL);
    v0 = heap;
    heap[idx] = 0LL;
  }
  return (int)v0;
}

```

-	Main:
	-	Inittialize data by `init_proc`.
	-	3 main option: alloc (actually realloc) new memory, realloc, free.
-	Allocate:
	-	Input `idx`, if > `heap` size (.bss section) which is `2`  then throw error, back to main or continue next step.
	-	Input `size` <=0x78 (tcache bins limit), `realloc(0, size)`, if `size` = 0 or > 0x78 then throw error, back to main or continue next step.
	-	Evaluate heap[idx] = `ptr` (ret value from realloc), secure read input from user, then evaluate input where `ptr` point in heap.
-	Realloc:
	-	Input `idx`, if > `heap` size (.bss section) which is `2`  then throw error, back to main or continue next step.
	-	Input `size` <=0x78, `realloc(0, size)`, if `size` = 0 or > 0x78 then throw error, back to main or continue next step.
	-	Realloc memory at heap[idx] with input `size`, reassign ptr to heap[idx] then read data.
-	Rfree:
	-	Input `idx`, if > `heap` size (.bss section) which is `2`  then throw error, back to main or continue next step.
	-	Realloc memory at heap[idx] with 0x0 size, null heap[idx].

> Concept of realloc():
1.	realloc(ptr, NULL): same a free(ptr).
2.	realloc(ptr, size): expand/shrink the memory chunk base on requested size. If the size value is the same as the old chunk size then nothing is done and the same memory chunk is returned.
2.	realloc(NULL, size) : same as malloc(size)

### Challenge constraints
1.	We can allocate the memory chunk less than 120 bytes. This limit the attack to tcache bins only.
2.	You can only store two memory chucks at any point of time in the global array.
3.	There is a buffer size check when reading user input for content of the memory chunk so, we cannot do any buffer overflow. 


### What is tcache?

From [malloc.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l2923)
, we can define:

-	Tcache entry:
	-	Note that `*next` pointer point to the next chunk of the same size.
	-	Also when free'd, the chunk's fd pointer point to the beginning of the tcache bins.
```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

-	Tcache_perthread_struct:
	-	This is the entire management of tcache which:
		-	`Tcache_entry` where store entry of different tcache sizes (or bins) up to 64 bins.
		-	`counts` which is recording the free'd chunks, up to 7 chunks.
```c
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
-	Tcache max bin is 64
```c
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */ 
# define TCACHE_MAX_BINS                64
```
-	Maximum chunk in each tcache is 7
```c
/* This is another arbitrary limit, which tunables can change.  Each
tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
```
-	For a fast implementation on reusing the free'd memory, it define tcache as below:
```c
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
```
-	`when a program requests for a chunk, the malloc algorithm first check whether the chunk of the requested size is available there in tcache bins if yes then it will call tcache_get function, get the pointer to the chunk and return it to the program else do further processing.`

```c
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```
#### Basic workflow

-	When malloc for the first time, it will malloc `tcache_perthread_struct` first.
-	When free the memory and the size is smaller than the bin size, tcache will record the chunk into bin. If size was over 0x408, it will put into unsorted bin.
-	Tcache bins:
	-	Find the appropriate bins, record it until full (7 chunks).
	-	When full, put into fastbin or unsorted bin like before.
	-	When 2 adjacent chunks free and put into a tache bins, these chunks do not consolidate.
-	Malloc new memory:
	-	Fetch the chunks from tcache bins until it empty.


> ref:https://payatu.com/blog/Gaurav-Nayak/introduction-of-tcache-bins-in-heap-management

> ref: https://www.taintedbits.com/2020/07/05/binary-exploitation-pwnable-tw-realloc/

> ref: https://ctf-wiki.org/pwn/linux/glibc-heap/implementation/tcache/

> double-free mitigated >=2.27: https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=affec03b713c82c43a5b025dddc21bde3334f41e
### Exploit
We're gonna abuse UAF to tcache poisoning at `reallocate` function.

Testing tcache poisoning

-	Let's alloc a new memory  `realloc(0,size)` at index 1. (`allocate` function)
	-	`realloc(index[1], 20)`
	-	`read_input` AAAA
```
+---------+  <=== index 1
|   0x20  |
+---------+
|   AAAA  |
+---------+
```
-	Here, because `reallocate` doesn't check size before 0x78 so we can `realloc` zero size.
	-	`realloc(index[1],0)` which is `free(index[1])`

```
+---------+  <=== index 1
|   0x20  |
+---------+
|   *FD   | <== *entries of 0x20 pointer
+---------+
|   *BK   | ==> point to counts tcache_perthread_struct
+---------+
```

-	We're abusing UAF to set our target value e.g `BBBB`
	-	`realloc(index[1], 20)` (remember the same size as previous realloc).
	-	`read_input` BBBB

```
+---------+  <=== index 1
|   0x20  |
+---------+
|   BBBB  | <== *entries of 0x20 pointer
+---------+
|   *BK   | ==> point to counts tcache_perthread_struct
+---------+
```

-	So, when we request for a new malloc with size 20, because of tcache implementation, the free list entry (which is currently point to BBBB) gonna fetch our target to free list!!
	-	`allocate` index 0.
		-	Now, tcache entry stored target address!!!
	-	`read_input` CCCC.
```
|   ...   |
+---------+
|   BBBB  |  <=== tcache entry above chunks
+---------+
|   ...   |
+---------+  <=== index 1
|   0x20  |
+---------+
|   CCCC  |
+---------+
```

Now we have arbitrary write, how can we make use of it? Because PIE disabled we can overwrite GOT but which one should we write? Notice that there's an `atoll` which is perfectly for us. Now we gonna patch `atoll` with `printf` for leaking libc address.


-	Apply above method, we achieved this: (remember to null heap global variable)

![arbitrary write](https://i.imgur.com/vnBRSE7.png)

-	Next, we request another chunk with it's content has printf.plt address, so when it malloc a new chunk, the value of atoll.got will be overwriten.

![arbitrary write](https://i.imgur.com/PmWsXYB.png)

-	Now all we need is leaking the libc, change the atoll.got to system, put /bin/sh as parameter then we got a shell.

![flag](https://i.imgur.com/08IhEEi.png)
