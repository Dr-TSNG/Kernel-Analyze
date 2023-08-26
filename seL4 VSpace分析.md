# seL4 VSpace 分析

## 地址空间结构

![seL4 RISC-V 地址空间](https://nullptr.icu/usr/uploads/2023/08/1908069288.png)

详见 seL4 启动流程一文。

## 地址转换

seL4 内核中的基本地址有 3 类：`paddr`、`pptr`、`kpptr`

| 地址类型  | 说明            |
|:-----:|:-------------:|
| paddr | 物理地址          |
| pptr  | 内核直接映射区域虚拟地址  |
| kpptr | 内核 ELF 区域虚拟地址 |

seL4 存在三个基本的地址转换：

| 地址转换          | 别名             | 实现                            | 说明                   |
|:-------------:|:--------------:|:-----------------------------:|:--------------------:|
| ptrFromPAddr  | paddr_to_pptr  | paddr + PPTR_BASE_OFFSET      | 从一个物理地址到内核可以解引用的虚拟地址 |
| addrFromPPtr  | pptr_to_paddr  | pptr - PPTR_BASE_OFFSET       | 从一个内核虚拟地址到物理地址       |
| addrFromKPPtr | kpptr_to_paddr | pptr - KERNEL_ELF_BASE_OFFSET | 从一个内核 ELF 区域地址到物理地址  |

从逻辑上来说，内核动态构造的数据结构都是通过 `pptr` 进行访问，而内核 ELF 文件通过 ld 脚本对其中的各种段进行编址是从 `KERNEL_ELF_BASE` 开始。也就是说，内核静态对象引用地址减去 `KERNEL_ELF_BASE` 即是物理地址。

因此，可以看到 `activate_kernel_vspace` 中设置根页表使用了 `kpptr_to_paddr(&kernel_root_pageTable)` 得到物理地址，其中 `kernel_root_pageTable` 是一个 ELF 中的静态数组。

## 关键函数分析

### `getPPtrFromHWPTE(pte_t *pte)`

#### 功能

给定页表项，获取下一级页表的虚拟地址。

#### 实现

将页表项 PPN 左移页帧大小，再翻译为虚拟地址。

```c
return PTE_PTR(ptrFromPAddr(pte_ptr_get_ppn(pte) << seL4_PageTableBits));
```

### `lookupPTSlot(pte_t *lvl1pt, vptr_t vptr)`

#### 功能

给定一级页表指针和虚拟地址，返回对应页表项。

#### 实现

`ret.ptSlot` 指向 `vptr` 在给定 `lvl1pt` 页表的槽位地址。

```c
lookupPTSlot_ret_t ret;

word_t level = CONFIG_PT_LEVELS - 1;
pte_t *pt = lvl1pt;


ret.ptBitsLeft = PT_INDEX_BITS * level + seL4_PageBits;
ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));
```

接下来逐层遍历，通过 `getPPtrFromHWPTE(ret.ptSlot)` 得到下一级页表。

```c
while (isPTEPageTable(ret.ptSlot) && likely(0 < level)) {
    level--;
    ret.ptBitsLeft -= PT_INDEX_BITS;
    pt = getPPtrFromHWPTE(ret.ptSlot);
    ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));
}
```

### `findVSpaceForASID(asid_t asid)`

根据一个 ASID，获取其一级页表的引用。

### `deleteASIDPool(asid_t asid_base, asid_pool_t *pool)`

解除一个 ASID 与 ASID 池的绑定。执行此操作后，会将当前页表重置为当前线程页表。

### `performASIDControlInvocation(void *frame, cte_t *slot, cte_t *parent, asid_t asid_base)`

为一个 ASID 绑定一个 ASID 池（对应一个物理页帧），并在对应槽位插入 `asid pool cap`。

### `performASIDPoolInvocation(asid_t asid, asid_pool_t *poolPtr, cte_t *vspaceCapSlot)`

#### 功能

为一个地址空间绑定一个 ASID，同时初始化页表。

#### 实现

为地址空间 cap 设置 ASID 等信息。

```c
cap_t cap = vspaceCapSlot->cap;
pte_t *regionBase = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
cap = cap_page_table_cap_set_capPTMappedAddress(cap, 0);
cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
vspaceCapSlot->cap = cap;
```

为其页表拷贝全局映射。

```c
copyGlobalMappings(regionBase as usize);
```

在 ASID Pool 对应位置记录页表基址。

```c
poolPtr->array[asid & MASK(asidLowBits)] = regionBase;
```

### `unmapPageTable(asid_t asid, vptr_t vptr, pte_t *target_pt)`

根据 ASID 和虚拟地址，找到 `target_pt` 所在页表，删除对应页表项。

### `unmapPage(page_size: usize, asid: asid_t, vptr: vptr_t, pptr: pptr_t)`

根据 ASID 和虚拟地址，删除一个从 `vptr` 到 `pptr` 的物理页映射。

与 `unmapPageTable` 类似，不过是删除叶子页表项。
