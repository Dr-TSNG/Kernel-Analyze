# seL4 启动流程

## 引导和基本地址空间

内核启动前，QEMU 会将 OpenSBI 加载到 `0x80000000`，之后跳转到 OpenSBI。OpenSBI 随后会将内核加载到 `0x84000000` 处，进入到 `head.S` 逻辑。`head.S` 中会设置好每个核心的栈内存，然后跳转到 `init_kernel`。

seL4 RISC-V 地址空间结构如下：

![seL4 RISC-V 地址空间](https://nullptr.icu/usr/uploads/2023/08/1908069288.png)

| 区域     | 虚拟地址起点             | 物理地址起点     |
|:------:|:------------------:|:----------:|
| 直接映射区域 | 0xFFFFFFC000000000 | 0          |
| 内核 ELF | 0xFFFFFFFF84000000 | 0x84000000 |
| 内核设备   | 0xFFFFFFFFC0000000 | 无          |

## 内核启动

在进入内核前，OpenSBI 会启用分页并将内核映射到对应的虚拟内存区域（`0xFFFFFFFF84000000`）。所以当进入内核时，此时的 `pc` 已经是内核的虚拟地址入口。

## 映射内核页表

map_kernel_window：该阶段第一步工作是将从 `PADDR_BASE` 开始，到 `PADDR_TOP` 结束的物理内存映射到从 `PPTR_BASE` 开始，到 `PPTR_TOP` 结束的虚拟内存，也即下图的部分。注意此处在一级页表直接映射物理内存。

![直接地址映射](https://nullptr.icu/usr/uploads/2023/08/2038345540.png)

> 非叶节点（页目录表，非末级页表）的表项标志位含义和叶节点（页表，末级页表）相比有一些不同：
> 
> - 当 `V` 为 0 的时候，代表当前指针是一个空指针，无法走向下一级节点，即该页表项对应的虚拟地址范围是无效的；
> - 只有当 `V` 为 1 且 `R/W/X` 均为 0 时，表示是一个合法的页目录表项，其包含的指针会指向下一级的页表；
> - 注意: 当 `V` 为 1 且 `R/W/X` 不全为 0 时，表示是一个合法的页表项，其包含了虚地址对应的物理页号。

```c
/* mapping of KERNEL_ELF_BASE (virtual address) to kernel's
 * KERNEL_ELF_PHYS_BASE  */
 assert(CONFIG_PT_LEVELS > 1 && CONFIG_PT_LEVELS <= 4);

 /* kernel window starts at PPTR_BASE */
 word_t pptr = PPTR_BASE;

 /* first we map in memory from PADDR_BASE */
 word_t paddr = PADDR_BASE;
 while (pptr < PPTR_TOP) {
    assert(IS_ALIGNED(pptr, RISCV_GET_LVL_PGSIZE_BITS(0)));
    assert(IS_ALIGNED(paddr, RISCV_GET_LVL_PGSIZE_BITS(0)));

    kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);

    pptr += RISCV_GET_LVL_PGSIZE(0);
    paddr += RISCV_GET_LVL_PGSIZE(0);
}
...
```

接下来的一步是映射 Kernel ELF。此处设置了两个虚拟地址指向同一个内核二级页表，一个是从 `KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET` 开始，一个是从 `KERNEL_ELF_BASE` 开始，占据 1GB。然后，分别完成二级页表到 Kernel ELF 对应物理内存的映射。

*为什么这里要映射两遍，不太明白。*

![Kernel ELF 映射](https://nullptr.icu/usr/uploads/2023/08/499604017.png)

```c
...
pptr = ROUND_DOWN(KERNEL_ELF_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
paddr = ROUND_DOWN(KERNEL_ELF_PADDR_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));

word_t index = 0;
/* The kernel image is mapped twice, locating the two indexes in the
 * root page table, pointing them to the same second level page table.
 */
kernel_root_pageTable[RISCV_GET_PT_INDEX(KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET, 0)] =
    pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] =
    pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
while (pptr < PPTR_TOP + RISCV_GET_LVL_PGSIZE(0)) {
    kernel_image_level2_pt[index] = pte_next(paddr, true);
    index++;
    pptr += RISCV_GET_LVL_PGSIZE(1);
    paddr += RISCV_GET_LVL_PGSIZE(1);
}
...
```

最后，映射内核设备。

*大概是 MMIO 一类的东西？*

```c
/* Map kernel device page table */
kernel_root_pageTable[RISCV_GET_PT_INDEX(KDEV_BASE, 0)] =
    pte_next(kpptr_to_paddr(kernel_image_level2_dev_pt), false);

/* There should be 1GiB free where we put device mapping */
assert(pptr == UINTPTR_MAX - RISCV_GET_LVL_PGSIZE(0) + 1);
map_kernel_devices();
```

## 初始化 CPU

`init_cpu`：该阶段的主要工作是写入根页表地址到 `satp`，完成页表切换，然后设置中断入口。

```c
BOOT_CODE static void init_cpu(void)
{
    activate_kernel_vspace();
    /* Write trap entry address to stvec */
    write_stvec((word_t)trap_entry);
    ...
}
```

## 初始化空闲内存

`arch_init_freemem`：该阶段内核主要负责根据内核镜像位置和 `elfloader` 传入的物理地址区域分配空闲内存，并为初始线程的控制块分配空间。排除掉内核镜像、用户程序镜像和 dtb，总的可用物理内存减去这三个区域就是空闲内存。

```
reserved virt address space regions: 3
  [ffffffc084000000..ffffffc084025000]
  [ffffffc084025000..ffffffc084026122]
  [ffffffc084027000..ffffffc08440d000]
```

### 创建初始线程信息

`create_rootserver_objects`：在空闲内存中找到一块用于放置初始线程（root_server）的控制块，包括以下内容：

```c
typedef struct {
    pptr_t cnode;
    pptr_t vspace;
    pptr_t asid_pool;
    pptr_t ipc_buf;
    pptr_t boot_info;
    pptr_t extra_bi;
    pptr_t tcb;
#ifdef CONFIG_KERNEL_MCS
    pptr_t sc;
#endif
    region_t paging;
} rootserver_mem_t;
```

## 为初始线程分配 Capabilities

依次赋予初始线程以下 cap：

| 类型              | Capability                  |
|:---------------:|:---------------------------:|
| 初始线程权限          | seL4_CapInitThreadCNode     |
| 线程管理权限          | seL4_CapDomain              |
| 中断控制权限          | seL4_CapIRQControl          |
| 初始线程地址空间        | seL4_CapInitThreadVSpace    |
| 启动信息页帧          | seL4_CapBootInfoFrame       |
| ASID 控制权限       | seL4_CapASIDControl         |
| 初始线程 IPC Buffer | seL4_CapInitThreadIPCBuffer |
| 初始线程 TCB        | seL4_CapInitThreadTCB       |

> For internal kernel book-keeping purposes, there is a fixed maximum number of applications the system can support. In order to manage this limited resource, the microkernel provides an ASID Control capability. The ASID Control capability is used to generate a capability that authorises the use of a subset of available address-space identifiers. This newly created capability is called an ASID Pool. ASID Control only has a single `MakePool` method for each architecture.
> 
> An ASID Pool confers the right to create a subset of the available maximum applications. For a VSpace to be usable by an application, it must be assigned to an ASID. This is done using a capability to an ASID Pool. The ASID Pool object has a single method, `Assign`.

### 创建根线程 cap

`create_root_cnode`：

```c
BOOT_CODE cap_t
create_root_cnode(void)
{
    cap_t cap = cap_cnode_cap_new(
                    CONFIG_ROOT_CNODE_SIZE_BITS, /* radix */
                    wordBits - CONFIG_ROOT_CNODE_SIZE_BITS, /* guard size */
                    0, /* guard */
                    rootserver.cnode); /* pptr */

    /* write the root CNode cap into the root CNode */
    write_slot(SLOT_PTR(rootserver.cnode, seL4_CapInitThreadCNode), cap);

    return cap;
}
```

### 创建初始线程地址空间

`create_it_address_space`：rootserver 能够访问整个内核的地址，所以将内核的一级页表复制给 rootserver，然后为其分配这个 cap：

```c
cap_t      lvl1pt_cap;
vptr_t     pt_vptr;

copyGlobalMappings(PTE_PTR(rootserver.vspace));

lvl1pt_cap =
    cap_page_table_cap_new(
        IT_ASID,               /* capPTMappedASID    */
        (word_t) rootserver.vspace,  /* capPTBasePtr       */
        1,                     /* capPTIsMapped      */
        (word_t) rootserver.vspace   /* capPTMappedAddress */
    );

seL4_SlotPos slot_pos_before = ndks_boot.slot_pos_cur;
write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace), lvl1pt_cap);
```

然后遍历 init thread 镜像的虚拟地址，构建镜像虚拟地址到物理地址的一级页表映射和二级页表映射后返回 `vspace cap` 。

```c
/* create all n level PT caps necessary to cover userland image in 4KiB pages */
for (int i = 0; i < CONFIG_PT_LEVELS - 1; i++) {

    for (pt_vptr = ROUND_DOWN(it_v_reg.start, RISCV_GET_LVL_PGSIZE_BITS(i));
         pt_vptr < it_v_reg.end;
         pt_vptr += RISCV_GET_LVL_PGSIZE(i)) {
        if (!provide_cap(root_cnode_cap,
                         create_it_pt_cap(lvl1pt_cap, it_alloc_paging(), pt_vptr, IT_ASID))
           ) {
            return cap_null_cap_new();
        }
    }

}

seL4_SlotPos slot_pos_after = ndks_boot.slot_pos_cur;
ndks_boot.bi_frame->userImagePaging = (seL4_SlotRegion) {
    slot_pos_before, slot_pos_after
};

return lvl1pt_cap;
```

**注意**：此过程只进行了一级和二级页表的映射，没有三级页表。虚拟地址到最终物理地址的映射会在之后完成。

### 创建各页帧 cap

接下来进行三级页表的映射。为 `bootinfo`、`extra bootinfo` 、`ipcbuf` 、`userland image` 分别创建对应区域并写入三级页表。以 `ipcbuf frame` 为例：在创建对应 cap 同时映射三级页表。

```c
BOOT_CODE cap_t create_ipcbuf_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr)
{
    clearMemory((void *)rootserver.ipc_buf, PAGE_BITS);

    /* create a cap of it and write it into the root CNode */
    cap_t cap = create_mapped_it_frame_cap(pd_cap, rootserver.ipc_buf, vptr, IT_ASID, false, false);
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer), cap);

    return cap;
}
```

## 创建线程

TCB 结构如下：

| 名称                   | 作用                 |
|:--------------------:|:------------------:|
| tcbArch              | 架构专用 TCB 信息（包括上下文） |
| tcbState             | 线程调度状态             |
| tcbBoundNotification | 通知钩子               |
| tcbFault             | 异常信息               |
| tcbLookupFailure     | 异常发生地址             |
| tcbDomain            | 子系统域               |
| tcbMCP               | 最大调度优先级            |
| tcbPriority          | 调度优先级              |
| tcbTimeSlice         | 剩余时间片              |
| tcbFaultHandler      | 异常处理程序，一个 cap      |
| tcbIPCBuffer         | 用户模式 IPC 处理程序      |
| tcbIPCBuffer         | IPC Buffer         |
| tcbSched/EP*         | 调度相关               |

> Domains are used to isolate independent subsystems, so as to limit information flow between them. The kernel switches between domains according to a fixed, time-triggered schedule.

**注意**：一个比较迷惑的点在于，`rootserver.tcb` 不是真正的 TCB，而是指的 TCB Block。所以，下面的 `rootserver.tcb` 指向 CTE，`tcb` 才是指向 TCB。

```c
We would like the actual 'tcb' region (the portion that contains the tcb_t) of the tcb
to be as large as possible, but it still needs to be aligned. As the TCB object contains
two sub objects the largest we can make either sub object whilst preserving size alignment
is half the total size. To halve an object size defined in bits we just subtract 1

A diagram of a TCB kernel object that is created from untyped:
 _______________________________________
|     |             |                   |
|     |             |                   |
|cte_t|   unused    |       tcb_t       |
|     |(debug_tcb_t)|                   |
|_____|_____________|___________________|
0     a             b                   c
a = tcbCNodeEntries * sizeof(cte_t)
b = BIT(TCB_SIZE_BITS)
c = BIT(seL4_TCBBits)

#define TCB_OFFSET BIT(TCB_SIZE_BITS)
```

### 创建空闲线程

`create_idle_thread`：如果存在多核，则为每个核心都创建一个空闲线程。

```c
BOOT_CODE void create_idle_thread(void)
{
    pptr_t pptr;

#ifdef ENABLE_SMP_SUPPORT
    for (unsigned int i = 0; i < CONFIG_MAX_NUM_NODES; i++) {
#endif /* ENABLE_SMP_SUPPORT */
        pptr = (pptr_t) &ksIdleThreadTCB[SMP_TERNARY(i, 0)];
        NODE_STATE_ON_CORE(ksIdleThread, i) = TCB_PTR(pptr + TCB_OFFSET);
        configureIdleThread(NODE_STATE_ON_CORE(ksIdleThread, i));
#ifdef CONFIG_DEBUG_BUILD
        setThreadName(NODE_STATE_ON_CORE(ksIdleThread, i), "idle_thread");
#endif
        SMP_COND_STATEMENT(NODE_STATE_ON_CORE(ksIdleThread, i)->tcbAffinity = i);
#ifdef CONFIG_KERNEL_MCS
        configure_sched_context(NODE_STATE_ON_CORE(ksIdleThread, i), SC_PTR(&ksIdleThreadSC[SMP_TERNARY(i, 0)]),
                                usToTicks(CONFIG_BOOT_THREAD_TIME_SLICE * US_IN_MS));
        SMP_COND_STATEMENT(NODE_STATE_ON_CORE(ksIdleThread, i)->tcbSchedContext->scCore = i;)
        NODE_STATE_ON_CORE(ksIdleSC, i) = SC_PTR(&ksIdleThreadSC[SMP_TERNARY(i, 0)]);
#endif
#ifdef ENABLE_SMP_SUPPORT
    }
#endif /* ENABLE_SMP_SUPPORT */
}
```

### 创建初始线程

`Arch_initContext`：将 `SPIE` 置 1，使 `sret` 返回时进入用户模式。

```c
BOOT_CODE tcb_t *create_initial_thread(cap_t root_cnode_cap, cap_t it_pd_cap, vptr_t ui_v_entry, vptr_t bi_frame_vptr,
                                       vptr_t ipcbuf_vptr, cap_t ipcbuf_cap)
{
    tcb_t *tcb = TCB_PTR(rootserver.tcb + TCB_OFFSET);
#ifndef CONFIG_KERNEL_MCS
    tcb->tcbTimeSlice = CONFIG_TIME_SLICE;
#endif

    Arch_initContext(&tcb->tcbArch.tcbContext);
    ...
}
```

接下来，拷贝一份 `ipcbuf cap`，并在 root task 的 CTE 中插入 `cnode cap`、`vtable cap`、`ipcbuf cap`，并设置指向 boot info 的寄存器和 `pc`。

*这里我没明白为什么 `ipcbuf cap`  要 derive 一遍。*

```c
/* derive a copy of the IPC buffer cap for inserting */
deriveCap_ret_t dc_ret = deriveCap(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer), ipcbuf_cap);
if (dc_ret.status != EXCEPTION_NONE) {
    printf("Failed to derive copy of IPC Buffer\n");
    return NULL;
}


/* initialise TCB (corresponds directly to abstract specification) */
cteInsert(
    root_cnode_cap,
    SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadCNode),
        SLOT_PTR(rootserver.tcb, tcbCTable)
);
cteInsert(
    it_pd_cap,
    SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace),
    SLOT_PTR(rootserver.tcb, tcbVTable)
);
cteInsert(
    dc_ret.cap,
    SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer),
    SLOT_PTR(rootserver.tcb, tcbBuffer)
);
tcb->tcbIPCBuffer = ipcbuf_vptr;

setRegister(tcb, capRegister, bi_frame_vptr);
setNextPC(tcb, ui_v_entry);
```

初始化调度信息。

```c
/* initialise TCB */
#ifdef CONFIG_KERNEL_MCS
configure_sched_context(tcb, SC_PTR(rootserver.sc), usToTicks(CONFIG_BOOT_THREAD_TIME_SLIE * US_IN_MS));
#endif

tcb->tcbPriority = seL4_MaxPrio;
tcb->tcbMCP = seL4_MaxPrio;
tcb->tcbDomain = ksDomSchedule[ksDomScheduleIdx].domain;
#ifndef CONFIG_KERNEL_MCS
setupReplyMaster(tcb);
#endif
setThreadState(tcb, ThreadState_Running);

ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
#ifdef CONFIG_KERNEL_MCS
ksDomainTime = usToTicks(ksDomSchedule[ksDomScheduleIdx].length * US_IN_MS);
#else
ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;
#endif
assert(ksCurDomain < CONFIG_NUM_DOMAINS && ksDomainTime > 0);

#ifndef CONFIG_KERNEL_MCS
SMP_COND_STATEMENT(tcb->tcbAffinity = 0);
#endif
```

最后，创建初始线程的 `tcb cap` 并设置线程名：

```c
/* create initial thread's TCB cap */
cap_t cap = cap_thread_cap_new(TCB_REF(tcb));
write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadTCB), cap);

#ifdef CONFIG_KERNEL_MCS
cap = cap_sched_context_cap_new(SC_REF(tcb->tcbSchedContext), seL4_MinSchedContextBits);
write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadSC), cap);
#endif
#ifdef CONFIG_DEBUG_BUILD
setThreadName(tcb, "rootserver");
#endif

return tcb;
```

## 返回用户态

初始化 CPU 调度，释放 bootinfo 页帧，解锁其他核心。

```c
init_core_state(initial);
...
/* finalise the bootinfo frame */
bi_finalise();
...
/* All cores are up now, so there can be concurrency. The kernel booting is
 * supposed to be finished before the secondary cores are released, all the
 * primary has to do now is schedule the initial thread. Currently there is
 * nothing that touches any global data structures, nevertheless we grab the
 * BKL here to play safe. It is released when the kernel is left. */
NODE_LOCK_SYS;

printf("Booting all finished, dropped to user space\n");
return true;
```

返回用户态。

```
/* Restore the initial thread. Note that the function restore_user_context()
 * could technically also be called at the end of init_kernel() directly,
 * there is no need to return to the assembly code here at all. However, for
 * verification things are a lot easier when init_kernel() is a normal C
 * function that returns. The function restore_user_context() is not a
 * normal C function and thus handled specially in verification, it does
 * highly architecture specific things to exit to user mode.
 */
la ra, restore_user_context
jr ra
```
