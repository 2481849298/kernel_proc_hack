#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

/* 缓存大小定义 */
#define CACHE_SIZE 128

/* 缓存结构体 */
struct phys_addr_cache {
    uintptr_t va;
    phys_addr_t pa;
} phys_cache[CACHE_SIZE];

/* 初始化缓存 */
static void init_phys_cache(void) {
    int i;
    for (i = 0; i < CACHE_SIZE; i++) {
        phys_cache[i].va = 0;
        phys_cache[i].pa = 0;
    }
}

/* 在缓存中查找物理地址 */
static phys_addr_t lookup_phys_cache(uintptr_t va) {
    int i;
    for (i = 0; i < CACHE_SIZE; i++) {
        if (phys_cache[i].va == va)
            return phys_cache[i].pa;
    }
    return 0;
}

/* 更新缓存 */
static void update_phys_cache(uintptr_t va, phys_addr_t pa) {
    int i;
    /* 简单的替换策略：替换第一个空闲的缓存项 */
    for (i = 0; i < CACHE_SIZE; i++) {
        if (phys_cache[i].va == 0) {
            phys_cache[i].va = va;
            phys_cache[i].pa = pa;
            return;
        }
    }
    /* 如果没有空闲的缓存项，替换第一个缓存项 */
    phys_cache[0].va = va;
    phys_cache[0].pa = pa;
}

/* 线性地址到物理地址的转换 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    pud = pud_offset(pgd, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}
#endif

/* 获取高内存地址 */
#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static size_t get_high_memory(void)
{
    struct sysinfo meminfo;
    si_meminfo(&meminfo);
    return (meminfo.totalram * (meminfo.mem_unit / 1024)) << PAGE_SHIFT;
}
#define valid_phys_addr_range(addr, count) (addr + count <= get_high_memory())
#else
#define valid_phys_addr_range(addr, count) true
#endif

/* 读取物理地址 */
size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    phys_addr_t mapped_pa = pa & PAGE_MASK;
    size_t mapped_size = PAGE_ALIGN(size);

    /* 检查物理页是否有效 */
    if (!pfn_valid(__phys_to_pfn(mapped_pa)))
        return 0;

    /* 检查物理地址范围是否有效 */
    if (!valid_phys_addr_range(mapped_pa, mapped_size))
        return 0;

    /* 映射物理地址到内核空间 */
    mapped = ioremap_cache(mapped_pa, mapped_size);
    if (!mapped)
        return 0;

    /* 复制数据到用户空间 */
    if (copy_to_user(buffer, mapped + (pa & (PAGE_SIZE - 1)), size)) {
        iounmap(mapped);
        return 0;
    }

    /* 取消映射 */
    iounmap(mapped);
    return size;
}

/* 写入物理地址 */
size_t write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    phys_addr_t mapped_pa = pa & PAGE_MASK;
    size_t mapped_size = PAGE_ALIGN(size);

    /* 检查物理页是否有效 */
    if (!pfn_valid(__phys_to_pfn(mapped_pa)))
        return 0;

    /* 检查物理地址范围是否有效 */
    if (!valid_phys_addr_range(mapped_pa, mapped_size))
        return 0;

    /* 映射物理地址到内核空间 */
    mapped = ioremap_cache(mapped_pa, mapped_size);
    if (!mapped)
        return 0;

    /* 从用户空间复制数据 */
    if (copy_from_user(mapped + (pa & (PAGE_SIZE - 1)), buffer, size)) {
        iounmap(mapped);
        return 0;
    }

    /* 取消映射 */
    iounmap(mapped);
    return size;
}

/* 读取进程内存 */
bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size, int read_write)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task)
        return false;
    mm = get_task_mm(task);
    if (!mm)
        return false;

    /* 尝试从缓存中获取物理地址 */
    pa = lookup_phys_cache(addr);
    if (!pa) {
        pa = translate_linear_address(mm, addr);
        if (pa)
            update_phys_cache(addr, pa);
    }

    while (size > 0) {
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (!pa)
            goto none_phy_addr;
        count += read_physical_address(pa, buffer, max);
        pa = 0; // 重置物理地址
        size -= max;
        buffer += max;
        addr += max;
        /* 尝试从缓存中获取下一个物理地址 */
        pa = lookup_phys_cache(addr);
        if (!pa) {
            pa = translate_linear_address(mm, addr);
            if (pa)
                update_phys_cache(addr, pa);
        }
    }

none_phy_addr:
    mmput(mm);
    return count;
}

/* 写入进程内存 */
bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size, int read_write)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task)
        return false;
    mm = get_task_mm(task);
    if (!mm)
        return false;

    /* 尝试从缓存中获取物理地址 */
    pa = lookup_phys_cache(addr);
    if (!pa) {
        pa = translate_linear_address(mm, addr);
        if (pa)
            update_phys_cache(addr, pa);
    }

    while (size > 0) {
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (!pa)
            goto none_phy_addr;
        count += write_physical_address(pa, buffer, max);
        pa = 0; // 重置物理地址
        size -= max;
        buffer += max;
        addr += max;
        /* 尝试从缓存中获取下一个物理地址 */
        pa = lookup_phys_cache(addr);
        if (!pa) {
            pa = translate_linear_address(mm, addr);
            if (pa)
                update_phys_cache(addr, pa);
        }
    }

none_phy_addr:
    mmput(mm);
    return count;
}