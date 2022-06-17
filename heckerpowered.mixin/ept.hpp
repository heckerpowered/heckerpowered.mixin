#pragma once

//////////////////////////////////////////////////
//				Debugger Config                 //
//////////////////////////////////////////////////

#define MaximumHiddenBreakpointsOnPage 40

//////////////////////////////////////////////////
//					Constants					//
//////////////////////////////////////////////////

/**
 * @brief Page attributes for internal use
 *
 */
#define PAGE_ATTRIB_READ  0x2
#define PAGE_ATTRIB_WRITE 0x4
#define PAGE_ATTRIB_EXEC  0x8

/**
 * @brief The number of 512GB PML4 entries in the page table
 *
 */
#define VMM_EPT_PML4E_COUNT 512

/**
 * @brief The number of 1GB PDPT entries in the page table per 512GB PML4 entry
 *
 */
#define VMM_EPT_PML3E_COUNT 512

/**
 * @brief Then number of 2MB Page Directory entries in the page table per 1GB
 *  PML3 entry
 *
 */
#define VMM_EPT_PML2E_COUNT 512

/**
 * @brief Then number of 4096 byte Page Table entries in the page table per 2MB PML2
 * entry when dynamically split
 *
 */
#define VMM_EPT_PML1E_COUNT 512

/**
 * @brief Integer 2MB
 *
 */
#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))

/**
 * @brief Offset into the 1st paging structure (4096 byte)
 *
 */
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)

/**
 * @brief Index of the 1st paging structure (4096 byte)
 *
 */
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

/**
 * @brief Index of the 2nd paging structure (2MB)
 *
 */
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

/**
 * @brief Index of the 3rd paging structure (1GB)
 *
 */
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

/**
 * @brief Index of the 4th paging structure (512GB)
 *
 */
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)