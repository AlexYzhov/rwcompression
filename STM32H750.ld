/*
*****************************************************************************
**

**  File        : LinkerScript.ld
**
**  Abstract    : Linker script for STM32H750 Device with
**                EXTERNAL-SPI FLASH, 512KByte RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used.
**
**  Target      : STMicroelectronics STM32
**
**
**  Distribution: The file is distributed as is, without any warranty
**                of any kind.
**
**  (c)Copyright Ac6.
**  You may use this file as-is or modify it according to the needs of your
**  project. Distribution of this file (unmodified or modified) is not
**  permitted. Ac6 permit registered System Workbench for MCU users the
**  rights to distribute the assembled, compiled & linked contents of this
**  file as part of an application binary file, provided that it is built
**  using the System Workbench for MCU toolchain.
**
*****************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Default value set in .data section */
PROVIDE(_sidata = 0x00);

/* Default value of the end of heap */
PROVIDE(end = 0x00);

/* Generate a link error if heap and stack don't fit into RAM */
_Min_Heap_Size  = 0x200;        /* required amount of heap  */
_Min_Stack_Size = 0x400;        /* required amount of stack */

/* Specify the memory areas */
MEMORY
{
/*INTERNAL (rx)   : ORIGIN = 0x08000000, LENGTH = 2048K*/
/*EXTERNAL (rx)   : ORIGIN = 0x90000000, LENGTH = 8192K*/
/*RAM (xrw)       : ORIGIN = 0x24000000, LENGTH = 512K*/
FLASH_STARTUP   (rx)  : ORIGIN = 0x08000000, LENGTH = 16K
FLASH_APP       (rx)  : ORIGIN = 0x08004000, LENGTH = 2032K
SPI_FLASH       (rx)  : ORIGIN = 0x90000000, LENGTH = 8192K
SRAM1           (xrw) : ORIGIN = 0x24000000, LENGTH = 416K
BLACKBOX        (rw)  : ORIGIN = 0x24068000, LENGTH = 32K
TCM             (xrw) : ORIGIN = 0x24070000, LENGTH = 64K
}

/* Define output sections */
SECTIONS
{
  /* The startup code goes first into FLASH */
  .isr_vector 0x08000000 : AT(0x08000000)
  {
    . = ALIGN(4);
    KEEP (*(.isr_vector))   /* Startup code */
    . = ALIGN(4);
  } >FLASH_STARTUP
  __isr_vector_start__ = ADDR(.isr_vector);
  __isr_vector_end__   = __isr_vector_start__ + SIZEOF(.isr_vector);

  /* The program code and other data goes into FLASH */
  .text : ALIGN(4)
  {
    . = ALIGN(4);
    _stext = .;

    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP(*(.init))
    KEEP(*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >FLASH_APP
  __text_start__ = ADDR(.text);
  __text_end__   = __text_start__ + SIZEOF(.text);

  /* Constant data goes into FLASH */
  .rodata __text_end__ : ALIGN(4)
  {
    . = ALIGN(4);
    _srodata = .;

    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */

    . = ALIGN(4);
    _erodata = .;
  } >FLASH_APP
  __rodata_start__ = ADDR(.rodata);
  __rodata_end__   = __rodata_start__ + SIZEOF(.rodata);

  .ARM.attributes : ALIGN(4)
  {
    . = ALIGN(4);
    *(.ARM.attributes)
    . = ALIGN(4);
  } >FLASH_APP
  __arm_attributes_start__ = ADDR(.ARM.attributes);
  __arm_attributes_end__   = __arm_attributes_start__ + SIZEOF(.ARM.attributes);

  .ARM.extab __arm_attributes_end__ : ALIGN(4)
  {
    . = ALIGN(4);
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    . = ALIGN(4);
  } >FLASH_APP
  __arm_extab_start__ = ADDR(.ARM.extab);
  __arm_extab_end__   = __arm_extab_start__ + SIZEOF(.ARM.extab);

  .ARM __arm_extab_end__ : ALIGN(4)
  {
    . = ALIGN(4);
    *(.ARM.exidx*)
    . = ALIGN(4);
  } >FLASH_APP
  __arm_exidx_start__ = ADDR(.ARM);
  __arm_exidx_end__   = __arm_exidx_start__ + SIZEOF(.ARM);

  /* Remove information from the standard libraries */
  /DISCARD/ :
  {
    libc.a(*)
    libm.a(*)
    libgcc.a(*)
  }
}

/* User defined data sections */
SECTIONS
{
  /* product info */
  .product_info __arm_exidx_end__ : ALIGN(4)
  {
    KEEP(*(product_info))
  } >FLASH_APP
  __product_info_start__  = ADDR(.product_info);
  __product_info_end__    = __product_info_start__ + SIZEOF(.product_info);

  /* device info */
  .device_info __product_info_end__ : ALIGN(4)
  {
    KEEP(*(device_info))
  } >FLASH_APP
  __device_info_start__  = ADDR(.device_info);
  __device_info_end__    = __device_info_start__ + SIZEOF(.device_info);

  /* startup init region */
  .init_region __device_info_end__ : ALIGN(4)
  {
    KEEP(*(__init_core_stage_0__))
    KEEP(*(__init_core_stage_1__))
    KEEP(*(__init_core_stage_2__))
    KEEP(*(__init_core_stage_3__))
    KEEP(*(__init_core_stage_4__))

    KEEP(*(__init_subsys_stage_0__))
    KEEP(*(__init_subsys_stage_1__))
    KEEP(*(__init_subsys_stage_2__))
    KEEP(*(__init_subsys_stage_3__))
    KEEP(*(__init_subsys_stage_4__))

    KEEP(*(__init_bsp_stage_0__))
    KEEP(*(__init_bsp_stage_1__))
    KEEP(*(__init_bsp_stage_2__))
    KEEP(*(__init_bsp_stage_3__))
    KEEP(*(__init_bsp_stage_4__))

    KEEP(*(__init_driver_stage_0__))
    KEEP(*(__init_driver_stage_1__))
    KEEP(*(__init_driver_stage_2__))
    KEEP(*(__init_driver_stage_3__))
    KEEP(*(__init_driver_stage_4__))

    KEEP(*(__init_env_stage_0__))
    KEEP(*(__init_env_stage_1__))
    KEEP(*(__init_env_stage_2__))
    KEEP(*(__init_env_stage_3__))
    KEEP(*(__init_env_stage_4__))

    KEEP(*(__init_device_stage_0__))
    KEEP(*(__init_device_stage_1__))
    KEEP(*(__init_device_stage_2__))
    KEEP(*(__init_device_stage_3__))
    KEEP(*(__init_device_stage_4__))

    KEEP(*(__init_app_stage_0__))
    KEEP(*(__init_app_stage_1__))
    KEEP(*(__init_app_stage_2__))
    KEEP(*(__init_app_stage_3__))
    KEEP(*(__init_app_stage_4__))
  } >FLASH_APP
  __init_region_start__ = ADDR(.init_region);
  __init_region_end__   = __init_region_start__ + SIZEOF(.init_region);
  __init_region_size__  = __init_region_end__ - __init_region_start__;

  /* power off deinit region */
  .deinit_region __init_region_end__ : ALIGN(4)
  {
  } >FLASH_APP
  __deinit_region_start__ = ADDR(.deinit_region);
  __deinit_region_end__   = __deinit_region_start__ + SIZEOF(.deinit_region);
  __deinit_region_size__  = __deinit_region_end__ - __deinit_region_start__;

  .exception_region __deinit_region_end__ : ALIGN(4)
  {
    KEEP (*(.exception))
  } >FLASH_APP
  __exception_region_start__ = ADDR(.exception_region);
  __exception_region_end__   = __exception_region_start__ + SIZEOF(.exception_region);
  __exception_region_size    = __exception_region_end__ - __exception_region_start__;

  /* logifier topic descriptions */
  .logifier_region __exception_region_end__ : ALIGN(4)
  {
    KEEP(*:*(.logifier_metadata))
  } >FLASH_APP
  __logifier_region_start__ = ADDR(.logifier_region);
  __logifier_region_end__   = __logifier_region_start__ + SIZEOF(.logifier_region);
  __logifier_region_size__  = __logifier_region_end__ - __logifier_region_start__;

  /* ushell command descriptions */
  .ushell_region __logifier_region_end__ : ALIGN(4)
  {
    KEEP(*:*(.ushell_command))
  } >FLASH_APP
  __ushell_region_start__ = ADDR(.ushell_region);
  __ushell_region_end__   = __ushell_region_start__ + SIZEOF(.ushell_region);
  __ushell_region_size__  = __ushell_region_end__ - __ushell_region_start__;
}

SECTIONS
{
  /* ram function & data relocated to TCM */
  .tcm 0x24070000 : ALIGN(4)
  {
    . = ALIGN(8);
    _stcm = .;

    *(tcm_func)
    *(tcm_data)

    . = ALIGN(8);
    _etcm = .;
  } >TCM AT>FLASH_APP
  __tcm_start__ = ADDR(.tcm);
  __tcm_end__   = __tcm_start__ + SIZEOF(.tcm);
  __tcm_size__  = __tcm_end__ - __tcm_start__;

  /* mem0 pool */
  .mem0_pool :
  {
    . = ALIGN(4);
  } >SRAM1 AT>FLASH_APP
  __mem0_pool_start__ = ADDR(.mem0_pool);
  __mem0_pool_end__   = __mem0_pool_start__ + SIZEOF(.mem0_pool);
  __mem0_pool_size__  = __mem0_pool_end__ - __mem0_pool_start__;

  /* mem1 pool */
  .mem1_pool :
  {
    . = ALIGN(4);
  } >SRAM1 AT>FLASH_APP
  __mem1_pool_start__ = ADDR(.mem1_pool);
  __mem1_pool_end__   = __mem1_pool_start__ + SIZEOF(.mem1_pool);
  __mem1_pool_size__  = __mem1_pool_end__ - __mem1_pool_start__;

  /* mem2 pool */
  .mem2_pool :
  {
    . = ALIGN(4);
  } >SRAM1 AT>FLASH_APP
  __mem2_pool_start__ = ADDR(.mem2_pool);
  __mem2_pool_end__   = __mem2_pool_start__ + SIZEOF(.mem2_pool);
  __mem2_pool_size__  = __mem2_pool_end__ - __mem2_pool_start__;

  /* mem3 pool */
  .mem3_pool :
  {
    . = ALIGN(4);
  } >SRAM1 AT>FLASH_APP
  __mem3_pool_start__ = ADDR(.mem3_pool);
  __mem3_pool_end__   = __mem3_pool_start__ + SIZEOF(.mem3_pool);
  __mem3_pool_size__  = __mem3_pool_end__ - __mem3_pool_start__;
}

SECTIONS
{
  /* Initialized data sections goes into RAM, load LMA copy after code */
  .data 0x24000000 : ALIGN(4)
  {
    . = ALIGN(4);
    _sdata = .;        /* create a global symbol at data start */

    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */

    . = ALIGN(4);
    _edata = .;        /* define a global symbol at data end */
  } >SRAM1 AT>FLASH_APP
  _sidata         = LOADADDR(.data);
  __data_start__  = ADDR(.data);
  __data_end__    = __data_start__ + SIZEOF(.data);
  __data_size__   = __data_end__ - __data_start__;

  /* Uninitialized data section */
  .bss _edata (NOLOAD) : ALIGN(4)
  {
    /* This is used by the startup in order to initialize the .bss secion */
    . = ALIGN(4);
    _sbss = .;         /* define a global symbol at bss start */

    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
  } >SRAM1 AT>FLASH_APP

  .ARM_LIB_HEAP 0x24066000 (NOLOAD) : ALIGN(8)
  {
    . = ALIGN(8);
    _sheap = .;
  } >SRAM1 AT>FLASH_APP
  PROVIDE(_eheap = 0x24066C00);
  end = _eheap;
  __heap_start__  = _sheap;
  __heap_end__    = _eheap;
  __heap_size__   = __heap_end__ - __heap_start__;
  ASSERT(__heap_size__ > _Min_Heap_Size, "The size of ARM_LIB_HEAP section does not fit the minimum requiry")

  .ARM_LIB_STACK 0x24066C00 (NOLOAD) : ALIGN(8)
  {
    . = ALIGN(8);
    _sstack = .;
  } >SRAM1 AT>FLASH_APP
  PROVIDE(_estack = 0x24068000);
  __stack_start__ = _sstack;
  __stack_end__   = _estack;
  __stack_size__  = __stack_end__ - __stack_start__;
  ASSERT(__stack_size__ > _Min_Stack_Size, "The size of ARM_LIB_STACK section does not fit the minimum requiry")

  .blackbox 0x24068000 (NOLOAD) : ALIGN(8)
  {
    . = ALIGN(8);
    PROVIDE (_sblackbox = .);
  } >BLACKBOX AT>FLASH_APP
  PROVIDE (_eblackbox = 0x24070000);
  __blackbox_start__ = _sblackbox;
  __blackbox_end__   = _eblackbox;
  __blackbox_size__  = __blackbox_end__ - __blackbox_start__;
}
