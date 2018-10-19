/** @file
    A simple OS Loader that load Dtb, Initrd and Linux Kernel from XIP flash memory.

    Copyright (c) 2018 Chen Baozi <cbz@baozis.org>. All rights reserved.<BR>
    This program and the accompanying materials
    are licensed and made available under the terms and conditions of the BSD License
    which accompanies this distribution. The full text of the license may be found at
    http://opensource.org/licenses/bsd-license.

    THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
    WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>

#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>

#include <libfdt.h> // EmbeddedPkg/Library/FdtLib

#define FLASH_BASE          0x0       // 0
#define FLASH_FDT_OFFSET    0x200000  // 2M
#define FLASH_KERNEL_OFFSET 0x400000  // 4M
#define FLASH_INITRD_OFFSET 0x2000000 // 32M

#define FDT_ADDR            (FLASH_BASE + FLASH_FDT_OFFSET)
#define INITRD_ADDR         (FLASH_BASE + FLASH_INITRD_OFFSET)
#define KERNEL_ADDR         (FLASH_BASE + FLASH_KERNEL_OFFSET)

#define FDT_BLOCK_SIZE      1048576	  // <2M
#define KERNEL_BLOCK_SIZE   14516736  // <28M
#define INITRD_BLOCK_SIZE   16724866	// <32M

#define FDT_ADDITIONAL_ENTRIES_SIZE 0x400

#define KERNEL_ARGS_SIZE    512
#define KERNEL_CMDLINE L"console=tty0 console=ttyAMA0,115200 earlyprintk=ttyAMA0,115200 root=/dev/ram0" // EFI handle string in UTF-8

typedef struct {
  MEMMAP_DEVICE_PATH Node1;
  EFI_DEVICE_PATH_PROTOCOL End;
} MEMORY_DEVICE_PATH;

STATIC CONST MEMORY_DEVICE_PATH mMemoryDevicePathTemplate =
{
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_MEMMAP_DP,
      {
        (UINT8)(sizeof(MEMMAP_DEVICE_PATH)),
        (UINT8)((sizeof(MEMMAP_DEVICE_PATH)) >> 8),
      },
    }, // Header
    0, // StartingAddress (set at runtime)
    0  // EndingAddress   (set at runtime)
  }, // Node1
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { sizeof(EFI_DEVICE_PATH_PROTOCOL), 0 }
  } // End
};

INTN
FlashLoaderGetChosenNode(
  IN INTN UpdatedFdtBase
  )
{
  INTN ChosenNode;

  ChosenNode = fdt_subnode_offset((CONST VOID *)UpdatedFdtBase, 0, "chosen");
  if (ChosenNode < 0)
  {
    ChosenNode = fdt_add_subnode((VOID *)UpdatedFdtBase, 0, "chosen");
    if (ChosenNode < 0)
    {
      DEBUG((DEBUG_ERROR, "Fail to find fdt node chosen!\n"));
      return 0;
    }
  }
  return ChosenNode;
}

EFI_STATUS
FlashLoaderSetProperty64 (
  IN  INTN        UpdatedFdtBase,
  IN  INTN        ChosenNode,
  IN  CHAR8      *PropertyName,
  IN  UINT64      Val
  )
{
  INTN                  Err;
  struct fdt_property  *Property;
  int                   Len;

  Property = fdt_get_property_w (
                (VOID *)UpdatedFdtBase,
                ChosenNode,
                PropertyName,
                &Len
                );
  if (NULL == Property && Len == -FDT_ERR_NOTFOUND) {  // No chosen node in the FDT
    Val = cpu_to_fdt64(Val);
    Err = fdt_appendprop (
                          (VOID *)UpdatedFdtBase,     // In Param
                          ChosenNode,                 // In Param
                          PropertyName,               // In Param
                          &Val,                       // In Param
                          sizeof(UINT64));
  } else if (Property != NULL) {                      // Already has chosen node
    Err = fdt_setprop_u64 (
                           (VOID *)UpdatedFdtBase,    // In Param
                           ChosenNode,                // IN Param
                           PropertyName,              // IN Param
                           Val                        // IN Param
                          );
  } else {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
FlashLoaderUpdateFdt (
  IN  VOID               *FdtBase,
  IN  VOID               *RamdiskData,
  IN  UINTN               RamdiskSize
  )
{
  INTN                    ChosenNode, Err, NewFdtSize;
  EFI_STATUS              Status;
  EFI_PHYSICAL_ADDRESS    UpdatedFdtBase;

  // Extended and Allocate FDT memory region.
  NewFdtSize = (UINTN)fdt_totalsize (FdtBase) + FDT_ADDITIONAL_ENTRIES_SIZE;
  Print(L"Original FDT starts at 0x%lx with size %d bytes.\n",
        FdtBase, fdt_totalsize(FdtBase));
  Print(L"We will extended new FDT buffer to size 0x%x.\n", NewFdtSize);
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData,
                  EFI_SIZE_TO_PAGES (NewFdtSize), &UpdatedFdtBase);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "Warning: Failed to reallocate FDT, err %d.\n",
            Status));
    return Status;
  } else {
    Print(L"Allocate new buffer for relocated FDT (@0x%lx).\n", UpdatedFdtBase);
  }

  // Load the Original FDT tree into the new region
  Err = fdt_open_into(FdtBase, (VOID *)(INTN)UpdatedFdtBase, NewFdtSize);
  if (Err) {
    DEBUG ((DEBUG_ERROR, "fdt_open_into(): %a\n", fdt_strerror (Err)));
    Status = EFI_INVALID_PARAMETER;
    goto Fdt_Exit;
  }

  ChosenNode = FlashLoaderGetChosenNode(UpdatedFdtBase);
  if (!ChosenNode) {
    goto Fdt_Exit;
  }

  // Set "linux,initrd-start" and "linux,initrd-end"
  Status = FlashLoaderSetProperty64 (UpdatedFdtBase, ChosenNode,
                                     "linux,initrd-start",
                                     (UINTN)RamdiskData);
  if (EFI_ERROR(Status)) {
    goto Fdt_Exit;
  }
  Status = FlashLoaderSetProperty64 (UpdatedFdtBase, ChosenNode,
                                     "linux,initrd-end",
                                     (UINTN)(RamdiskData + RamdiskSize));
  if (EFI_ERROR (Status)) {
    goto Fdt_Exit;
  }

  Status = gBS->InstallConfigurationTable (&gFdtTableGuid, (VOID *)(UINTN)UpdatedFdtBase);

  if (!EFI_ERROR(Status)) {
    Print(L"Successfully allocate new buffer for FDT and update the chosen node with initrd info.\n");
    return EFI_SUCCESS;
  }

Fdt_Exit:
  gBS->FreePages(UpdatedFdtBase, EFI_SIZE_TO_PAGES(NewFdtSize));
  return Status;
}

/***
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.
***/
EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  EFI_HANDLE                  KernelImageHandle;
  MEMORY_DEVICE_PATH	        KernelDevicePath;
  EFI_LOADED_IMAGE_PROTOCOL  *KernelImageInfo;

  VOID                       *KernelArg;
  VOID                       *NewKernelArg;

  VOID	                     *OrigKernel;
  UINTN                       KernelSize;

  VOID                       *OrigFdt;

  VOID                       *Ramdisk;
  VOID                       *OrigRamdisk;
  UINTN                       RamdiskSize;

  Print(L"Enter FlashLoader.\n");

  OrigFdt = (VOID *)FDT_ADDR;
  Print(L"Device Tree Blob starts at 0x%lx\n", OrigFdt);
  
  //
  // Load the Initrd from a fixed address
  //
  OrigRamdisk = (VOID *)INITRD_ADDR;
  Print(L"OrigRamdisk starts at 0x%lx .\n", OrigRamdisk);
  RamdiskSize = INITRD_BLOCK_SIZE;
  Print(L"Size of Ramdisk: 0x%lx\n", RamdiskSize);
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData,
                  EFI_SIZE_TO_PAGES (RamdiskSize), (EFI_PHYSICAL_ADDRESS *)&Ramdisk);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "Warning: Failed to reallocate Ramdisk, err %d.\n",
            Status));
    return Status;
  } else {
    Print(L"Allocate %d pages (%d bytes) for Ramdisk, starts at 0x%lx\n",
          EFI_SIZE_TO_PAGES (RamdiskSize), EFI_SIZE_TO_PAGES(RamdiskSize)*4096, Ramdisk);
  }
  gBS->CopyMem (Ramdisk, OrigRamdisk, RamdiskSize);

  //
  // Reallocate and extend FDT with chosen node region.
  // Add "linux,initrd-start" and "linux,initrd-end" entries to the chosen node (of DTB).
  // Install FDT as a configuration table.
  //
  FlashLoaderUpdateFdt (OrigFdt, Ramdisk, RamdiskSize);
   
  //
  // Load the Kernel (with EFI stub) from the fixed location with
  // EFI_BOOT_SERVICES.LoadImage service using the SourceBuffer and SourceSize
  // parameters.
  //
  OrigKernel = (VOID *)KERNEL_ADDR;
  KernelSize = KERNEL_BLOCK_SIZE;
  Print(L"Load the kernel from 0x%lx, which has the size of %d\n",
        OrigKernel, KernelSize);

  KernelDevicePath = mMemoryDevicePathTemplate;
  KernelDevicePath.Node1.StartingAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) OrigKernel;
  Print(L"  Kernel starts from 0x%lx.\n", KernelDevicePath.Node1.StartingAddress);
  KernelDevicePath.Node1.EndingAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) OrigKernel + KernelSize;
  Print(L"  Kernel ends at 0x%lx.\n", KernelDevicePath.Node1.EndingAddress);
  Print(L"Before calling gBS->LoadImage.\n");
  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  (EFI_DEVICE_PATH *)&KernelDevicePath,
                  (VOID *)(UINTN)OrigKernel,
                  KernelSize,
                  &KernelImageHandle);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to LoadImage\n");
    return Status;
  } else {
    Print(L"LoadImage looks successful.\n");
  }

  //
  // Add the kernel command line in the LoadOptions string
  //
  
  KernelArg = KERNEL_CMDLINE;
  Print(L"Static kernel args: %s\n", KernelArg);
  
  Status = gBS->AllocatePool (EfiBootServicesData, StrLen(KernelArg), &NewKernelArg);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_WARN, "Warning: Failed to allocate kernel args buffer, err %d.\n",
           Status));
    return Status;
  } else {
    Print(L"AllocatePool succeeded for NewKernelArg.\n");
  }
  StrnCpyS(NewKernelArg, KERNEL_ARGS_SIZE, KernelArg, StrLen(KernelArg));
  Print(L"Kernel cmdline: %s\n", NewKernelArg);
  
  Status = gBS->HandleProtocol (
                  KernelImageHandle, 
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&KernelImageInfo);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to HandleProtocol gEfiLoadedImageProtocolGuid.\n");
    return Status;
  }
  KernelImageInfo->LoadOptions = NewKernelArg;
  KernelImageInfo->LoadOptionsSize = StrLen (NewKernelArg) * sizeof (CHAR16);

  //
  // Start the Kernel with EFI_BOOT_SERVICES.StartImage boot service
  //
  Status = gBS->StartImage (KernelImageHandle, 0, NULL);

  Print(L"Failed to StartImage.\n");
  // When successful, not reach.
  gBS->UnloadImage (KernelImageHandle);
  // TODO: Free LoadOptions

  return Status;
}
