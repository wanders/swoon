#include <efi.h>
#include <efilib.h>

#define VERSION "0.2"

extern char _kernel_data_begin[];
extern char _kernel_data_end[];

extern char _initrd_data_begin[];
extern char _initrd_data_end[];

extern char _creation_message[];

#define ERROR_STALL_TIME (3 * 1000 * 1000)
#define error(code, msg) ({Print(msg ": %r\n", code); uefi_call_wrapper(BS->Stall, 1, ERROR_STALL_TIME); err; })


/* $KERNEL_DIR/Documentation/x86/boot.txt */

#define LINUX_X86_BOOT_PROTO_type_of_loader_OFF 0x210
#define LINUX_X86_BOOT_PROTO_type_of_loader_TYPE UINT8
#define LINUX_X86_BOOT_PROTO_code32_start_OFF 0x214
#define LINUX_X86_BOOT_PROTO_code32_start_TYPE UINT32
#define LINUX_X86_BOOT_PROTO_ramdisk_image_OFF 0x218
#define LINUX_X86_BOOT_PROTO_ramdisk_image_TYPE UINT32
#define LINUX_X86_BOOT_PROTO_ramdisk_size_OFF 0x21c
#define LINUX_X86_BOOT_PROTO_ramdisk_size_TYPE UINT32
#define LINUX_X86_BOOT_PROTO_initrd_addr_max_OFF 0x22c
#define LINUX_X86_BOOT_PROTO_initrd_addr_max_TYPE UINT32
#define LINUX_X86_BOOT_PROTO_cmd_line_ptr_OFF 0x228
#define LINUX_X86_BOOT_PROTO_cmd_line_ptr_TYPE UINT32

#define LINUX_X86_BOOT_PROTO_setup_sects_OFF 0x1F1
#define LINUX_X86_BOOT_PROTO_setup_sects_TYPE UINT8

#define LINUX_X86_BOOT_PROTO_handover_offset_OFF 0x264
#define LINUX_X86_BOOT_PROTO_handover_offset_TYPE UINT32

#define LINUX_X86_BOOT_PROTO_SIZE 0x268


#define get_off(what) LINUX_X86_BOOT_PROTO_##what##_OFF
#define get_type(what) LINUX_X86_BOOT_PROTO_##what##_TYPE
#define _bootparam(base, off, type) (*((type *)(((char *)(base)) + (off))))
#define bootparam(base, what) _bootparam(base, get_off(what), get_type(what))

static EFI_STATUS hand_over_to_linux(EFI_HANDLE *image,
				     EFI_PHYSICAL_ADDRESS cmdline_addr,
				     UINTN linux_addr,
				     UINTN initrd_addr, UINTN initrd_size) {
        EFI_PHYSICAL_ADDRESS zero_page_addr;
	EFI_STATUS err;

        zero_page_addr = 0x3fffffff;
        err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
                                EFI_SIZE_TO_PAGES(0x4000), &zero_page_addr);
        if (EFI_ERROR(err))
                return err;

	EFI_PHYSICAL_ADDRESS linux_code32_start = linux_addr + (bootparam(linux_addr, setup_sects) + 1) * 512;

        ZeroMem((void *)zero_page_addr, 0x4000);

	/* boot.txt says 'All other fields should be zero.' but that
	 * doesn't seem to work */
        CopyMem((void *)zero_page_addr, (void *)linux_addr, LINUX_X86_BOOT_PROTO_SIZE);

	bootparam(zero_page_addr, type_of_loader) = 0xff;
	bootparam(zero_page_addr, cmd_line_ptr) = cmdline_addr;
	bootparam(zero_page_addr, code32_start) = linux_code32_start;
	bootparam(zero_page_addr, ramdisk_image) = initrd_addr;
	bootparam(zero_page_addr, ramdisk_size) = initrd_size;


	typedef VOID(*linux_efi_handover_func_t)(VOID *image, EFI_SYSTEM_TABLE *table, void *zero_page);

	Print(L"Handing over!\n");

	linux_efi_handover_func_t func;
	func = (linux_efi_handover_func_t) (linux_code32_start + bootparam(linux_addr, handover_offset) + 0x200);

        asm volatile ("cli");
	func (image, ST, (void *)zero_page_addr);

	/* will not return */
	return EFI_SUCCESS;
}


static EFI_STATUS build_kernel_commandline(EFI_HANDLE image, EFI_PHYSICAL_ADDRESS *out_cmdline)
{
	EFI_LOADED_IMAGE *loaded_image;
	EFI_STATUS err;

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, &loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
		return error(err, L"OpenProtocol of LoadedImageProtocol failed");
        }

	CHAR16 *efi_options;
	CHAR8 *kernel_cmdline;
	UINTN kernel_cmdline_len;
	efi_options = loaded_image->LoadOptions;
	kernel_cmdline_len = (loaded_image->LoadOptionsSize / sizeof(CHAR16)) * sizeof(CHAR8);

	EFI_PHYSICAL_ADDRESS addr;
	addr = 0xA0000;
	err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, EfiLoaderData,
				EFI_SIZE_TO_PAGES(kernel_cmdline_len + 1), &addr);

        if (EFI_ERROR(err)) {
		return error(err, L"AllocatePages for cmdline failed");
        }

	kernel_cmdline = (unsigned char *)addr;

	UINTN warned = 0;
	for (UINTN i = 0; i < kernel_cmdline_len; i++) {
		if (efi_options[i] > 127 && !warned) {
			Print(L"WARNING: There are non-ascii chars in commandline\n");
			uefi_call_wrapper(BS->Stall, 1, ERROR_STALL_TIME);
			warned = 1;
		}
		kernel_cmdline[i] = efi_options[i];
	}
	kernel_cmdline[kernel_cmdline_len] = 0;

	*out_cmdline = addr;

	return EFI_SUCCESS;
}

static EFI_STATUS memdup(EFI_PHYSICAL_ADDRESS *out_addr, UINTN *out_size,
			 void *start, void *end,
			 EFI_PHYSICAL_ADDRESS addr_hint, EFI_MEMORY_TYPE mem_type) {
	EFI_PHYSICAL_ADDRESS addr;
	EFI_STATUS err;

	UINTN siz = end - start;

	addr = addr_hint;
	err = uefi_call_wrapper(BS->AllocatePages, 4, AllocateMaxAddress, mem_type,
				EFI_SIZE_TO_PAGES(siz), &addr);

	if (EFI_ERROR(err))
		return error(err, L"AllocatePages failed");

	CopyMem((void *)addr, start, siz);

	*out_size = siz;
	*out_addr = addr;

	return EFI_SUCCESS;
}

static EFI_STATUS get_kernel(EFI_PHYSICAL_ADDRESS *out_kernel, UINTN *out_kernel_size) {
	return memdup(out_kernel, out_kernel_size,
		      _kernel_data_begin, _kernel_data_end,
		      0x3fffffff, EfiLoaderCode);
}

static EFI_STATUS get_initrd(EFI_PHYSICAL_ADDRESS *out_initrd, UINTN *out_initrd_size, EFI_PHYSICAL_ADDRESS kernel_addr) {
	return memdup(out_initrd, out_initrd_size,
		      _initrd_data_begin, _initrd_data_end,
		      bootparam(kernel_addr, initrd_addr_max), EfiLoaderData);
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *SystemTable) {
	EFI_STATUS err;

	InitializeLib(image, SystemTable);

	Print(L"SWOON v" VERSION "\n");
	Print(L"%s\n", _creation_message);

	Print(L"kernel...\n");
	EFI_PHYSICAL_ADDRESS kernel_addr;
	UINTN kernel_siz;
	err = get_kernel(&kernel_addr, &kernel_siz);
	if (EFI_ERROR(err))
		return err;
	Print(L"      ... stored in memory allocated at %lx\n", kernel_addr);

	Print(L"initrd...\n");
	EFI_PHYSICAL_ADDRESS initrd_addr;
	UINTN initrd_siz;
	err = get_initrd(&initrd_addr, &initrd_siz, kernel_addr);
	if (EFI_ERROR(err))
		return err;

	Print(L"      ... stored in memory allocated at %lx\n", initrd_addr);

	EFI_PHYSICAL_ADDRESS cmdline_addr;
	err = build_kernel_commandline (image, &cmdline_addr);
	if (EFI_ERROR(err))
		return err;

	err = hand_over_to_linux(image,
				 cmdline_addr, kernel_addr,
				 initrd_addr, initrd_siz);

	return error(err, L"Execution linux image failed");
}
