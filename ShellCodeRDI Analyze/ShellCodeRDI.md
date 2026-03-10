# ShellCodeRDI Analyze

https://github.com/monoxgas/sRDI/tree/master/ShellcodeRDI

## Tổng quát:

Trọng tâm bài này xoay quanh hàm _LoadDLL_ nằm trong file _ShellcodeRDI.c_. Hàm này sử dụng kĩ thuật API Hashing + Reflective DLL Injection để ẩn giấu DLL độc hại khi chèn vào memory

## Cú pháp:

```c
ULONG_PTR LoadDLL(
    PBYTE     pbModule,
    DWORD     dwFunctionHash,
    LPVOID    lbUserData,
    PVOID     pbShellcodeBase,
    DWORD     dwFlags
);
```

## Params:

`PBYTE pbModule`
Là con trỏ trỏ tới offset đầu tiên của DLL file, dựa trên việc param xuất hiện trong file luôn được đi cùng struct _PIMAGE_DOS_HEADER_. Ngoài DLL file ra thì bất cứ file PE khác đều có thể sử dụng được, nhưng mà mục đích chính của param này chỉ có vậy.

`DWORD dwFunctionHash`
Dựa trên cái tên thì đây có vẻ là đoạn hash sau khi hash hàm. Param này nếu không sử dụng thì để giá trị là 0. Vai trò chính của param này sẽ được nói tới ở Step 11.

`LPVOID lpUserData`
Chưa rõ vai trò của biến này, nhưng có vẻ là giá trị không thể là null. Sẽ update thêm tại Step 11.

`DWORD dwUserdataLen`
Kích cỡ của lpUserData.

`PVOID pvShellcodeBase`
Chưa rõ vai trò của biến này, nhưng có vẻ là giá trị không thể là null. Sẽ update thêm tại Step 11.

`DWORD dwFlags`
Các giá trị dwFlags sử dụng bao gồm:

```c
#define SRDI_CLEARHEADER 0x1
#define SRDI_CLEARMEMORY 0x2
#define SRDI_OBFUSCATEIMPORTS 0x4
#define SRDI_PASS_SHELLCODE_BASE 0x8
```

Như cái tên và các giá trị thể hiện, biến này sẽ thực thi một số đoạn code nhất định nằm trong các step, chi tiết sẽ thể hiện sau

## Cấu trúc:

### Step 1

Đoạn code ở đây sử dụng API Hashing. Cụ thể, ở 2 biến _pLdrLoađll_ và _pLdrGetProcAddress_ sử dụng hàm _GetProcAddressHash_ để đối chiếu đoạn hash đã có sẵn trong file:

```c
pLdrLoadDll = (LDRLOADDLL)GetProcAddressWithHash(LDRLOADDLL_HASH);
pLdrGetProcAddress = (LDRGETPROCADDRESS)GetProcAddressWithHash(LDRGETPROCADDRESS_HASH);
```

Dưới đây là struct đầy đủ của 2 hàm trên:

```c
NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
    );
-------------------------------------
NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    _In_ PVOID DllHandle,
    _In_opt_ PCANSI_STRING ProcedureName,
    _In_opt_ ULONG ProcedureNumber,
    _Out_ PVOID *ProcedureAddress
    );
```

Vai trò của 2 hàm trên giống như LoadLibraryA và GetProcAddress, có vẻ mục đích chính là để tránh các công cụ phát hiện thứ tự và số lượng các param giống với LoadLibraryA và GetProcAddress.

Sau đó, các hàm cần cho chương trình được nạp vào:

```c
pLdrLoadDll(NULL, 0, &uString, &library);

FILL_STRING_WITH_BUF(aString, sVirtualAlloc);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pVirtualAlloc);

FILL_STRING_WITH_BUF(aString, sVirtualProtect);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pVirtualProtect);

FILL_STRING_WITH_BUF(aString, sFlushInstructionCache);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pFlushInstructionCache);

FILL_STRING_WITH_BUF(aString, sGetNativeSystemInfo);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pGetNativeSystemInfo);

FILL_STRING_WITH_BUF(aString, sSleep);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pSleep);

FILL_STRING_WITH_BUF(aString, sRtlAddFunctionTable);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pRtlAddFunctionTable);

FILL_STRING_WITH_BUF(aString, sLoadLibrary);
pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pLoadLibraryA);

//FILL_STRING_WITH_BUF(aString, sMessageBox);
//pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pMessageBoxA);

if (pVirtualAlloc || pVirtualProtect || pSleep ||
    pFlushInstructionCache || pGetNativeSystemInfo) {
    return 0;
}
```

### Step 2

Sau khi đã có các hàm cần sử dụng, chương trình lấy địa chỉ _ntHeaders_ qua hàm custom _RVA_ có chức năng tính toán địa chỉ cần lấy.

```c
#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)

...

ntHeaders = RVA(PIMAGE_NT_HEADERS, pbModule, ((PIMAGE_DOS_HEADER)pbModule)->e_lfanew);

if (ntHeaders->Signature = IMAGE_NT_SIGNATURE)
    return 0;

if (ntHeaders->FileHeader.Machine = HOST_MACHINE)
    return 0;

if (ntHeaders->OptionalHeader.SectionAlignment & 1)
    return 0;
```

Sau khi xác định được _ntHeaders_, chương trình căn chỉnh (align) RVA sao cho hệ thống sẽ luôn cấp phát đủ bộ nhớ cho các sections

```c
sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
lastSectionEnd = 0;

for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
    if (sectionHeader->SizeOfRawData == 0) {
        endOfSection = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.SectionAlignment;
    }
    else {
        endOfSection = sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData;
    }

    if (endOfSection > lastSectionEnd) {
        lastSectionEnd = endOfSection;
    }
}

pGetNativeSystemInfo(&sysInfo);
alignedImageSize = (DWORD)AlignValueUp(ntHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
if (alignedImageSize = AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
    return 0;
}
```

Đoạn mã tính toán bắt đầu từ sections đầu tiên có trong chương trình, sau đó đi qua các sections và lưu địa chỉ section kế tiếp. Ta có 2 trường hợp:

- Trường hợp 1 (_SizeOfRawData_ = 0): Dành cho những section đã có dữ liệu trên disk (.data, .text,...) thì địa chỉ kết thúc section = _virtualAddress_ + _sizeOfRawData_
- Trường hợp 2 (_SizeOfRawData_ == 0): Dành cho những section chưa có dữ liệu nằm trên disk, thì địa chỉ sẽ được đặt là một lần căn chỉnh của section (_sectionAlignment_), tức _endOfsection_ = _virtualAddress_ + _sectionAlignment_

Sau khi tính toán được địa chỉ kết thúc của section cuối cùng, chương trình kiểm tra xem việc tính toán _lastSectionEnd_ có bằng _SizeOfImage_ hay là không, tức là chương trình đang thực hiện nạp thủ công image mà không khiến xung đột memory.

Hàm _AlignValueUp_ ở đây có chức năng là tính toán kích thước bộ nhớ dựa trên logic của Windows là làm tròn lên theo SectionAlignment:

```c
static inline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}
```

(_Một điều đáng lưu ý là các đoạn code trong step 2 đều được mượn từ [MemoryModule](https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c), một repo với vai trò chính là hỗ trợ load DLL trực tiếp từ memory mà không phải qua bước trung gian là lưu trữ trên disk, nên ta có thể dễ hình dung mục đích của các bước tiếp theo._)

Sau khi căn chỉnh sao cho vừa với page size, chương trình tạo không gian bộ nhớ để load DLL vào.

```c
baseAddress = (ULONG_PTR)pVirtualAlloc(
    (LPVOID)(ntHeaders->OptionalHeader.ImageBase),
    alignedImageSize,
    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
);

if (baseAddress == 0) {
    baseAddress = (ULONG_PTR)pVirtualAlloc(
        NULL,
        alignedImageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );
}
```

Giá trị của _baseAddress_ sẽ phụ thuộc vào việc liệu giá trị _imageBase_ có được chấp nhận hay không. Tức là nếu memory cho phép script tạo không gian bộ nhớ tại địa chỉ imageBase thì baseAddress sẽ có giá trị, còn nếu không thì baseAddress sẽ không được nhận và để hệ thống quyết định vị trí của image. Cách làm này khá giống việc liệu chương trình có đang bật ASLR hay là không. Vai trò của việc làm này sẽ được giải thích tiếp tại Step 4.

Đoạn cuối step 2 cho ta biết được ý nghĩa của 1 trong các flags:

```c
if (dwFlags & SRDI_CLEARHEADER) {
    ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew = ((PIMAGE_DOS_HEADER)pbModule)->e_lfanew;

    for (i = ((PIMAGE_DOS_HEADER)pbModule)->e_lfanew; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++) {
        ((PBYTE)baseAddress)[i] = ((PBYTE)pbModule)[i];
    }

}else{
    for (i = 0; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++) {
        ((PBYTE)baseAddress)[i] = ((PBYTE)pbModule)[i];
    }
}

ntHeaders = RVA(PIMAGE_NT_HEADERS, baseAddress, ((PIMAGE_DOS_HEADER)baseAddress)->e_lfanew);
```

Nếu _SRDI_CLEARHEADER_ được "dựng", chương trình sẽ chỉ copy dữ liệu bắt đầu từ giá trị của e_lfanew (tức offset của PE header) thay vì toàn bộ file DLL. Quan sát từ đầu, chương trình chưa bao giờ nhắc tới DOS Header, lý do là vì đây là 1 cách anti-analyst của DLL Injection. Khi ta dump 1 file bằng các công cụ hỗ trợ, chương trình sẽ cố gắng tìm từ giá trị 0x5A4D vì nó đánh dấu 1 file PE điển hình. Chính vì sự thiếu vắng của giá trị trên mà các chương trình tự động phát hiện sẽ gặp khó khăn trong việc phát hiện toàn bộ DLL đã inject vào memory.

### Step 3

Sau khi load các Headers vào memory, chương trình tiếp tục load các section đang nằm trên disk vào thẳng memory (có thể gọi đây là 1 cách mapping thủ công cũng được)

```c
sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
    for (c = 0; c < sectionHeader->SizeOfRawData; c++) {
        ((PBYTE)(baseAddress + sectionHeader->VirtualAddress))[c] = ((PBYTE)(pbModule + sectionHeader->PointerToRawData))[c];
    }
}
```

Vì đây là load DLL vào thẳng memory, nên việc ta phải thay hệ thống xử lý các bước này là điều thiết yếu, vì thế nên khá khó để các chương trình anti-virus phát hiện hành vi.

### Step 4

Nói tiếp về _ImageBase_, trong trường hợp giá trị _imageBase_ không được memory cho phép, hệ thống sẽ tạo 1 vùng nhớ khác rồi mapping dữ liệu sang vị trí mới đó. Để làm như vậy thì trong file có section _.reloc_ (hoặc là _.rdata_) chịu trách nhiệm cho việc hướng dẫn hệ thống mapping từ địa chỉ cũ sang địa chỉ mới.

Và nhiệm vụ của step 4 là đóng vai trò đó, bằng việc kiểm tra liệu _baseAddress_ có trùng khớp với _imageBase_ và _IMAGE_BASE_RELOCATION_ có giá trị hay là không, chương trình sẽ thay thế vai trò của .reloc để mapping.

```c
baseOffset = baseAddress - ntHeaders->OptionalHeader.ImageBase;
dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

if (baseOffset && dataDir->Size) {

    relocation = RVA(PIMAGE_BASE_RELOCATION, baseAddress, dataDir->VirtualAddress);

    while (relocation->VirtualAddress) {
        relocList = (PIMAGE_RELOC)(relocation + 1);

        while ((PBYTE)relocList = (PBYTE)relocation + relocation->SizeOfBlock) {

            if (relocList->type == IMAGE_REL_BASED_DIR64)
                *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += baseOffset;
            else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
                *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
            else if (relocList->type == IMAGE_REL_BASED_HIGH)
                *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += HIWORD(baseOffset);
            else if (relocList->type == IMAGE_REL_BASED_LOW)
                *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += LOWORD(baseOffset);

            relocList++;
        }
        relocation = (PIMAGE_BASE_RELOCATION)relocList;
    }
}
```

Đây là structure của _IMAGE_BASE_RELOCATION_:

```c
typedef struct _IMAGE_BASE_RELOCATION {
  DWORD   VirtualAddress;
  DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
```

Ngoài lề một chút, trong khi tìm kiếm lý do cho sự tồn tại của _IMAGE_BASE_RELOCATION_, mình tìm được một blog rất chi tiết về [cách inject code vào PE file](https://www.codeproject.com/articles/Inject-your-code-to-a-Portable-Executable-file). Blog này khai thác rất sâu vào PE file, nên khá là đáng để đọc đấy.

### Step 5

Để mà tóm tắt chức năng step 5 thì nó đơn giản là đẩy import table của DLL file vào memory, nên chức năng chính sẽ không phải thứ bàn tới. Thay vào đó là phần "không làm chức năng chính".

```c
randSeed = (DWORD)((ULONGLONG)pbModule);
importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, baseAddress, dataDir->VirtualAddress);
importCount = 0;
for (; importDesc->Name; importDesc++) {
    importCount++;
}


if (dwFlags & SRDI_OBFUSCATEIMPORTS && importCount > 1) {
    sleep = (dwFlags & 0xFFFF0000);
    sleep = sleep >> 16;

    for (i = 0; i < importCount - 1; i++) {
        randSeed = (214013 * randSeed + 2531011);
        rand = (randSeed >> 16) & 0x7FFF;
        selection = i + rand / (32767 / (importCount - i) + 1);

        tempDesc = importDesc[selection];
        importDesc[selection] = importDesc[i];
        importDesc[i] = tempDesc;
    }
}

...

    if (sleep && dwFlags & SRDI_OBFUSCATEIMPORTS && importCount > 1) {
        pSleep(sleep * 1000);
    }
```

Như tên của flag: _SRDI_OBFUSCATEIMPORTS_, vai trò của dòng code trên là gây rối _Import Directory Table_. Một trong các phương pháp để phân tích nhanh các mã độc là lưu trữ signature của đoạn mã đó, rồi đối chiếu với sample xem có trùng ở phần nào không. Việc thay đổi thứ tự các hàm import sẽ tạo ra nhiều biến thể của _import table_, gây khó khăn trong việc phát hiện. Còn đoạn sleep ở dưới đơn giản là khi các công cụ debugger tự động chạy đến dòng đó sẽ bị treo và không thể tiếp tục.

Ngoài lề một chút thì thuật toán được sử dụng khá giống _Fisher–Yates shuffle Algorithm_, với cách thức giống nhau về mặt triển khai.

### Step 6+7

Mình gộp 2 step này vì ở step 6 có cách thức triển khai y hệt step 5 nhưng thay vì là import table thì là delayed import table, còn step 7 là thiết lập quyền truy cập cho các sections. Không có quá nhiều thứ để nói ở đây.

### Step 8

```c
dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

if (dataDir->Size)
{
    tlsDir = RVA(PIMAGE_TLS_DIRECTORY, baseAddress, dataDir->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *)(tlsDir->AddressOfCallBacks);

    for (; *callback; callback++) {
        (*callback)((LPVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
    }
}
```

Đoạn mã trên giả lập kĩ thuật của Windows Loader, nhằm đẩy các hàm nằm trong IMAGE_DIRECTORY_ENTRY_TLS lên trước việc thực thi hàm Main. Việc xuất hiện hàm chạy trước hàm Main không chỉ gây khó khăn cho các công cụ phân tích mà còn cho cả người phân tích nếu mà họ chỉ tập trung khi debugger chỉ đến _EntryPoint_. Các hàm check debugger có thể được đặt ở đây nhằm sớm biết được liệu chương trình có đang chạy "bên cạnh" debugger hay không thay vì đặt sau Entrypoint, nơi mà các decompiler hay các công cụ anti-antidebug đơn giản phát hiện được.

### Step 9+10

Vì nội dung của cả 2 bước này quá ngắn nên mình sẽ dán trực tiếp toàn bộ :>

```c
// STEP 9: Register exception handlers (x64 only)
///

#ifdef _WIN64
dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

if (pRtlAddFunctionTable && dataDir->Size)
{
    rfEntry = RVA(PIMAGE_RUNTIME_FUNCTION_ENTRY, baseAddress, dataDir->VirtualAddress);
    pRtlAddFunctionTable(rfEntry, (dataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, baseAddress);
}
#endif

///
// STEP 10: call our images entry point
///

dllMain = RVA(DLLMAIN, baseAddress, ntHeaders->OptionalHeader.AddressOfEntryPoint);
dllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);
```

### Step 11

Vai trò chính của step 11 nhằm tạo _export function table_. Quay lại ở mục Param, mình có nhắc về việc có các biến được đặt tại đây và lúc đấy mình chưa rõ vai trò của các param đấy. Nhưng có vẻ sau khi đọc lại thì mình khá hiểu về chức năng của các param đó:

```c
for (i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++) {

    expNameStr = RVA(LPCSTR, baseAddress, *expName);
    funcHash = 0;

    if (expNameStr)
        break;

    for (; *expNameStr; expNameStr++) {
        funcHash += *expNameStr;
        funcHash = ROTR32(funcHash, 13);

    }

    if (dwFunctionHash == funcHash && expOrdinal)
    {
        exportFunc = RVA(EXPORTFUNC, baseAddress, *(PDWORD)(baseAddress + exportDir->AddressOfFunctions + (*expOrdinal * 4)));

        if (dwFlags & SRDI_PASS_SHELLCODE_BASE) {
            exportFunc(pvShellcodeBase, sizeof(PVOID));
        } else {
            exportFunc(lpUserData, dwUserdataLen);
        }

        break;
    }
}
```

`pvShellcodeBase`
Chuyển tiếp Shellcode mong muốn cho các DLL file khác cần sử dụng
`dwFunctionHash`
Ngoài việc sử dụng API Hashing để che giấu tên hàm, thì tên hàm còn được sử dụng nhằm che đi nội dung thật là Shellcode hoặc dữ liệu người dùng được đẩy ra ngoài.
`lpUserData`
100% là dữ liệu người dùng, với cách thức chuyển tiếp y hệt cách chuyển tiếp shellcode

_(P/s 12/12/2025: Việc nói `lpUserData` là "dữ liệu người dùng" thực ra chưa chính xác, giống như việc thấy 1 câu lệnh `"Hello" + userData` và bào đây là leak thông tin vậy. Đây là một param, tức là dữ liệu đầu vào phụ thuộc vào người viết script, tức là có thể đây chứa shellcode hoặc cái gì đó khả nghi, chứ không phải dữ liệu của nạn nhân)_

Cuối cùng là xóa sạch dấu vết và trả lại handle cho module nhằm cho chuỗi tấn công nối tiếp sau đó:

```c
if (dwFlags & SRDI_CLEARMEMORY && pVirtualFree && pLocalFree) {
    if (pVirtualFree((LPVOID)pbModule, 0, 0x8000))
        pLocalFree((LPVOID)pbModule);
}

// Atempt to return a handle to the module
return baseAddress;
```

### (Các) yếu tố chưa được nhắc tới

Tên các module và các hàm không được lưu dưới dạng string mà dưới dạng chuỗi các kí tự (array of chars).

```c
WCHAR sKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'};

BYTE sSleep[] = { 'S', 'l', 'e', 'e', 'p' };
BYTE sLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A' };
BYTE sVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c' };
BYTE sVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't' };
BYTE sFlushInstructionCache[] = { 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e' };
BYTE sGetNativeSystemInfo[] = { 'G', 'e', 't', 'N', 'a', 't', 'i', 'v', 'e', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o' };
BYTE sRtlAddFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e' };
```

Trong C, ta đều biết bản chất string là một chuỗi các kí tự, nhưng có sự khác biệt giữa _BYTE sSleep[] = { 'S', 'l', 'e', 'e', 'p' };_ và _BYTE sSleep[] = "Sleep";_. Sự khác biệt nằm ở: Cách khai báo thứ 2 tồn tại kí tự '\0' báo kết thúc chuỗi, còn cách khai báo thứ 1 không có. Một số công cụ phát hiện sử dụng '\0' để phát hiện các chuỗi kí tự, sẽ có thể xảy ra lỗi là chuỗi "kernel32.dllabcdxef" không được phát hiện vì nó dính liền với các kí tự khác.
