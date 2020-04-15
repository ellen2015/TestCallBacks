#include <ntddk.h>
#include <ntstrsafe.h>

NTKERNELAPI
UCHAR *PsGetProcessImageFileName(__in PEPROCESS Process);

NTSTATUS
PsLookupProcessByProcessId(IN HANDLE pid, OUT PEPROCESS *process);

NTSTATUS _stdcall ObQueryNameString(__in PVOID Object,
                                    __out_bcount_opt(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
                                    __in ULONG Length,
                                    __out PULONG ReturnLength);

// ��ȡע���Ķ�Ӧ��ȫ·����ƴ�ӵ�
BOOLEAN
GetRegistryObjectCompleteName(
    OUT PUNICODE_STRING pRegistryPath,
    IN PUNICODE_STRING pPartialRegistryPath,
    IN PVOID pRegistryObject)
{
    BOOLEAN foundCompleteName = FALSE;
    BOOLEAN partial = FALSE;

    // ȷ�������ڴ�ɷ���
    if ((!MmIsAddressValid(pRegistryObject)) ||
        (pRegistryObject == NULL))
    {
        return FALSE;
    }

    // �Ƿ����partial,�еû�ֱֻ�ӿ����������
    if (pPartialRegistryPath != NULL && pPartialRegistryPath->Buffer)
    {
        if (pPartialRegistryPath->Buffer[0] == L'\\')
        {
            RtlUnicodeStringCopy(pRegistryPath, pPartialRegistryPath);

            partial = TRUE;

            foundCompleteName = TRUE;
        }
    }

    // û�еĻ�ͨ��ע������ ��ȡ������
    if (!foundCompleteName)
    {
        NTSTATUS status;
        ULONG returnedLength;
        PUNICODE_STRING pObjectName = NULL;

        // �Ȼ�ȡע����������ռ�õ��ڴ��С
        status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // �����ڴ�
            pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'nxxh');

            // ��ȡ����
            status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);

            if (NT_SUCCESS(status))
            {
                //����ƴ��
                RtlUnicodeStringCopy(pRegistryPath, pObjectName);

                if (pPartialRegistryPath && pPartialRegistryPath->Buffer && pPartialRegistryPath->Buffer[0] != L'\\')
                {
                    RtlUnicodeStringCatString(pRegistryPath, L"\\");

                    RtlUnicodeStringCat(pRegistryPath, pPartialRegistryPath);
                }

                foundCompleteName = TRUE;
            }

            // �ͷ��ڴ�
            ExFreePoolWithTag(pObjectName, 'nxxh');
        }
    }

    return foundCompleteName;
}

BOOLEAN
IsAbsolute(PREG_CREATE_KEY_INFORMATION pCreateInfo)
{
    BOOLEAN bAbsolute = FALSE;
    do
    {
        if (pCreateInfo == NULL)
        {
            break;
        }
        if (!pCreateInfo->CompleteName || !pCreateInfo->CompleteName->Buffer || !pCreateInfo->CompleteName->Length)
        {
            break;
        }
        if (pCreateInfo->CompleteName->Buffer[0] != L'\\')
        {
            /*���·��*/
            break;
        }
        /*����·��*/
        bAbsolute = TRUE;
    } while (FALSE);
    return bAbsolute;
}

LARGE_INTEGER g_Cookie = {0};

NTSTATUS
RegistryCallback(
    __in PVOID CallbackContext,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2)
{
    switch ((REG_NOTIFY_CLASS)Argument1)
    {
    case RegNtPreCreateKey:
    {
        PUCHAR pProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
        PREG_PRE_CREATE_KEY_INFORMATION pCreateInfo = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
        DbgPrint("RegFilter ProcessName = %s, CreateKey: %wZ\n", pProcessName, pCreateInfo->CompleteName);
        break;
    }

    case RegNtPreCreateKeyEx:
    {
        PUCHAR pProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
        PREG_CREATE_KEY_INFORMATION pCreateInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
        /*�ж��Ƿ����·��*/
        if (IsAbsolute(pCreateInfo))
        {
            /*����·��*/
            DbgPrint("RegFilter ProcessName = %s,CreateKeyEx:%wZ\n", pProcessName, pCreateInfo->CompleteName);
        }
        else
        {
            CHAR strrRootPath[260] = {0};
            ULONG uReturnLen = 0;
            POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)strrRootPath;
            if (pCreateInfo->RootObject != NULL)
            {
                ObQueryNameString(pCreateInfo->RootObject, pNameInfo, sizeof(strrRootPath), &uReturnLen);
            }
            DbgPrint("RegFilter ProcessName = %s,CreateKeyEx:%wZ\\%wZ\n", pProcessName, &(pNameInfo->Name), pCreateInfo->CompleteName);
        }
        break;
    }

    case RegNtPreSetValueKey:
    {
        PUCHAR pProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
        PREG_SET_VALUE_KEY_INFORMATION setKey = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

        DbgPrint("RegNtSetValueKey process name %s key value %wZ\n", pProcessName, setKey->ValueName);

        BOOLEAN registryEventIsValid;
        UNICODE_STRING registryPath;

        registryPath.Length = 0;
        registryPath.MaximumLength = 512 * sizeof(WCHAR);
        registryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, registryPath.MaximumLength, 'yekS');

        if (registryPath.Buffer == NULL)
        {
            break;
        }

        RtlZeroMemory(registryPath.Buffer, registryPath.MaximumLength);

        registryEventIsValid = GetRegistryObjectCompleteName(&registryPath, NULL, setKey->Object);

        DbgPrint("process name : %s registryPath : %wZ\n", pProcessName, registryPath);

        ExFreePoolWithTag(registryPath.Buffer, 'yekS');
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}

VOID MyCreateProcessNotify(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    // DbgBreakPoint();
    // ���ٴ������̵���Ϊ
    if (Create)
    {
        PEPROCESS pProcess = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        status = PsLookupProcessByProcessId(ProcessId, &pProcess);
        if (NT_SUCCESS(status))
        {
            ObDereferenceObject(pProcess);
            PCHAR pFileName = PsGetProcessImageFileName(pProcess);
            DbgPrint("<PID: > %d----------<ProcessName: >%s\n", ProcessId, pFileName);
        }
    }
    if (!Create)
    {
        // �رս���
        PEPROCESS pProcess = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        status = PsLookupProcessByProcessId(ProcessId, &pProcess);
        if (NT_SUCCESS(status))
        {
            ObDereferenceObject(pProcess);
            PCHAR pFileName = PsGetProcessImageFileName(pProcess);
            DbgPrint("-----------------------------------------------------------------\n");

            DbgPrint("<PID: > %d----------<ProcessName: >%s  �رս���\n", ProcessId, pFileName);
        }
    }
}

void MyloadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    PEPROCESS pProcess = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (NT_SUCCESS(status))
    {
        PUCHAR pProcessName = PsGetProcessImageFileName(pProcess);

        DbgPrint("<PID : > %d  <PROCESS NAME : > %s load image name : %wZ  base address: %p ----- end address: %p \n",
                 ProcessId, pProcessName,
                 FullImageName,
                 ImageInfo->ImageBase,
                 (PVOID)((PUCHAR)(ImageInfo->ImageBase) + ImageInfo->ImageSize));
    }
}

/// ��λ�����ķ�ʽ  ����ʹ�ô�ͳ�ĺ���������������
/*
	����ֻ��Windows 7 sp1�汾�²���
	1��ʹ��PsSetCreateProcessNotifyRoutine��λ����PspSetCreateProcessNotifyRoutine
	2��ʹ��PspSetCreateProcessNotifyRoutine��λ���յ�Ŀ�꺯��PspCreateProcessNotifyRoutine�ĵ�ַ

*/

PVOID
FindPspCreateProcessNotifyRoutine()
{
    UNICODE_STRING ustrApiName = {0};
    PUCHAR pApiAddress = NULL;
    //NTSTATUS status = STATUS_SUCCESS;
    PVOID pReturnAddress = NULL;
    RtlInitUnicodeString(&ustrApiName, L"PsSetCreateProcessNotifyRoutine");
    //DbgBreakPoint();
    pApiAddress = MmGetSystemRoutineAddress(&ustrApiName);
    DbgPrint("PsSetCreateProcessNotifyRoutine address : %llx\n", pApiAddress);

    if (!pApiAddress)
    {
        DbgPrint("[Warning!!!] MmGetSystemRoutineAddress not found PsSetCreateProcessNotifyRoutine\n");
        //status = STATUS_UNSUCCESSFUL;
        return pReturnAddress;
    }
    /*

45 33 C0                                            xor     r8d, r8d
E9 E8 FD FF FF                                      jmp     PspSetCreateProcessNotifyRoutine ; ����ִ�д������̼�ص�
	*/
    //DbgBreakPoint();
    PUCHAR pPspSetCreateProcessNotifyRoutine = NULL;
    if (*(pApiAddress + 3) == 0xE9)
    {
        pPspSetCreateProcessNotifyRoutine = *(PLONG)(pApiAddress + 4) + pApiAddress + 3 + 5;
        DbgPrint("pPspSetCreateProcessNotifyRoutine address �� %llx\n", pPspSetCreateProcessNotifyRoutine);
    }

    /* PspSetCreateProcessNotifyRoutine

PAGE:00000001404BE1B0 48 89 5C 24 08                       mov     [rsp+8], rbx
PAGE:00000001404BE1B5 48 89 6C 24 10                       mov     [rsp+10h], rbp
PAGE:00000001404BE1BA 48 89 74 24 18                       mov     [rsp+18h], rsi
PAGE:00000001404BE1BF 57                                   push    rdi
PAGE:00000001404BE1C0 41 54                                push    r12
PAGE:00000001404BE1C2 41 55                                push    r13
PAGE:00000001404BE1C4 41 56                                push    r14
PAGE:00000001404BE1C6 41 57                                push    r15
PAGE:00000001404BE1C8 48 83 EC 20                          sub     rsp, 20h
PAGE:00000001404BE1CC 45 33 E4                             xor     r12d, r12d
PAGE:00000001404BE1CF 41 8A E8                             mov     bpl, r8b
PAGE:00000001404BE1D2 4C 8B E9                             mov     r13, rcx
PAGE:00000001404BE1D5 41 8D 5C 24 01                       lea     ebx, [r12+1]
PAGE:00000001404BE1DA 41 3A D4                             cmp     dl, r12b
PAGE:00000001404BE1DD 0F 84 0E 01 00 00                    jz      loc_1404BE2F1
PAGE:00000001404BE1E3 65 48 8B 3C 25 88 01+                mov     rdi, gs:188h
PAGE:00000001404BE1EC 83 C8 FF                             or      eax, 0FFFFFFFFh
PAGE:00000001404BE1EF 66 01 87 C4 01 00 00                 add     [rdi+1C4h], ax
PAGE:00000001404BE1F6 4C 8D 35 83 95 D6 FF                 lea     r14, unk_140227780

PAGE:00000001404B94AF 66 01 87 C4 01 00 00     add     [rdi+1C4h], ax
PAGE:00000001404B94B6 4C 8D 35 23 AB D6 FF     lea     r14, PspCreateProcessNotifyRoutine ; PspCreateProcessNotifyRoutine base address
	*/

    __try
    {
        for (PUCHAR pIndex = pPspSetCreateProcessNotifyRoutine;
             pIndex < 0xff + pPspSetCreateProcessNotifyRoutine;
             pIndex++)
        {

            if (*(pIndex) == 0x4C &&
                *(pIndex + 1) == 0x8D)
            {
                //DbgBreakPoint();
                pReturnAddress = (PVOID)((ULONG64)(pIndex) + *(PLONG)(pIndex + 3) + 7);
                DbgPrint("PspCreateProcessNotifyRoutine address : %llx\n", pReturnAddress);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("PspCreateProcessNotifyRoutine address EXCEPTION_EXECUTE_HANDLER\n");
    }

    return pReturnAddress;
}
//
///// ö�ٽ��̴����ص�����
VOID EnumProcessNotifyRoutine()
{
    //DbgBreakPoint();
    PVOID pArray = FindPspCreateProcessNotifyRoutine();
    if (!pArray)
    {
        DbgPrint("[MSCC] not found PspCreateProcessNotifyRoutine address %llx %s line %d; \n", pArray, __FUNCTION__, __LINE__);
        return;
    }

    for (size_t i = 0; i < 64; i++)
    {
        //DbgBreakPoint();
        ULONG64 ulNotifyAddr = 0;
        ULONG64 ulMagic = 0;
        ulMagic = (ULONG64)pArray + i * 8;
        ulNotifyAddr = *(PULONG64)(ulMagic);

        if (MmIsAddressValid((PVOID)ulNotifyAddr) && (ulNotifyAddr != 0))
        {
            ulNotifyAddr = *(PULONG64)(ulNotifyAddr & 0xfffffffffffffff8);
            DbgPrint("CreateProcess notify address : %llx\n", ulNotifyAddr);
        }
    }
}

// ע���ص�����

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{

    PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify, TRUE);
    // ж��
    PsRemoveLoadImageNotifyRoutine(MyloadImageNotifyRoutine);

    CmUnRegisterCallback(g_Cookie);

    DbgPrint("[ProcessMoniter] Driver Unload\n");
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("onload\n");
    // ���ý�����Ϣ�ص�
    //status = PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify, FALSE);

    // ����ģ��Ļص�
    //status = PsSetLoadImageNotifyRoutine(MyloadImageNotifyRoutine);

    // ö��
    //EnumProcessNotifyRoutine();
    /*PVOID pAddress = FindPspCreateProcessNotifyRoutine();
	if (pAddress == NULL)
	{
		DbgPrint("not found\n");
	}*/

    //EnumCreateProcessNotify();

    //FindPspCreateProcessNotifyRoutine();
    //EnumProcessNotifyRoutine();

    // ע���ص�
    status = CmRegisterCallback(RegistryCallback, NULL, &g_Cookie);

    pDriverObject->DriverUnload = DriverUnload;

    return status;
}
