#include <stdio.h>
#include <time.h>
#include "winsock2.h"
#include <windows.h>
#include <conio.h>
#include <tchar.h>
#include <winioctl.h>
#include <winternl.h>
#include <ImageHlp.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) 
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#pragma warning(disable:4996)
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "ImageHlp.lib")

PVOID GetLibraryProcAddress(PSTR, PSTR);
BOOL SetPrivilege(HANDLE, LPCTSTR, BOOL);
VOID WINAPI SetConsoleColors(WORD);
DWORD WINAPI Processing_Thread();
int ScanMemory_DisplayMemory(char, unsigned int, UNICODE_STRING);
void ScanPhysicalDisk_DisplayDisk(HANDLE, UNICODE_STRING);
void ScanLogicalDisk_DisplayDisk(TCHAR[]);
void ScanLogicalDisk_DeleteDisk(TCHAR[]);
void ScanPhysicalDisk_DeleteDisk(TCHAR[]);
void ScanFile_DisplayAnalysis(char[]);
int Disable_DEP_ASLR(char[], int, int);
void Display_Graphics(int);
int getInt();
unsigned long long int getUSLLInt();
void PrintData(char*, int);
void PrintIpHeader(char*);
void PrintIcmpPacket(char*, int);
void PrintUdpPacket(char*, int);
void PrintTcpPacket(char*, int);
void ProcessPacket(char*, int);
void StartSniffing(SOCKET, long long int);
void HexDump(char *, int, int);
int InitializeSniffer(long long int);

HANDLE eventHnd;
int stopRequested = 0;
FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _EVENTLOGHEADER {
	
	ULONG HeaderSize;
	ULONG Signature;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG StartOffset;
	ULONG EndOffset;
	ULONG CurrentRecordNumber;
	ULONG OldestRecordNumber;
	ULONG MaxSize;
	ULONG Flags;
	ULONG Retention;
	ULONG EndHeaderSize;

} EVENTLOGHEADER, *PEVENTLOGHEADER;

typedef struct ipv4_hdr
{
	unsigned char ip_header_len : 4; 
	unsigned char ip_version : 4; 
	unsigned char ip_tos; 
	unsigned short ip_total_length; 
	unsigned short ip_id; 

	unsigned char ip_frag_offset : 5; 

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;

	unsigned char ip_ttl; 
	unsigned char ip_protocol; 
	unsigned short ip_checksum; 
	unsigned int ip_srcaddr; 
	unsigned int ip_destaddr; 

} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; 
	unsigned short dest_port; 
	unsigned short udp_length; 
	unsigned short udp_checksum; 

} UDP_HDR;

typedef struct tcp_header
{
	unsigned short source_port; 
	unsigned short dest_port;
	unsigned int sequence; 
	unsigned int acknowledge; 

	unsigned char ns : 1; 
	unsigned char reserved_part1 : 3; 
	unsigned char data_offset : 4; 

	unsigned char fin : 1;
	unsigned char syn : 1; 
	unsigned char rst : 1; 
	unsigned char psh : 1; 
	unsigned char ack : 1; 
	unsigned char urg : 1; 

	unsigned char ecn : 1; 
	unsigned char cwr : 1; 

	unsigned short window; 
	unsigned short checksum; 
	unsigned short urgent_pointer; 

} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; 
	BYTE code; 
	USHORT checksum;
	USHORT id;
	USHORT seq;

} ICMP_HDR;

/**typedef struct ipv6_header
{

unsigned int
version : 4,
traffic_class : 8,
flow_label : 20;
unsigned short int length;
unsigned char  next_header;
unsigned char  hop_limit;
struct in6_addr src;
struct in6_addr dst;

} IPV6_HDR;**/

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;

}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		//printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		//printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The process does not have the required privilege. \n");
		return FALSE;
	}

	return TRUE;
}

VOID WINAPI SetConsoleColors(WORD attribs) {

	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	CONSOLE_SCREEN_BUFFER_INFOEX cbi;
	cbi.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);
	GetConsoleScreenBufferInfoEx(hOutput, &cbi);
	cbi.wAttributes = attribs;
	SetConsoleScreenBufferInfoEx(hOutput, &cbi);

}

DWORD WINAPI Processing_Thread() {

	printf("\n\nOperation is being performed. Please wait.....................");

	do {

		// WaitForSingleObject(eventHnd, INFINITE);

		if (stopRequested)
			return;

		printf("|");
		printf("\b");
		Sleep(100);
		fflush(stdout);
		printf("/");
		printf("\b");
		Sleep(100);
		fflush(stdout);
		printf("-");
		printf("\b");
		Sleep(100);
		fflush(stdout);
		printf("\\");
		printf("\b");
		Sleep(100);
		fflush(stdout);

	} while (1);

}

int ScanMemory_DisplayMemory(char option, unsigned int pid, UNICODE_STRING pName)
{

	MEMORY_BASIC_INFORMATION meminfo;
	unsigned char  *addr = 0, *addr1 = 0;


	FILE *f;

	if (option == '0') {
		f = fopen("ProcDump.txt", "a");
	}
	else if(option == '1') {
		f = fopen("MemDump.txt", "a");
	}
	else {
		f = fopen("ErrDump.txt", "a");
	}


	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	HANDLE lProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	eventHnd = CreateEvent(NULL, 0, 0, NULL);
	stopRequested = 0;
	HANDLE thread = CreateThread(NULL, 0, Processing_Thread, NULL, 0, NULL);
	DWORD error = GetLastError();

	HANDLE fProc;

	int t_run = -1;

	if (SetEvent(eventHnd)) {

		t_run = 1;

	}


	if (hProc || lProc)
	{


		//(!hProc && lProc) ? printf("lproc") : printf("hProc"); //Testing Condition
		fProc = (!hProc && lProc) ? lProc : hProc;

		//printf("Process Name : %ws\r\n", pName.Buffer);
		fprintf(f, "Process Name : %ws\n\n\n", pName.Buffer);

		while (1) {
			if ((VirtualQueryEx(fProc, addr1, &meminfo, sizeof(meminfo))) == 0)
			{
				break;
			}


			if (meminfo.State == MEM_COMMIT)
			{
				static unsigned char display_buffer[1024 * 128];
				SIZE_T bytes_left;
				SIZE_T total_read;
				SIZE_T bytes_to_read;
				SIZE_T bytes_read;

					addr = (unsigned char*)meminfo.BaseAddress;

					//printf("Base Address : 0x%08x\r\n", addr);
					fprintf(f, "Base Address : %X\n", addr);

					bytes_left = meminfo.RegionSize;

					//printf("Region Size : %d\r\n", bytes_left);
					fprintf(f, "Region Size : %d\r\n", bytes_left);

					total_read = 0;

					while (bytes_left)
					{
						bytes_to_read = (bytes_left > sizeof(display_buffer)) ? sizeof(display_buffer) : bytes_left;
						ReadProcessMemory(hProc, addr + total_read, display_buffer, bytes_to_read, &bytes_read);
						if (bytes_read != bytes_to_read) break;

						char a, line[17], c;
						int bsize = 0;
						int j;
						long long int memaddr = 0;

						for (bsize = 0; bsize < bytes_to_read; bsize++, memaddr++)
						{

							if (bsize % 16 == 0)fprintf(f, "%X:", (addr+memaddr));
							if (bsize % 4 == 0)fprintf(f, " |");

							c = display_buffer[bsize];

							fprintf(f, " %.2X", (unsigned char)c);

							a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

							line[bsize % 16] = a;

							if ((bsize != 0 && (bsize + 1) % 16 == 0) || bsize == bytes_to_read - 1)
							{
								line[bsize % 16 + 1] = '\0';

								fprintf(f, "          ");

								for (j = strlen(line); j < 16; j++)
								{
									fprintf(f, "   ");
								}

								fprintf(f, "%s \n", line);
							}

						}

						fprintf(f, "\r\n\n");

						bytes_left -= bytes_read;
						total_read += bytes_read;
					}
				}
			addr1 = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
		}

		CloseHandle(fProc);

	}

	else {

		printf("\nFailed to open process - error - %d\r\n", error);

	}

	if (t_run == 1) {

		stopRequested = 1;
		SetEvent(eventHnd);
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		CloseHandle(eventHnd);
		printf(" \b\b  ");
		fflush(stdout);
		printf("\n");
		t_run = -1;
	}

	fclose(f);
	return 0;
}

void ScanPhysicalDisk_DisplayDisk(HANDLE disk, UNICODE_STRING diskx) {

	eventHnd = CreateEvent(NULL, 0, 0, NULL);
	stopRequested = 0;
	HANDLE thread = CreateThread(NULL, 0, Processing_Thread, NULL, 0, NULL);

	int t_run = -1;

	if (SetEvent(eventHnd)) {

		t_run = 1;

	}

	FILE *f;

	f = fopen("DiskDump.txt", "a");

	DWORD br = 0;
	DISK_GEOMETRY dg;

	DeviceIoControl(disk, IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0, &dg, sizeof(dg), &br, 0);

	int bufsize = dg.BytesPerSector;
	unsigned char *buf = malloc(bufsize);

	fprintf(f, "Disk Name : %ws\r\n", diskx.Buffer);

	long long int sectorVolume = 1;

	fprintf(f, "\n\n");


	while (ReadFile(disk, buf, bufsize, &br, NULL))
	{

		if (br == 0)
			break;

		char a, line[17], c;
		int j;


		for (int bsize = 0; bsize < bufsize; bsize++) {

			if (bsize % 16 == 0)fprintf(f, "Sector %ld:", sectorVolume);
			if (bsize % 4 == 0)fprintf(f, " |");

			c = buf[bsize];

			fprintf(f, " %.2X", (unsigned char)c);

			a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

			line[bsize % 16] = a;

			if ((bsize != 0 && (bsize + 1) % 16 == 0) || bsize == bufsize - 1)
			{
				line[bsize % 16 + 1] = '\0';

				fprintf(f, "          ");

				for (j = strlen(line); j < 16; j++)
				{
					fprintf(f, "   ");
				}

				fprintf(f, "%s \n", line);
			}

		}

		sectorVolume++;
		fprintf(f, "\n");

	}

	fprintf(f, "\n\n\r");

	fclose(f);
	printf("\n");

	if (t_run == 1) {

		stopRequested = 1;
		SetEvent(eventHnd);
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		CloseHandle(eventHnd);
		printf(" \b\b  ");
		fflush(stdout);
		printf("\n");
		t_run = -1;
	}

}

void ScanLogicalDisk_DisplayDisk(TCHAR driveString[]) {

	eventHnd = CreateEvent(NULL, 0, 0, NULL);
	stopRequested = 0;
	HANDLE thread = CreateThread(NULL, 0, Processing_Thread, NULL, 0, NULL);

	int t_run = -1;

	if (SetEvent(eventHnd)) {

		t_run = 1;

	}

	FILE *f;

	f = fopen("DriveDump.txt", "a");
	//printf("%ws", driveString);

	HANDLE handle = CreateFile(driveString, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

	DWORD br = 0;
	DISK_GEOMETRY dg;

	DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0, &dg, sizeof(dg), &br, 0);

	int bufsize = dg.BytesPerSector;
	unsigned char *buf = malloc(bufsize);

	fprintf(f, "Drive Name : %ws\r\n", driveString);

	long long int sectorVolume = 1;

	fprintf(f, "\n\n");

	while (ReadFile(handle, buf, bufsize, &br, NULL))
	{
		if (br == 0)
			break;

		char a, line[17], c;
		int j;
		

		for (int bsize = 0; bsize < bufsize; bsize++) {

			if (bsize % 16 == 0)fprintf(f, "Sector %ld:", sectorVolume);
			if (bsize % 4 == 0)fprintf(f," |");			

			c = buf[bsize];

			fprintf(f, " %.2X", (unsigned char)c);
			
			a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

			line[bsize % 16] = a;
			
			if ((bsize != 0 && (bsize + 1) % 16 == 0) || bsize == bufsize - 1)
			{
				line[bsize % 16 + 1] = '\0';

				fprintf(f, "          ");

				for (j = strlen(line); j < 16; j++)
				{
					fprintf(f, "   ");
				}

				fprintf(f, "%s \n", line);
			}

		}

		sectorVolume++;
		fprintf(f, "\n");

	}

	fprintf(f, "\n\n\r");

	printf("\n");
	fclose(f);
	CloseHandle(handle);

	if (t_run == 1) {

		stopRequested = 1;
		SetEvent(eventHnd);
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		CloseHandle(eventHnd);
		printf(" \b\b  ");
		fflush(stdout);
		printf("\n");

	}
}

void ScanLogicalDisk_DeleteDisk(TCHAR driveString[]) {


	eventHnd = CreateEvent(NULL, 0, 0, NULL);
	stopRequested = 0;
	HANDLE thread = CreateThread(NULL, 0, Processing_Thread, NULL, 0, NULL);

	char zeroByte[512];
	
	int t_run = -1;

	if (SetEvent(eventHnd)) {

		t_run = 1;

	}
	
	for (int j = 0; j < 32; j++) {

		HANDLE handle = CreateFile(driveString, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

		DWORD br = 0;

		DeviceIoControl(handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &br, NULL);
		DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &br, NULL);

		for (int i = 0; i < 512; i++) {
			zeroByte[i] = j;
		}

		while (WriteFile(handle, zeroByte, 512, &br, NULL)) {
			//CHECK LAST WRITE FILE CONDITION
		}

		CloseHandle(handle);

	}	

	printf("\n");

	if (t_run == 1) {

		stopRequested = 1;
		SetEvent(eventHnd);
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		CloseHandle(eventHnd);
		printf(" \b\b  ");
		fflush(stdout);
		printf("\n");

	}

}

void ScanPhysicalDisk_DeleteDisk(TCHAR disk[]) {

	/** UNMOUNT VOLUMES CONNECTED TO DISK. GET THEM IN AN ARRAY LINKING THEM TO DISK AND THEN UNMOUNT LOCK AND THEN WRITE TO FILE***/

	eventHnd = CreateEvent(NULL, 0, 0, NULL);
	stopRequested = 0;
	HANDLE thread = CreateThread(NULL, 0, Processing_Thread, NULL, 0, NULL);

	char zeroByte[512];

	int t_run = -1;

	if (SetEvent(eventHnd)) {

		t_run = 1;

	}


	for (int j = 0; j < 32; j++) {

		HANDLE handle = CreateFile(disk, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

		DWORD br = 0;

		PARTITION_INFORMATION_EX part;

		DeviceIoControl(handle, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, NULL, 0, &br, NULL);
		DeviceIoControl(handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &br, NULL);
		DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &br, NULL);

		for (int i = 0; i < 512; i++) {
			zeroByte[i] = j;
		}

		while (WriteFile(handle, zeroByte, 512, &br, NULL)) {
			//CHECK LAST WRITE FILE CONDITION
		}

		CloseHandle(handle);

	}

	printf("\n");

	if (t_run == 1) {

		stopRequested = 1;
		SetEvent(eventHnd);
		WaitForSingleObject(thread, 5000);
		CloseHandle(thread);
		CloseHandle(eventHnd);
		printf(" \b\b  ");
		fflush(stdout);
		printf("\n");

	}

}

void ScanFile_DisplayAnalysis(char filename[]) {
	FILE *fp1, *f, *fp2, *fp3;
	int i, j = 0;

	f = fopen("FileDump.txt", "a");
	fp1 = fopen(filename, "rb");
	fp2 = fopen(filename, "rb");
	fp3 = fopen(filename, "rb");


	if (fp1 == NULL) {
		fprintf(f, "Cannot open Input File\n");
		return;
	}

	unsigned char c[16];
	int ch[16];
	
	while(j!=1){

		for (i = 0; i<16 && ((c[i] = getc(fp1)) != EOF); i++) {
			fprintf(f, "%02X ", c[i]);
			if (i % 4 == 3)
				fprintf(f, " |");
		}

		fprintf(f, "\t\t");

		for (i = 0; i<16 && ((c[i] = getc(fp2)) != EOF); i++) {
			unsigned char a = (c[i] >= 32 && c[i] <= 128) ? c[i] : '.';
			fprintf(f, "%c", a);
		}

		fprintf(f, "\n");

		for (i = 0; i < 16; i++) {

			ch[i] = getc(fp3);

			if (ch[i] == EOF) {
				j = 1;
			}
			
		}

	}


	fclose(fp2);
	fclose(fp1);
	fclose(fp3);
	fclose(f);

}

int Disable_DEP_ASLR(char filename[], int ASLR, int DEP) {

	LOADED_IMAGE PE;
	if (MapAndLoad(filename, 0, &PE, 0, 0))
	{
		if (ASLR) {
			PE.FileHeader->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}
		else {
			PE.FileHeader->OptionalHeader.DllCharacteristics = NULL;
		}

		if (DEP) {
			PE.FileHeader->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}
		else {
			PE.FileHeader->OptionalHeader.DllCharacteristics = NULL;
		}

		UnMapAndLoad(&PE);
		return 1;
	}
	return 0;

}

void Display_Graphics(int priv) {

	system("cls");

	printf("                  ___________            _____ _____   _____           _ _    _ _\n");
	printf("                 |_   _| ___ \\   ___    |  ___/  __ \\ |_   _|         | | |  (_) |\n");
	printf("                   | | | |_/ /  ( _ )   | |__ | /  \\/   | | ___   ___ | | | ___| |_\n");
	printf("                   | | |    /   / _ \\/\\ |  __|| |       | |/ _ \\ / _ \\| | |/ / | __|\n");
	printf("                  _| |_| |\\ \\  | (_>  < | |___| \\__/\\   | | (_) | (_) | |   <| | |_\n");
	printf("                  \\___/\\_| \\_|  \\___/\\/ \\____/ \\____/   \\_/\\___/ \\___/|_|_|\\_\\_|\\__|\n");
	printf("\n");
	printf("                                 DEVELOPED BY : SAPTARSHI LAHA (RIK)\n");
	if (priv == 1) {
		printf("                                  DEBUG PRIVILEGE STATUS : GRANTED\n");
	}
	else if (priv == -1) {
		printf("                                  DEBUG PRIVILEGE STATUS : DENIED\n");
	}
	printf("\n\n");
	printf("0. Single Process Memory Dump\n");
	printf("1. Full System Memory Dump (Consumes a LOT of Space!)\n");
	printf("2. Logical Drive Analysis (Consumes a LOT of Space!)\n");
	printf("3. Physical Drive Analysis (Consumes a LOT of Space!)\n");
	printf("4. Application Port Scanning\n");
	printf("5. Network Analysis (Packet Sniffing)\n");
	printf("6. PE File Analysis\n");
	printf("7. Handle Analysis - Process\n");
	printf("8. Binary Analysis of File\n");
	printf("9. File Encryption/Decryption\n");
	printf("A. Forensic Wipe - Logical Drive (Launch From Another Logical Drive)\n");
	printf("B. Forensic Wipe - Physical Drive (Launch From Another Physical Drive) Currently Not Functional & Can Cause Errors\n"); // TO BE FIXED
	printf("C. Disable Data Execution Prevention & Address Space Layout Randomization For External Application\n");
	printf("Q. Exit\n\n");
}

int getInt()
{
	int n = 0;
	char buffer[128];
	fgets(buffer, sizeof(buffer), stdin);
	n = atoi(buffer);
	return (n > 0) ? n : -1;
}

unsigned long long int getUSLLInt()
{
	unsigned long long int n = 0;
	char buffer[128];
	fgets(buffer, sizeof(buffer), stdin);
	n = atoi(buffer);
	return (n > 0) ? n : -1;
}

void PrintData(char* data, int Size)
{
	char a, line[17], c;
	int j;

	for (i = 0; i < Size; i++)
	{
		if (i % 4 == 0)fprintf(logfile, " |");
		c = data[i];

		fprintf(logfile, " %.2X", (unsigned char)c);

		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';

		line[i % 16] = a;

		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';

			fprintf(logfile, "          ");

			for (j = strlen(line); j < 16; j++)
			{
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "%s \n", line);
		}
	}

	fprintf(logfile, "\n");
}

void PrintIpHeader(char* Buffer)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	fprintf(logfile, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdr->ip_header_len)) * 4);
	fprintf(logfile, " |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	fprintf(logfile, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	fprintf(logfile, " |-Identification : %d\n", ntohs(iphdr->ip_id));
	fprintf(logfile, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	fprintf(logfile, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	fprintf(logfile, " |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile, " |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	fprintf(logfile, " |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	fprintf(logfile, " |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	fprintf(logfile, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintIcmpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer);

	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, " |-Type : %d", (unsigned int)(icmpheader->type));

	if ((unsigned int)(icmpheader->type) == 11)
	{
		fprintf(logfile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->type) == 0)
	{
		fprintf(logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(logfile, " |-Code : %d\n", (unsigned int)(icmpheader->code));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(icmpheader->checksum));
	fprintf(logfile, " |-ID : %d\n", ntohs(icmpheader->id));
	fprintf(logfile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(ICMP_HDR));

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len * 4));

	fprintf(logfile, "\n***********************End Of Packet*************************");
	fprintf(logfile, "\n\n");
}

void PrintUdpPacket(char *Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR *)(Buffer + iphdrlen);

	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, " |-Source Port : %d\n", ntohs(udpheader->source_port));
	fprintf(logfile, " |-Destination Port : %d\n", ntohs(udpheader->dest_port));
	fprintf(logfile, " |-UDP Length : %d\n", ntohs(udpheader->udp_length));
	fprintf(logfile, " |-UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");

	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");

	PrintData(Buffer + iphdrlen, sizeof(UDP_HDR));

	fprintf(logfile, "Data Payload\n");

	PrintData(Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));

	fprintf(logfile, "\n***********************End Of Packet*************************");
	fprintf(logfile, "\n\n");
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, " |-Source Port : %u\n", ntohs(tcpheader->source_port));
	fprintf(logfile, " |-Destination Port : %u\n", ntohs(tcpheader->dest_port));
	fprintf(logfile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequence));
	fprintf(logfile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledge));
	fprintf(logfile, " |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcpheader->data_offset, (unsigned int)tcpheader->data_offset * 4);
	fprintf(logfile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->cwr);
	fprintf(logfile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ecn);
	fprintf(logfile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urg);
	fprintf(logfile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->ack);
	fprintf(logfile, " |-Push Flag : %d\n", (unsigned int)tcpheader->psh);
	fprintf(logfile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->rst);
	fprintf(logfile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->syn);
	fprintf(logfile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->fin);
	fprintf(logfile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(logfile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(logfile, "\n");
	fprintf(logfile, "DATA Dump ");
	fprintf(logfile, "\n^^^^^^^^^\n\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcpheader->data_offset * 4);

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));

	fprintf(logfile, "\n***********************End Of Packet*************************");
	fprintf(logfile, "\n\n");
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;
	++total;

	switch (iphdr->ip_protocol) 
	{
	case 1: 
		++icmp;
		PrintIcmpPacket(Buffer, Size);
		break;

	case 2: 
		++igmp;
		break;

	case 6: 
		++tcp;
		PrintTcpPacket(Buffer, Size);
		break;

	case 17: 
		++udp;
		PrintUdpPacket(Buffer, Size);
		break;

	default: 
		++others;
		break;
	}
	printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

void StartSniffing(SOCKET sniffer, long long int number)
{
	int psniff = 0;
	char *Buffer = (char *)malloc(65536); 
	int mangobyte;

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0); 

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
			psniff++;
		}
		else
		{
			printf("Receiving failed.\n");
		}

		if (psniff >= number)
			break;

	} while (mangobyte > 0);

	free(Buffer);
}

void HexDump(char *p, int size, int secAddress)
{

	FILE *f;
	f = fopen("PEDump.txt", "a");

	int i = 1, temp = 0;
	wchar_t buf[18];     
	fprintf(f, "\n\n%X: |", secAddress);

	buf[temp] = ' '; 
	buf[temp + 16] = ' ';  
	buf[temp + 17] = 0;  
	temp++;              
	for (; i <= size; i++, p++, temp++)
	{
		buf[temp] = !iswcntrl((*p) & 0xff) ? (*p) & 0xff : '.';
		fprintf(f, "%-3.2X", (*p) & 0xff);

		if (i % 16 == 0) {      
			fputws(buf, f);
			if (i + 1 <= size)fprintf(f,"\n%X: ", secAddress += 16);
			temp = 0;
		}
		if (i % 4 == 0)fprintf(f,"|");
	}
	if (i % 16 != 0) {
		buf[temp] = 0;
		for (; i % 16 != 0; i++)
			fprintf(f,"%-3.2c", ' ');
		fputws(buf, f);
	}

	fprintf(f, "\n===============================================================================\n");

	fclose(f);

}

int InitializeSniffer(long long int number)
{

	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	logfile = fopen("SniffDump.txt", "a");

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Winsock Startup Failed.\n");
		return 1;
	}

	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to Create Raw Socket.\n");
		return 1;
	}

	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	printf("Host name : %s \n", hostname);

	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n", (i + 1), inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");

	in = getInt();
	in--;

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		printf("Binding (%s) failed.\n", inet_ntoa(addr));
		return 1;
	}

	j = 1;

	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		printf("IOCTL Windows Sniffing failed.\n");
		return 1;
	}

	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer, number);
	closesocket(sniffer);
	WSACleanup();

	return 0;

}

int main() {

	int privilege = 1;

	SetConsoleColors(BACKGROUND_GREEN | BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	SetConsoleTitle(_T("Incident Response & Evidence Collection Toolkit"));

	HANDLE hProc = GetCurrentProcess();

	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		privilege = -1;
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
		privilege = -1;
	}

	NTSTATUS status;
	PVOID buffer;
	PSYSTEM_PROCESS_INFO spi;


	buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		return -1;
	}

	char option = -1;
	int pid = -1, i, x;
	int con = -1;
	uintptr_t h[1024 * 30];
	UNICODE_STRING pName[1024 * 30];

	Display_Graphics(privilege);



	while (1) {

		option = -1;
		spi = (PSYSTEM_PROCESS_INFO)buffer;

		if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL)))
		{

			VirtualFree(buffer, 0, MEM_RELEASE);
			return -1;
		}

		if (con != 1) { printf("IR&ECToolkit@Root>"); }

		con = -1;
		option = getch();

		i = 0;

		if (option == 13) {
			printf("\nIR&ECToolkit@Root>");
			con = 1;
		}
		else if (option == 0) {
			con = 1;
			//NULL TERMINATING STRING
		}
		else if (option == '0') {
			printf("\n");
			while (spi->NextEntryOffset)
			{
				h[i] = spi->ProcessId;
				pName[i].Buffer = spi->ImageName.Buffer;
				printf("Process name: %ws | Process ID: %d\n", spi->ImageName.Buffer, spi->ProcessId);
				spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
				i++;
			}

			x = i;

			printf("\nEnter Process ID :");


			pid = getInt();

			printf("\n");

			UNICODE_STRING pNameToBePassed;
			pNameToBePassed.Buffer = NULL;

			for (i = 0; i < x; i++) {
				if (h[i] == pid) {
					pNameToBePassed.Buffer = pName[i].Buffer;
				}
			}

			if (pNameToBePassed.Buffer != NULL) {
				printf("%ws\n", pNameToBePassed.Buffer);
				ScanMemory_DisplayMemory(option, pid, pNameToBePassed);
				printf("\n\nOperation Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}
			else {
				printf("\nInvalid PID. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);
			}

		}

		else if (option == '1') {

			i = 0;
			printf("\n");

			while (spi->NextEntryOffset)
			{
				h[i] = spi->ProcessId;
				pName[i].Buffer = spi->ImageName.Buffer;
				printf("Process name: %ws | Process ID: %d\n", spi->ImageName.Buffer, spi->ProcessId);
				spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
				i++;
			}

			x = i;

			UNICODE_STRING pNameToBePassed;
			pNameToBePassed.Buffer = NULL;

			for (i = 0; i < x; i++) {

				pNameToBePassed.Buffer = pName[i].Buffer;
				printf("\n%d.Process Name : %ws\n", (i + 1), pNameToBePassed.Buffer);
				pid = h[i];
				ScanMemory_DisplayMemory(option, pid, pNameToBePassed);
				printf("Operation Completed Status :  \t %d out of %d\n\n", (i + 1), (x + 1));
			}

			printf("\n\nOperation Completed.\n");
			system("pause");
			Display_Graphics(privilege);

		}

		else if (option == '2') {

			int loopdrives;
			DWORD drives = GetLogicalDrives();
			int drivenum[26];
			int drivecount = 0;

			for (loopdrives = 0; loopdrives < 26; loopdrives++) {

				drivenum[loopdrives] = 0;

			}



			printf("\n");
			printf("Logical Volumes : \n");
			char Drive1[] = { ("A:\\") };
			TCHAR Drive2[] = L"\\\\.\\A:";

			for (loopdrives = 0; loopdrives < 26; loopdrives++)
			{
				if (drives & (1 << loopdrives))
				{
					drivecount = drivecount + 1;
					Drive1[0] = ('A') + loopdrives;
					printf("%d. %s\n", drivecount, Drive1);
					drivenum[loopdrives] = loopdrives;
				}

			}

			printf("Enter Logical Drive Number :");

			int getLogicalDriveNumber = 0;
			getLogicalDriveNumber = getInt();

			printf("\n");

			if (getLogicalDriveNumber > 0 && getLogicalDriveNumber <= drivecount) {

				int countdrive = 0;
				int driveloop;

				for (driveloop = 0; driveloop < 26; driveloop++) {

					if (drivenum[driveloop] != 0) {

						Drive2[4] = ('A') + drivenum[driveloop];
						countdrive = countdrive + 1;

						if (countdrive == getLogicalDriveNumber) {

							ScanLogicalDisk_DisplayDisk(Drive2);
							printf("\n\nOperation Completed.\n");
							system("pause");
							Display_Graphics(privilege);
							break;

						}

					}

				}

			}
			else {

				printf("\nInvalid Drive. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);

			}

		}
		else if (option == '3') {

			printf("\n");
			printf("Physical Volumes : \n");

			HANDLE device[100];
			TCHAR strPathFinal[100][20];

			for (int clear1 = 0; clear1 < 100; clear1++) {
				for (int clear2 = 0; clear2 < 20; clear2++) {
					strPathFinal[clear1][clear2] = NULL;
				}
			}

			int diskloop;
			int diskcounter = 0;

			for (diskloop = 0; diskloop < 100; diskloop++) {

				TCHAR strPath0[] = L"\\\\.\\PhysicalDrive0";
				TCHAR strPath1[] = L"\\\\.\\PhysicalDrive10";
				TCHAR strPath2[] = L"\\\\.\\PhysicalDrive20";
				TCHAR strPath3[] = L"\\\\.\\PhysicalDrive30";
				TCHAR strPath4[] = L"\\\\.\\PhysicalDrive40";
				TCHAR strPath5[] = L"\\\\.\\PhysicalDrive50";
				TCHAR strPath6[] = L"\\\\.\\PhysicalDrive60";
				TCHAR strPath7[] = L"\\\\.\\PhysicalDrive70";
				TCHAR strPath8[] = L"\\\\.\\PhysicalDrive80";
				TCHAR strPath9[] = L"\\\\.\\PhysicalDrive90";


				if (diskloop >= 0 && diskloop < 10) {
					strPath0[17] = ('0') + diskloop;
					device[diskloop] = CreateFile(strPath0, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath0);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}
				}
				else if (diskloop >= 10 && diskloop < 20) {
					strPath1[18] = ('0') + (diskloop - 10);
					device[diskloop] = CreateFile(strPath1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath1);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}
				}
				else if (diskloop >= 20 && diskloop < 30) {
					strPath2[18] = ('0') + (diskloop - 20);
					device[diskloop] = CreateFile(strPath2, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath2);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 30 && diskloop < 40) {
					strPath3[18] = ('0') + (diskloop - 30);
					device[diskloop] = CreateFile(strPath3, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath3);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 40 && diskloop < 50) {
					strPath4[18] = ('0') + (diskloop - 40);
					device[diskloop] = CreateFile(strPath4, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath4);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 50 && diskloop < 60) {
					strPath5[18] = ('0') + (diskloop - 50);
					device[diskloop] = CreateFile(strPath5, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath5);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 60 && diskloop < 70) {
					strPath6[18] = ('0') + (diskloop - 60);
					device[diskloop] = CreateFile(strPath6, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath6);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 70 && diskloop < 80) {
					strPath7[18] = ('0') + (diskloop - 70);
					device[diskloop] = CreateFile(strPath7, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath7);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 80 && diskloop < 90) {
					strPath8[18] = ('0') + (diskloop - 80);
					device[diskloop] = CreateFile(strPath8, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath8);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 90 && diskloop < 100) {
					strPath9[18] = ('0') + (diskloop - 90);
					device[diskloop] = CreateFile(strPath9, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath9);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}

			}

			printf("Enter Physical Drive : ");
			int getDisk = getInt();
			printf("\n");
			int validcounter = 0;

			if (getDisk > 0 && getDisk <= diskcounter) {

				for (diskloop = 0; diskloop < 100; diskloop++) {

					if (device[diskloop] != INVALID_HANDLE_VALUE) {

						validcounter = validcounter + 1;
						if (validcounter == getDisk) {
							UNICODE_STRING dStr;
							dStr.Buffer = strPathFinal[diskloop];
							ScanPhysicalDisk_DisplayDisk(device[diskloop], dStr);

							for (diskloop = 0; diskloop < 100; diskloop++) {

								if (device[diskloop] != INVALID_HANDLE_VALUE) {

									CloseHandle(device[diskloop]);

								}

							}

							printf("\n\nOperation Completed.\n");
							system("pause");
							Display_Graphics(privilege);
							break;
						}

					}

				}
			}
			else {

				printf("\nInvalid Drive. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);

			}

		}
		else if (option == '4') {

			FILE *f;


			system("netstat -a -b -ano >> NetworkStats.txt");
			f = fopen("NetworkStats.txt", "a");
			fprintf(f, "\n\n***********************End Of Report*************************\n\n\n");
			printf("\n\nOperation Completed.\n");
			system("pause");
			Display_Graphics(privilege);

			fclose(f);

		}
		else if (option == '5') {

		  long long int psniff = -1;

			while (1) {
				printf("\nEnter Number of Packets to Sniff (Minimum 1) : ");
				psniff = getInt();
				if (psniff >= 1)
					break;
			}

			printf("\n");
			int sniffer_result = InitializeSniffer(psniff);

			if (sniffer_result == 0) {
				printf("\n\nOperation Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}
			else {
				printf("\n\nOperation Could Not Be Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}

		}
		else if (option == '6') {
			
			int PeFile = 0;
			TCHAR PeFileName[300];
			int File_Found = -1;
			HANDLE hMapObject, hFile;           
			LPVOID lpBase;                     
			PIMAGE_DOS_HEADER dosHeader;        
			PIMAGE_NT_HEADERS ntHeader;        
			IMAGE_FILE_HEADER header;           
			IMAGE_OPTIONAL_HEADER opHeader;     
			PIMAGE_SECTION_HEADER pSecHeader;
			FILE *pefile;
			pefile = fopen("PEDump.txt", "a");
			

			do {
				printf("\nEnter PE File Name With Extension : ");
				wscanf(L"%ws", PeFileName);
				printf("\n");

				hFile = CreateFile(PeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE) { 
					printf("\nERROR : Could not open the file specified\n");  
					File_Found = -1;
				}
				else {
					File_Found = 1;

					hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
					lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

					dosHeader = (PIMAGE_DOS_HEADER)lpBase;

					if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
						fprintf(pefile, "PE File Name : %ws\n\n",PeFileName);
						fprintf(pefile,"\nValid Dos Exe File\n------------------\n");
						fprintf(pefile,"\nDumping DOS Header Info....\n---------------------------");
						fprintf(pefile,"\n%-36s%s ", "Magic number : ", dosHeader->e_magic == 0x5a4d ? "MZ(Mark Zbikowski)" : "-");
						fprintf(pefile,"\n%-36s%#x", "Bytes on last page of file :", dosHeader->e_cblp);
						fprintf(pefile,"\n%-36s%#x", "Pages in file : ", dosHeader->e_cp);
						fprintf(pefile,"\n%-36s%#x", "Relocation : ", dosHeader->e_crlc);
						fprintf(pefile,"\n%-36s%#x", "Size of header in paragraphs : ", dosHeader->e_cparhdr);
						fprintf(pefile,"\n%-36s%#x", "Minimum extra paragraphs needed : ", dosHeader->e_minalloc);
						fprintf(pefile,"\n%-36s%#x", "Maximum extra paragraphs needed : ", dosHeader->e_maxalloc);
						fprintf(pefile,"\n%-36s%#x", "Initial (relative) SS value : ", dosHeader->e_ss);
						fprintf(pefile,"\n%-36s%#x", "Initial SP value : ", dosHeader->e_sp);
						fprintf(pefile,"\n%-36s%#x", "Checksum : ", dosHeader->e_csum);
						fprintf(pefile,"\n%-36s%#x", "Initial IP value : ", dosHeader->e_ip);
						fprintf(pefile,"\n%-36s%#x", "Initial (relative) CS value : ", dosHeader->e_cs);
						fprintf(pefile,"\n%-36s%#x", "File address of relocation table : ", dosHeader->e_lfarlc);
						fprintf(pefile,"\n%-36s%#x", "Overlay number : ", dosHeader->e_ovno);
						fprintf(pefile,"\n%-36s%#x", "OEM identifier : ", dosHeader->e_oemid);
						fprintf(pefile,"\n%-36s%#x", "OEM information(e_oemid specific) :", dosHeader->e_oeminfo);
						fprintf(pefile,"\n%-36s%#x", "RVA address of PE header : ", dosHeader->e_lfanew);
						fprintf(pefile,"\n===============================================================================\n");
					}
					else {
						printf("\nGiven File is not a valid DOS file\n");
						UnmapViewOfFile(lpBase);
						CloseHandle(hMapObject);
						fclose(pefile);
					}


					ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)(dosHeader)+(dosHeader->e_lfanew));  

					if (ntHeader->Signature == IMAGE_NT_SIGNATURE) {
						fprintf(pefile,"\nValid PE file \n-------------\n");

						fprintf(pefile,"\nDumping COFF/PE Header Info....\n--------------------------------");
						fprintf(pefile,"\n%-36s%s", "Signature :", "PE");

						header = ntHeader->FileHeader;

						fprintf(pefile,"\n%-36s", "Machine Architechture :");
						switch (header.Machine) { 
						case 0x0:    fprintf(pefile,"All "); break;
						case 0x14d:  fprintf(pefile,"Intel i860"); break;
						case 0x14c:  fprintf(pefile,"Intel i386,i486,i586"); break;
						case 0x200:  fprintf(pefile,"Intel Itanium processor"); break;
						case 0x8664: fprintf(pefile,"AMD x64"); break;
						case 0x162:  fprintf(pefile,"MIPS R3000"); break;
						case 0x166:  fprintf(pefile,"MIPS R4000"); break;
						case 0x183:  fprintf(pefile,"DEC Alpha AXP"); break;
						default:     fprintf(pefile,"Not Found"); break;
						}
						
						fprintf(pefile, "\n%-36s", "Characteristics : ");
						if ((header.Characteristics & 0x0002) == 0x0002) fprintf(pefile, "Executable Image.");
						if ((header.Characteristics & 0x0020) == 0x0020) fprintf(pefile, " Application can address > 2GB.");
						if ((header.Characteristics & 0x1000) == 0x1000) fprintf(pefile, " System file (Kernel Mode Driver).");
						if ((header.Characteristics & 0x2000) == 0x2000) fprintf(pefile, " Dll File.");
						if ((header.Characteristics & 0x4000) == 0x4000) fprintf(pefile, " Application Runs Only In UniProcessor.");

		
						fprintf(pefile,"\n%-36s%s", "Time Stamp :", ctime(&(header.TimeDateStamp)));
						fprintf(pefile,"\n%-36s%d", "No.sections(size) :", header.NumberOfSections);
						fprintf(pefile,"\n%-36s%d", "No.entries in symbol table :", header.NumberOfSymbols);
						fprintf(pefile,"\n%-36s%d", "Size of optional header :", header.SizeOfOptionalHeader);

						fprintf(pefile, "\n\nDumping PE Optional Header Info....\n-----------------------------------");
						
						opHeader = ntHeader->OptionalHeader;
						fprintf(pefile,"\n\nInfo of optional Header\n-----------------------");
						fprintf(pefile, "\n%-36s%#x", "Address of Entry Point : ", opHeader.AddressOfEntryPoint);
						fprintf(pefile, "\n%-36s%#x", "Base Address of the Image : ", opHeader.ImageBase);
						fprintf(pefile, "\n%-36s%s", "SubSystem type : ",
							opHeader.Subsystem == 1 ? "Device Driver(Native windows Process)" :
							opHeader.Subsystem == 2 ? "Windows GUI" :
							opHeader.Subsystem == 3 ? "Windows CLI" :
							opHeader.Subsystem == 9 ? "Windows CE GUI" :
							"Unknown"
						);
						fprintf(pefile, "\n%-36s%s", "Given file is a : ", opHeader.Magic == 0x20b ? "PE32+(64)" : "PE32");
						fprintf(pefile, "\n%-36s%d", "Size of code segment(.text) : ", opHeader.SizeOfCode);
						fprintf(pefile, "\n%-36s%#x", "Base address of code segment(RVA) :", opHeader.BaseOfCode);
						fprintf(pefile, "\n%-36s%d", "Size of Initialized data : ", opHeader.SizeOfInitializedData);
						//fprintf(pefile, "\n%-36s%#x", "Base address of data segment(RVA) :", opHeader.BaseOfData);
						fprintf(pefile, "\n%-36s%#x", "Section Alignment :", opHeader.SectionAlignment);
						fprintf(pefile, "\n%-36s%d", "Major Linker Version : ", opHeader.MajorLinkerVersion);
						fprintf(pefile, "\n%-36s%d", "Minor Linker Version : ", opHeader.MinorLinkerVersion);
						fprintf(pefile, "\n\nDumping Sections Header Info....\n--------------------------------");

						fclose(pefile);

						for (pSecHeader = IMAGE_FIRST_SECTION(ntHeader), PeFile = 0; PeFile < ntHeader->FileHeader.NumberOfSections; PeFile++, pSecHeader++) {
							
							pefile = fopen("PEDump.txt", "a");
							
							fprintf(pefile,"\n\nSection Info (%d of %d)", PeFile + 1, ntHeader->FileHeader.NumberOfSections);
							fprintf(pefile,"\n---------------------");
							fprintf(pefile,"\n%-36s%s", "Section Header name : ", pSecHeader->Name);
							fprintf(pefile,"\n%-36s%#x", "ActualSize of code or data : ", pSecHeader->Misc.VirtualSize);
							fprintf(pefile,"\n%-36s%#x", "Virtual Address(RVA) :", pSecHeader->VirtualAddress);
							fprintf(pefile,"\n%-36s%#x", "Size of raw data (rounded to FA) : ", pSecHeader->SizeOfRawData);
							fprintf(pefile,"\n%-36s%#x", "Pointer to Raw Data : ", pSecHeader->PointerToRawData);
							fprintf(pefile,"\n%-36s%#x", "Pointer to Relocations : ", pSecHeader->PointerToRelocations);
							fprintf(pefile,"\n%-36s%#x", "Pointer to Line numbers : ", pSecHeader->PointerToLinenumbers);
							fprintf(pefile,"\n%-36s%#x", "Number of relocations : ", pSecHeader->NumberOfRelocations);
							fprintf(pefile,"\n%-36s%#x", "Number of line numbers : ", pSecHeader->NumberOfLinenumbers);
							fprintf(pefile,"\n%-36s%s", "Characteristics : ", "Contains ");
							if ((pSecHeader->Characteristics & 0x20) == 0x20)fprintf(pefile,"executable code, ");
							if ((pSecHeader->Characteristics & 0x40) == 0x40)fprintf(pefile,"initialized data, ");
							if ((pSecHeader->Characteristics & 0x80) == 0x80)fprintf(pefile,"uninitialized data, ");
							if ((pSecHeader->Characteristics & 0x80) == 0x80)fprintf(pefile,"uninitialized data, ");
							if ((pSecHeader->Characteristics & 0x200) == 0x200)fprintf(pefile,"comments and linker commands, ");
							if ((pSecHeader->Characteristics & 0x10000000) == 0x10000000)fprintf(pefile,"shareable data(via DLLs), ");
							if ((pSecHeader->Characteristics & 0x40000000) == 0x40000000)fprintf(pefile,"Readable, ");
							if ((pSecHeader->Characteristics & 0x80000000) == 0x80000000)fprintf(pefile,"Writable, ");

							fclose(pefile);

							if (pSecHeader->SizeOfRawData != 0) {
								HexDump((char *)((BYTE*)dosHeader + pSecHeader->PointerToRawData), pSecHeader->SizeOfRawData, opHeader.ImageBase + pSecHeader->VirtualAddress);
							}
						}
					}

					
					UnmapViewOfFile(lpBase);
					CloseHandle(hMapObject);
					fclose(pefile);
					printf("\n\nOperation Completed.\n");
					system("pause");
					Display_Graphics(privilege);

				}
			} while (File_Found != 1);

		}
		else if (option == '7') {
			
			_NtQuerySystemInformation NtQuerySystemInformation =
				GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
			_NtDuplicateObject NtDuplicateObject =
				GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
			_NtQueryObject NtQueryObject =
				GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
			NTSTATUS status;
			PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
			ULONG handleInfoSize = 0x10000;
			HANDLE processHandle;
			ULONG countHandle;
			FILE *HandleFile;
			HandleFile = fopen("HandleDump.txt", "a");

			printf("\n");
			while (spi->NextEntryOffset)
			{
				h[i] = spi->ProcessId;
				pName[i].Buffer = spi->ImageName.Buffer;
				printf("Process name: %ws | Process ID: %d\n", spi->ImageName.Buffer, spi->ProcessId);
				spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
				i++;
			}

			x = i;

			printf("\nEnter Process ID :");


			pid = getInt();

			printf("\n");

			UNICODE_STRING pNameToBePassed;
			pNameToBePassed.Buffer = NULL;

			for (i = 0; i < x; i++) {
				if (h[i] == pid) {
					pNameToBePassed.Buffer = pName[i].Buffer;
				}
			}

			if (pNameToBePassed.Buffer != NULL) {
				fprintf(HandleFile, "Handle Analysis Of : %ws\n", pNameToBePassed.Buffer);
				fprintf(HandleFile, "Process ID : %d\n\n", pid);
				

				if ((processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
				{

					handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

					while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
						handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

					if (NT_SUCCESS(status))
					{
						
						for (i = 0; i < handleInfo->HandleCount; i++)
						{
							SYSTEM_HANDLE handle = handleInfo->Handles[i];
							HANDLE dupHandle = NULL;
							POBJECT_TYPE_INFORMATION objectTypeInfo;
							PVOID objectNameInfo;
							UNICODE_STRING objectName;
							ULONG returnLength;

							if (handle.ProcessId != pid)
								continue;

							if (!NT_SUCCESS(NtDuplicateObject(processHandle, handle.Handle, GetCurrentProcess(), &dupHandle, 0,	0, 0)))
							{
								fprintf(HandleFile,"[%#x] Error!\n", handle.Handle);
								continue;
							}

							objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
							if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation,	objectTypeInfo,	0x1000,	NULL))){
								fprintf(HandleFile, "[%#x] Error!\n", handle.Handle);
								CloseHandle(dupHandle);
								continue;
							}

							if (handle.GrantedAccess == 0x0012019f)
							{
								fprintf(HandleFile, "[%#x] %.*S: (did not get name)\n",	handle.Handle, objectTypeInfo->Name.Length / 2,	objectTypeInfo->Name.Buffer);
								free(objectTypeInfo);
								CloseHandle(dupHandle);
								continue;
							}

							objectNameInfo = malloc(0x1000);
							if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,	objectNameInfo,	0x1000,	&returnLength)))
							{
								objectNameInfo = realloc(objectNameInfo, returnLength);

								if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,	objectNameInfo,	returnLength, NULL)))
								{
									fprintf(HandleFile,	"[%#x] %.*S: (could not get name)\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
									free(objectTypeInfo);
									free(objectNameInfo);
									CloseHandle(dupHandle);
									continue;
								}
							}

							objectName = *(PUNICODE_STRING)objectNameInfo;

							if (objectName.Length)
							{
								fprintf(HandleFile, "[%#x] %.*S: %.*S\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer, objectName.Length / 2, objectName.Buffer);
							}
							else
							{
								fprintf(HandleFile,	"[%#x] %.*S: (unnamed)\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
							}

							free(objectTypeInfo);
							free(objectNameInfo);
							CloseHandle(dupHandle);
						}

						free(handleInfo);
						CloseHandle(processHandle);
						
					}
					else {
						printf("NtQuerySystemInformation failed!\n");
					}

				}
				else {

					printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);

				}

				fprintf(HandleFile, "\n\n***********************End Of Report*************************\n\n\n");
				fclose(HandleFile);
				printf("\n\nOperation Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}
			else {
				fclose(HandleFile);
				printf("\nInvalid PID. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);
			}

		}
		else if (option == '8') {

			char fName[300];
			printf("\n");
			printf("Enter File Name Along With Extension (Example : Test.txt) : ");
			gets(fName);
			printf("\n");

			ScanFile_DisplayAnalysis(fName);

			printf("\n\nOperation Completed.\n");
			system("pause");
			Display_Graphics(privilege);

		}
		else if (option == '9') {

			while (1) {

				unsigned long long int key;
				char fName[300];
				int encrdcr;
				printf("\n1. Encrypt File\n");
				printf("2. Decrypt File\n");
				printf("\nChoose an option : ");
				encrdcr = getInt();
				printf("\n");
				printf("Enter Key (Upto 9 Digits) : ");
				key = getUSLLInt();				
				printf("\n");

				FILE *inFile, *outFile;
				long  int inFileSize;

				printf("Enter File Name Along With Extension (Example : Test.txt) : ");
				gets(fName);
				printf("\n");

				if(encrdcr == 1){
				
					char buffer[1024];


					inFile = fopen(fName, "rb");

					if (inFile == NULL) {

						printf("Wrong File Name Or File Does Not Exist!\n");
						system("pause");
						break;

					}

					outFile = fopen("Encrypted", "wb");


					if (outFile == NULL) {

						printf("Error Creating File...\n");
						system("pause");
						break;

					}
				
					int countFile;

					while (countFile = fread(buffer, 1, 1024, inFile))
					{
						int i;
						int end = countFile / 4;
						if (countFile % 4)
							++end;

						for (i = 0; i < end; ++i)
						{
							((unsigned long long int *)buffer)[i] ^= key;
						}
						if (fwrite(buffer, 1, countFile, outFile) != countFile)
						{
							fclose(inFile);
							fclose(outFile);

							printf("Error Encrypting....\n");

							system("pause");
						}
					}

					fclose(inFile);
					fclose(outFile);

					printf("File Has Been Encrypted. The File Extension Has Been Stripped.!\n");
					system("pause");
					break;

				}
				else if(encrdcr == 2){
				
					char buffer[1024];


					inFile = fopen(fName, "rb");

					if (inFile == NULL) {

						printf("Wrong File Name Or File Does Not Exist!\n");
						system("pause");
						break;

					}

					outFile = fopen("Decrypted", "wb");


					if (outFile == NULL) {

						printf("Error Creating File...\n");
						system("pause");
						break;

					}

					int countFile;

					while (countFile = fread(buffer, 1, 1024, inFile))
					{
						int i;
						int end = countFile / 4;
						if (countFile % 4)
							++end;

						for (i = 0; i < end; ++i)
						{
							((unsigned long long int *)buffer)[i] ^= key;
						}
						if (fwrite(buffer, 1, countFile, outFile) != countFile)
						{
							fclose(inFile);
							fclose(outFile);

							printf("Error Encrypting....\n");

							system("pause");
						}
					}

					fclose(inFile);
					fclose(outFile);

					printf("File Has Been Decrypted. Add The Desired Extension To Make The File Valid!\n");
					system("pause");
					break;

				}
				else{
				
					printf("\nInvalid Input. Please Try Again.\n");			
				
				}

			}
			
			printf("\n\nOperation Completed.\n");
			system("pause");
			Display_Graphics(privilege);

		}
		else if (option == 'A' || option == 'a') {
			
			int loopdrives;
			DWORD drives = GetLogicalDrives();
			int drivenum[26];
			int drivecount = 0;

			for (loopdrives = 0; loopdrives < 26; loopdrives++) {

				drivenum[loopdrives] = 0;

			}



			printf("\n");
			printf("Logical Volumes : \n");
			char Drive1[] = { ("A:\\") };
			TCHAR Drive2[] = L"\\\\.\\A:";

			for (loopdrives = 0; loopdrives < 26; loopdrives++)
			{
				if (drives & (1 << loopdrives))
				{
					drivecount = drivecount + 1;
					Drive1[0] = ('A') + loopdrives;
					printf("%d. %s\n", drivecount, Drive1);
					drivenum[loopdrives] = loopdrives;
				}

			}

			printf("Enter Logical Drive Number :");

			int getLogicalDriveNumber = 0;
			getLogicalDriveNumber = getInt();

			printf("\n");

			if (getLogicalDriveNumber > 0 && getLogicalDriveNumber <= drivecount) {

				int countdrive = 0;
				int driveloop;

				for (driveloop = 0; driveloop < 26; driveloop++) {

					if (drivenum[driveloop] != 0) {

						Drive2[4] = ('A') + drivenum[driveloop];
						countdrive = countdrive + 1;

						if (countdrive == getLogicalDriveNumber) {

							ScanLogicalDisk_DeleteDisk(Drive2);
							printf("\n\nOperation Completed.\n");
							system("pause");
							Display_Graphics(privilege);
							break;

						}

					}

				}

			}
			else {

				printf("\nInvalid Drive. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);

			}

		}
		else if (option == 'B' || option == 'b') {
			
			printf("\n");
			printf("Physical Volumes : \n");

			HANDLE device[100];
			TCHAR strPathFinal[100][20];

			for (int clear1 = 0; clear1 < 100; clear1++) {
				for (int clear2 = 0; clear2 < 20; clear2++) {
					strPathFinal[clear1][clear2] = NULL;
				}
			}

			int diskloop;
			int diskcounter = 0;

			for (diskloop = 0; diskloop < 100; diskloop++) {

				TCHAR strPath0[] = L"\\\\.\\PhysicalDrive0";
				TCHAR strPath1[] = L"\\\\.\\PhysicalDrive10";
				TCHAR strPath2[] = L"\\\\.\\PhysicalDrive20";
				TCHAR strPath3[] = L"\\\\.\\PhysicalDrive30";
				TCHAR strPath4[] = L"\\\\.\\PhysicalDrive40";
				TCHAR strPath5[] = L"\\\\.\\PhysicalDrive50";
				TCHAR strPath6[] = L"\\\\.\\PhysicalDrive60";
				TCHAR strPath7[] = L"\\\\.\\PhysicalDrive70";
				TCHAR strPath8[] = L"\\\\.\\PhysicalDrive80";
				TCHAR strPath9[] = L"\\\\.\\PhysicalDrive90";


				if (diskloop >= 0 && diskloop < 10) {
					strPath0[17] = ('0') + diskloop;
					device[diskloop] = CreateFile(strPath0, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath0);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}
				}
				else if (diskloop >= 10 && diskloop < 20) {
					strPath1[18] = ('0') + (diskloop - 10);
					device[diskloop] = CreateFile(strPath1, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath1);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}
				}
				else if (diskloop >= 20 && diskloop < 30) {
					strPath2[18] = ('0') + (diskloop - 20);
					device[diskloop] = CreateFile(strPath2, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath2);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 30 && diskloop < 40) {
					strPath3[18] = ('0') + (diskloop - 30);
					device[diskloop] = CreateFile(strPath3, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath3);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 40 && diskloop < 50) {
					strPath4[18] = ('0') + (diskloop - 40);
					device[diskloop] = CreateFile(strPath4, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath4);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 50 && diskloop < 60) {
					strPath5[18] = ('0') + (diskloop - 50);
					device[diskloop] = CreateFile(strPath5, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath5);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 60 && diskloop < 70) {
					strPath6[18] = ('0') + (diskloop - 60);
					device[diskloop] = CreateFile(strPath6, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath6);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 70 && diskloop < 80) {
					strPath7[18] = ('0') + (diskloop - 70);
					device[diskloop] = CreateFile(strPath7, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath7);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 80 && diskloop < 90) {
					strPath8[18] = ('0') + (diskloop - 80);
					device[diskloop] = CreateFile(strPath8, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath8);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}
				else if (diskloop >= 90 && diskloop < 100) {
					strPath9[18] = ('0') + (diskloop - 90);
					device[diskloop] = CreateFile(strPath9, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

					if (device[diskloop] != INVALID_HANDLE_VALUE)
					{
						diskcounter = diskcounter + 1;
						wcscpy(strPathFinal[diskloop], strPath9);
						printf("%d. %ws\n", diskcounter, strPathFinal[diskloop]);
					}

				}

			}

			printf("Enter Physical Drive : ");
			int getDisk = getInt();
			printf("\n");
			int validcounter = 0;

			if (getDisk > 0 && getDisk <= diskcounter) {

				for (diskloop = 0; diskloop < 100; diskloop++) {

					if (device[diskloop] != INVALID_HANDLE_VALUE) {

						validcounter = validcounter + 1;
						if (validcounter == getDisk) {
							int loopvalue = diskloop;
							
							for (diskloop = 0; diskloop < 100; diskloop++) {

								if (device[diskloop] != INVALID_HANDLE_VALUE) {

									CloseHandle(device[diskloop]);

								}

							}

								ScanPhysicalDisk_DeleteDisk(strPathFinal[loopvalue]);							

							printf("\n\nOperation Completed.\n");
							system("pause");
							Display_Graphics(privilege);
							break;
						}

					}

				}
			}
			else {

				printf("\nInvalid Drive. Please Try Again.\n");
				system("pause");
				Display_Graphics(privilege);

			}

		}
		else if (option == 'C' || option == 'c') {
			
		
			char PeFileName[400];
			printf("\nEnter PE File Name With Extension : ");
			scanf("%s", PeFileName);
			printf("\n");

			int status = Disable_DEP_ASLR(PeFileName, 0, 0);

			if (status == 1) {
				printf("\n\nOperation Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}
			else {
				printf("\n\nOperation Could Not Be Completed.\n");
				system("pause");
				Display_Graphics(privilege);
			}
		}
		else if (option == 'Q' || option == 'q') {
			break;
		}
		else {
			printf("\nInvalid Input. Please Try Again.\n");
			system("pause");
			Display_Graphics(privilege);
		}
	}


	VirtualFree(buffer, 0, MEM_RELEASE);
	printf("\n\nExiting.\n");
	system("pause");
	return 0;

}
