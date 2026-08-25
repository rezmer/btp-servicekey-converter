# btp-servicekey-converter

Turn a SAP BTP service key JSON into a usable `.pfx` and `.pem` — interactive PowerShell tool, no OpenSSL, works on Windows PowerShell 5.1.

SAP BTP service keys with `credential-type: x509` (for example SAP Cloud ALM mTLS bindings) contain the certificate chain and the private key as JSON string fields, with literal `\n` escapes instead of real line breaks. That format cannot be imported anywhere directly. This script converts such a service key into:

- a **password-protected PKCS#12 file** (`.pfx`) containing the leaf certificate, the full chain and the private key
- a **plain PEM bundle** (`.pem`) with real line breaks, for tools and portals that expect PEM rather than PKCS#12

## Requirements

- Windows PowerShell 5.1 (Windows 10/11) — PowerShell 7 works too, but is not required
- .NET Framework 4.8 recommended; older versions also work via a built-in fallback parser (see [How it works](#how-it-works))
- No OpenSSL, no additional modules

## Usage

Run it without any parameters for the interactive flow:

```powershell
.\New-PfxFromServiceKey.ps1
```

You will be asked:

1. **How to provide the certificate and key**
   - `[1]` path to a service key JSON file
   - `[2]` paste the service key JSON directly into the console (finish with `EOF` on its own line)
   - `[3]` separate paths to an existing certificate file and key file
2. **Where to write the output** — defaults to the folder the script is running from, named after the current date and time (e.g. `2026-08-25-13-35.pfx`). The `.pem` file is written next to it with the same base name.
3. **Which password to use** — either auto-generate one (printed once to the console) or set your own with confirmation.

### Non-interactive / automation

All prompts can be skipped via parameters:

```powershell
$pw = Read-Host "PFX password" -AsSecureString
.\New-PfxFromServiceKey.ps1 -ServiceKeyPath .\servicekey.json -OutputPath .\cert.pfx -Password $pw
```

| Parameter | Description |
| --- | --- |
| `-ServiceKeyPath` | Path to the service key JSON file |
| `-OutputPath` | Target path for the `.pfx`; the `.pem` is written alongside it |
| `-JsonKeyPath` | JSON node holding `certificate` and `key` (default: `uaa`) |
| `-Password` | PFX password as `SecureString` |

## Execution policy

Windows blocks unsigned scripts by default, and files downloaded from a browser are additionally flagged as coming from the internet. Depending on your setup you may see:

```
.\New-PfxFromServiceKey.ps1 : File cannot be loaded. The file is not digitally signed.
You cannot run this script on the current system.
```

Fixes, from least invasive upwards:

```powershell
# 1. Remove the "downloaded from the internet" mark (most common cause)
Unblock-File -Path .\New-PfxFromServiceKey.ps1

# 2. Allow scripts for the current session only (no admin rights needed)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Allow local scripts permanently for your user (no admin rights needed)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If your organisation enforces the execution policy through group policy, options 2 and 3 will be rejected and you will need an exception or a signed copy of the script from your IT department.

## Expected input

The script looks for a `certificate` and a `key` field, by default under the `uaa` node (override with `-JsonKeyPath`). Fields directly at root level are also accepted.

```json
{
  "uaa": {
    "credential-type": "x509",
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...",
    "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----\n",
    "clientid": "sb-...",
    "certurl": "https://<tenant>.authentication.cert.<region>.hana.ondemand.com"
  }
}
```

Supported private key formats: PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`). Encrypted private keys are not supported.

## How it works

- **Key import** uses .NET's native `RSA.ImportRSAPrivateKey()` / `ImportPkcs8PrivateKey()` when available. On older .NET Framework versions these methods are missing, so the script falls back to a small built-in ASN.1/DER parser that decodes the key structure by hand.
- **Certificate and key are matched** before anything is written: if the private key's modulus does not match the certificate's public key, the script aborts instead of producing a broken file.
- **The private key is attached** through a named, persisted CAPI key container (`ProviderType 24`, the AES-capable provider needed by SHA-256 signed certificates). The container is deleted again when the script finishes.
- **The result is verified** by re-importing the exported `.pfx` and confirming the private key is present. A PKCS#12 file without a key would otherwise only fail much later, at import time, with errors such as `No key found in supplied blob`.

## Security notes

- The `.pem` output is **not encrypted** — it contains the private key in clear text, because that is what tools expecting PEM need. Treat it accordingly and delete it once it has served its purpose.
- The generated PFX password is printed to the console exactly once. Store it somewhere safe immediately.
- Never commit service keys, `.pfx`, `.pem` or `.key` files to a repository. The included `.gitignore` covers the usual extensions, but check `git status` before your first commit.
- If a private key was ever exposed, rotating the credentials (rebinding the service instance) is the only way to invalidate it — SAP does not check certificate revocation for these bindings.

## Testing a converted key

```powershell
curl --cert certificate.pem --key key.pem -X POST `
  "https://<tenant>.authentication.cert.<region>.hana.ondemand.com/oauth/token" `
  -d "grant_type=client_credentials&client_id=<clientid>"
```

## License

MIT
