# CIRIS Keys Directory

This directory contains critical cryptographic keys for the CIRIS system.

## Files

### secrets_master.key
- **Purpose**: Master encryption key for the SecretsService
- **Type**: 256-bit symmetric key
- **Usage**: Used to derive per-secret encryption keys via PBKDF2
- **Algorithm**: AES-256-GCM encryption
- **Critical**: Loss of this key means all encrypted secrets become unrecoverable

### audit_signing_private.pem
- **Purpose**: Private key for signing audit log entries
- **Type**: RSA 2048-bit private key
- **Usage**: Creates digital signatures for non-repudiation
- **Critical**: Keep this key secure - compromise allows forging audit entries

### audit_signing_public.pem
- **Purpose**: Public key for verifying audit signatures
- **Type**: RSA 2048-bit public key
- **Usage**: Verifies signatures on audit entries
- **Note**: Can be shared publicly for verification purposes

## Security Notes

1. **Permissions**: All key files should have restrictive permissions (600)
2. **Backup**: Regularly backup these keys to secure offline storage
3. **Rotation**: Consider key rotation policies for long-running deployments
4. **Access**: Only the CIRIS process should access these keys

## DO NOT
- Commit these files to version control
- Share the private keys or master key
- Store copies in insecure locations
