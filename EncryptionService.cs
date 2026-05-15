using System.Security.Cryptography;
using System.Text;

namespace HasiCorpWalletPOC.Services;

/// <summary>
/// AES-256-GCM encrypt / decrypt using the key fetched from Vault.
///
/// Wire format (all base64-encoded as one string):
///   [ 12-byte IV | ciphertext | 16-byte GCM tag ]
/// </summary>
public interface IEncryptionService
{
    Task<(string CipherText, string KeyVersion)> EncryptAsync(string plainText, CancellationToken ct = default);
    Task<string> DecryptAsync(string cipherText, CancellationToken ct = default);
}

public sealed class EncryptionService : IEncryptionService
{
    private const int IvSize  = 12; // 96-bit nonce — recommended for AES-GCM
    private const int TagSize = 16; // 128-bit authentication tag

    private readonly IVaultService _vault;
    private readonly ILogger<EncryptionService> _log;

    public EncryptionService(IVaultService vault, ILogger<EncryptionService> log)
    {
        _vault = vault;
        _log   = log;
    }

    // ──────────────────────────────────────────
    // Encrypt
    // ──────────────────────────────────────────

    public async Task<(string CipherText, string KeyVersion)> EncryptAsync(
        string plainText, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plainText);

        var (keyBytes, version) = await _vault.GetActiveKeyAsync(ct);

        using var aes = new AesGcm(keyBytes, TagSize);

        var iv         = RandomNumberGenerator.GetBytes(IvSize);
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipher     = new byte[plainBytes.Length];
        var tag        = new byte[TagSize];

        aes.Encrypt(iv, plainBytes, cipher, tag);

        // Pack: IV | ciphertext | tag  → single base64 blob
        var packed = new byte[IvSize + cipher.Length + TagSize];
        Buffer.BlockCopy(iv,     0, packed, 0,                         IvSize);
        Buffer.BlockCopy(cipher, 0, packed, IvSize,                    cipher.Length);
        Buffer.BlockCopy(tag,    0, packed, IvSize + cipher.Length,    TagSize);

        var cipherText = Convert.ToBase64String(packed);

        _log.LogInformation("Encrypted {Bytes} bytes using key version {Version}.",
            plainBytes.Length, version);

        return (cipherText, version);
    }

    // ──────────────────────────────────────────
    // Decrypt
    // ──────────────────────────────────────────

    public async Task<string> DecryptAsync(string cipherText, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cipherText);

        var (keyBytes, version) = await _vault.GetActiveKeyAsync(ct);

        byte[] packed;
        try
        {
            packed = Convert.FromBase64String(cipherText);
        }
        catch (FormatException)
        {
            throw new ArgumentException("CipherText is not valid base64.");
        }

        if (packed.Length < IvSize + TagSize + 1)
            throw new ArgumentException("CipherText is too short to be valid.");

        var cipherLen = packed.Length - IvSize - TagSize;

        var iv         = new byte[IvSize];
        var cipher     = new byte[cipherLen];
        var tag        = new byte[TagSize];
        var plainBytes = new byte[cipherLen];

        Buffer.BlockCopy(packed, 0,                      iv,     0, IvSize);
        Buffer.BlockCopy(packed, IvSize,                 cipher, 0, cipherLen);
        Buffer.BlockCopy(packed, IvSize + cipherLen,     tag,    0, TagSize);

        using var aes = new AesGcm(keyBytes, TagSize);

        try
        {
            aes.Decrypt(iv, cipher, tag, plainBytes);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException(
                "Decryption failed — authentication tag mismatch. " +
                "The data may be tampered, or the key has rotated since encryption.");
        }

        var plainText = Encoding.UTF8.GetString(plainBytes);

        _log.LogInformation("Decrypted {Bytes} bytes using key version {Version}.",
            plainBytes.Length, version);

        return plainText;
    }
}
