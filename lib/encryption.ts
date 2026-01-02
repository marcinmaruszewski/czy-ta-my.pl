import crypto from "crypto"

const ALGORITHM = "aes-256-gcm"
const IV_LENGTH = 16
const AUTH_TAG_LENGTH = 16

/**
 * Encrypts text using AES-256-GCM.
 * Returns base64 encoded string containing IV + ciphertext + authTag.
 * 
 * @param text - Plain text to encrypt
 * @param userKey - 256-bit encryption key (hex string or 32 bytes)
 * @returns Base64 encoded encrypted data
 */
export function encryptText(text: string, userKey: string): string {
    const key = normalizeKey(userKey)
    const iv = crypto.randomBytes(IV_LENGTH)

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv)

    const encrypted = Buffer.concat([
        cipher.update(text, "utf8"),
        cipher.final(),
    ])

    const authTag = cipher.getAuthTag()

    // Combine: IV (16 bytes) + encrypted + authTag (16 bytes)
    const combined = Buffer.concat([iv, encrypted, authTag])

    return combined.toString("base64")
}

/**
 * Decrypts text encrypted with encryptText.
 * 
 * @param encryptedData - Base64 encoded data from encryptText
 * @param userKey - Same key used for encryption
 * @returns Original plain text
 * @throws Error if decryption fails
 */
export function decryptText(encryptedData: string, userKey: string): string {
    const key = normalizeKey(userKey)
    const combined = Buffer.from(encryptedData, "base64")

    if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH) {
        throw new Error("Invalid encrypted data: too short")
    }

    const iv = combined.subarray(0, IV_LENGTH)
    const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH)
    const encrypted = combined.subarray(IV_LENGTH, combined.length - AUTH_TAG_LENGTH)

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
    ])

    return decrypted.toString("utf8")
}

/**
 * Normalizes key to 32-byte Buffer for AES-256.
 */
function normalizeKey(key: string): Buffer {
    // If hex string (64 chars = 32 bytes)
    if (/^[a-f0-9]{64}$/i.test(key)) {
        return Buffer.from(key, "hex")
    }

    // If already 32 bytes, use directly
    if (key.length === 32) {
        return Buffer.from(key, "utf8")
    }

    // Hash to get exactly 32 bytes
    return crypto.createHash("sha256").update(key).digest()
}
