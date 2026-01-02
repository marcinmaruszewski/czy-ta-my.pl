import crypto from "crypto"

const PBKDF2_ITERATIONS = 100_000
const KEY_LENGTH = 32 // 256 bits for AES-256
const DIGEST = "sha256"

/**
 * Derives a symmetric encryption key from the user's Google 'sub' claim
 * and a server-side secret.
 * 
 * The key is NEVER stored - it's derived on-the-fly when needed.
 * 
 * @param googleSub - User's unique Google 'sub' claim (e.g., "123456789012345678901")
 * @param serverSecret - Server-side secret from environment variable
 * @returns 64-character hex string (256-bit key)
 */
export function deriveEncryptionKey(googleSub: string, serverSecret: string): string {
    if (!googleSub || !serverSecret) {
        throw new Error("Both googleSub and serverSecret are required for key derivation")
    }

    // Use googleSub as salt (unique per user)
    // Use serverSecret as password (same for all users, secret)
    const salt = Buffer.from(googleSub, "utf8")
    const password = Buffer.from(serverSecret, "utf8")

    const derivedKey = crypto.pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        DIGEST
    )

    return derivedKey.toString("hex")
}

/**
 * Derives encryption key using environment variable for server secret.
 * 
 * @param googleSub - User's unique Google 'sub' claim
 * @returns 64-character hex string (256-bit key)
 * @throws Error if ENCRYPTION_SECRET env var is not set
 */
export function deriveEncryptionKeyFromEnv(googleSub: string): string {
    const serverSecret = process.env.ENCRYPTION_SECRET

    if (!serverSecret) {
        throw new Error("ENCRYPTION_SECRET environment variable is not set")
    }

    return deriveEncryptionKey(googleSub, serverSecret)
}
