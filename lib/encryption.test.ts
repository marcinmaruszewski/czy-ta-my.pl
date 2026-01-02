import { describe, expect, it } from "vitest"
import { decryptText, encryptText } from "./encryption"

describe("encryption", () => {
    const testKey = "a".repeat(64) // Valid 256-bit hex key

    describe("encryptText / decryptText roundtrip", () => {
        it("encrypts and decrypts text correctly", () => {
            const plaintext = "Hello, World!"
            const encrypted = encryptText(plaintext, testKey)
            const decrypted = decryptText(encrypted, testKey)

            expect(decrypted).toBe(plaintext)
        })

        it("handles empty string", () => {
            const plaintext = ""
            const encrypted = encryptText(plaintext, testKey)
            const decrypted = decryptText(encrypted, testKey)

            expect(decrypted).toBe(plaintext)
        })

        it("handles unicode characters", () => {
            const plaintext = "Zażółć gęślą jaźń 🎉 日本語"
            const encrypted = encryptText(plaintext, testKey)
            const decrypted = decryptText(encrypted, testKey)

            expect(decrypted).toBe(plaintext)
        })

        it("handles long text", () => {
            const plaintext = "Lorem ipsum ".repeat(1000)
            const encrypted = encryptText(plaintext, testKey)
            const decrypted = decryptText(encrypted, testKey)

            expect(decrypted).toBe(plaintext)
        })
    })

    describe("encryption properties", () => {
        it("produces different ciphertext for same plaintext (due to random IV)", () => {
            const plaintext = "Same text"
            const encrypted1 = encryptText(plaintext, testKey)
            const encrypted2 = encryptText(plaintext, testKey)

            expect(encrypted1).not.toBe(encrypted2)
        })

        it("produces different ciphertext with different keys", () => {
            const plaintext = "Test message"
            const key1 = "a".repeat(64)
            const key2 = "b".repeat(64)

            const encrypted1 = encryptText(plaintext, key1)
            const encrypted2 = encryptText(plaintext, key2)

            expect(encrypted1).not.toBe(encrypted2)
        })

        it("fails to decrypt with wrong key", () => {
            const plaintext = "Secret message"
            const key1 = "a".repeat(64)
            const key2 = "b".repeat(64)

            const encrypted = encryptText(plaintext, key1)

            expect(() => decryptText(encrypted, key2)).toThrow()
        })
    })

    describe("key normalization", () => {
        it("accepts 64-char hex key", () => {
            const hexKey = "0123456789abcdef".repeat(4)
            const plaintext = "Test"

            const encrypted = encryptText(plaintext, hexKey)
            const decrypted = decryptText(encrypted, hexKey)

            expect(decrypted).toBe(plaintext)
        })

        it("accepts short key (hashes to 32 bytes)", () => {
            const shortKey = "password"
            const plaintext = "Test"

            const encrypted = encryptText(plaintext, shortKey)
            const decrypted = decryptText(encrypted, shortKey)

            expect(decrypted).toBe(plaintext)
        })
    })

    describe("error handling", () => {
        it("throws on invalid encrypted data", () => {
            expect(() => decryptText("invalid", testKey)).toThrow()
        })

        it("throws on tampered ciphertext", () => {
            const encrypted = encryptText("Test", testKey)
            const tampered = encrypted.slice(0, -4) + "XXXX"

            expect(() => decryptText(tampered, testKey)).toThrow()
        })
    })
})
