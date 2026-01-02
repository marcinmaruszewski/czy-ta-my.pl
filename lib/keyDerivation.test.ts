import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { deriveEncryptionKey, deriveEncryptionKeyFromEnv } from "./keyDerivation"

describe("keyDerivation", () => {
    describe("deriveEncryptionKey", () => {
        it("returns a 64-character hex string", () => {
            const key = deriveEncryptionKey("google-sub-123", "server-secret")

            expect(key).toHaveLength(64)
            expect(key).toMatch(/^[a-f0-9]{64}$/)
        })

        it("is deterministic (same inputs produce same output)", () => {
            const googleSub = "123456789012345678901"
            const serverSecret = "my-secret"

            const key1 = deriveEncryptionKey(googleSub, serverSecret)
            const key2 = deriveEncryptionKey(googleSub, serverSecret)

            expect(key1).toBe(key2)
        })

        it("produces different keys for different googleSub", () => {
            const serverSecret = "same-secret"

            const key1 = deriveEncryptionKey("user-1", serverSecret)
            const key2 = deriveEncryptionKey("user-2", serverSecret)

            expect(key1).not.toBe(key2)
        })

        it("produces different keys for different serverSecret", () => {
            const googleSub = "same-user"

            const key1 = deriveEncryptionKey(googleSub, "secret-1")
            const key2 = deriveEncryptionKey(googleSub, "secret-2")

            expect(key1).not.toBe(key2)
        })

        it("throws error when googleSub is empty", () => {
            expect(() => deriveEncryptionKey("", "secret")).toThrow()
        })

        it("throws error when serverSecret is empty", () => {
            expect(() => deriveEncryptionKey("sub", "")).toThrow()
        })
    })

    describe("deriveEncryptionKeyFromEnv", () => {
        const originalEnv = process.env

        beforeEach(() => {
            vi.resetModules()
            process.env = { ...originalEnv }
        })

        afterEach(() => {
            process.env = originalEnv
        })

        it("uses ENCRYPTION_SECRET from environment", () => {
            process.env.ENCRYPTION_SECRET = "test-secret"

            const key1 = deriveEncryptionKeyFromEnv("user-123")
            const key2 = deriveEncryptionKey("user-123", "test-secret")

            expect(key1).toBe(key2)
        })

        it("throws error when ENCRYPTION_SECRET is not set", () => {
            delete process.env.ENCRYPTION_SECRET

            expect(() => deriveEncryptionKeyFromEnv("user-123")).toThrow("ENCRYPTION_SECRET")
        })
    })
})
