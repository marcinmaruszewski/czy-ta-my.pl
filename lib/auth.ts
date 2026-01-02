import type { NextAuthOptions, Session } from "next-auth"
import type { JWT } from "next-auth/jwt"
import GoogleProvider from "next-auth/providers/google"

declare module "next-auth" {
    interface Session {
        user: {
            id: string
            sub: string
            name?: string | null
            email?: string | null
            image?: string | null
        }
    }
}

declare module "next-auth/jwt" {
    interface JWT {
        sub: string
    }
}

/**
 * NextAuth configuration with Google OAuth provider.
 * 
 * Required environment variables:
 * - GOOGLE_CLIENT_ID: Google OAuth client ID
 * - GOOGLE_CLIENT_SECRET: Google OAuth client secret
 * - NEXTAUTH_SECRET: Secret for JWT encryption
 * - NEXTAUTH_URL: Base URL of the app (for production)
 */
export const authOptions: NextAuthOptions = {
    providers: [
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID ?? "",
            clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
        }),
    ],

    callbacks: {
        /**
         * Include the user's Google 'sub' claim in the JWT.
         * This 'sub' is used for encryption key derivation.
         */
        async jwt({ token, account, profile }): Promise<JWT> {
            if (account && profile) {
                // 'sub' is the unique Google user ID
                token.sub = profile.sub ?? token.sub ?? ""
            }
            return token
        },

        /**
         * Include 'sub' in the session for client access.
         * WARNING: 'sub' is sensitive - don't expose in client-side code!
         * Only use for server-side encryption operations.
         */
        async session({ session, token }): Promise<Session> {
            if (session.user) {
                session.user.id = token.sub ?? ""
                session.user.sub = token.sub ?? ""
            }
            return session
        },
    },

    session: {
        strategy: "jwt",
        maxAge: 30 * 24 * 60 * 60, // 30 days
    },
}
