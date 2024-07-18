import Credentials from "next-auth/providers/credentials"
import bcrypt from "bcryptjs"
import type { NextAuthConfig } from "next-auth"
import { loginSchema } from "./schemas"
import { getUserByEmail } from "./data/user"

export default {
    providers: [
        Credentials({
            async authorize(credentials) {
                const validatedFields = await loginSchema.safeParse(credentials)
                
                if(validatedFields.success){
                   const {email, password} = validatedFields.data

                   const user = await getUserByEmail(email)
                   if(!user || !user.password) return null;
                    const pwdMatch = await bcrypt.compare(password, user.password) 
                    if(pwdMatch){
                        return user
                    }
                  }
                return null
            
            }
        })

    ]
} satisfies NextAuthConfig