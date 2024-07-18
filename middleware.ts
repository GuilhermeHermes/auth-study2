import NextAuth, { Session } from "next-auth"

import authConfig from "./auth.config"

import {
    DEFAULT_LOGIN_REDIRECT,
    apiAuthPrefix,
    publicRoutes,
    authRoutes
} from "@/routes"
import { NextRequest } from "next/server";


const { auth } = NextAuth(authConfig)

export default auth((req: NextRequest & { auth: Session | null }): Response | void => {
    const { nextUrl } = req;
    const isLoggedIn = !!req.auth;
    
    const isApiAuthRoute = nextUrl.pathname.startsWith(apiAuthPrefix);
    const isPublicRoute = publicRoutes.includes(nextUrl.pathname);
    const isAuthRoute = authRoutes.includes(nextUrl.pathname);
    
    if (isApiAuthRoute) {
      return;
    }
    
    if (isAuthRoute) {
      if (isLoggedIn) {
        return Response.redirect(new URL(DEFAULT_LOGIN_REDIRECT, nextUrl));
      }
      return;
    }
    
    if (!isLoggedIn && !isPublicRoute) {
      return Response.redirect(new URL('/auth/login', nextUrl));
      
    }
    
    return;
},
);


/**
 * Configuration object for middleware.
 */
export const config = {
    matcher: ['/((?!.*\\..*|_next).*)', '/', '/(api|trpc)(.*)'],
}