# Next.js + .NET Authentication Project

This is a fullstack project using **Next.js** (App Router) on the frontend and **ASP.NET Core (.NET 8)** on the backend. The goal is to implement secure, modern authentication using **HTTP-only cookies** and a `/api/auth/profile` endpoint for user validation.

## Features

- Auth token stored in HTTP-only cookies for secure auth.
- Token extraction on backend via cookie, Authorization header, or query.
- Server-side rendering (SSR) support for fetching user info.
- Seamless user experience: show login/profile state correctly without client-side flicker.
- Clear separation of concerns between frontend and backend.

## Stack

- **Frontend:** Next.js (v15) with TypeScript, App Router
- **Backend:** ASP.NET Core (.NET 8) Web API
- **Auth:** JWT in HTTP-only cookies
- **Communication:** REST via fetch from server components

## How it works

1. On login, the backend sets a `Set-Cookie` header with the auth token.
2. The frontend uses server-side code to read the token from cookies using `cookies()` from `next/headers`.
3. If token exists, it calls `.NET API /api/v1/me` using `fetch()` and sets proper headers.
4. Based on the response, it shows login button or profile icon without waiting for hydration.

