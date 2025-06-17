import { User } from "@/@types/user";
import { cookies } from "next/headers";

export async function getUserFromBackend(): Promise<User | null> {
  console.log("getUserFromBackend function called");
  
  const cookieStore = await cookies(); //ssr cookies safe
  
  // Get all cookies for debugging
  const allCookies = cookieStore.getAll();
  console.log("All cookies:", allCookies.map(c => c.name));
  
  // Try both cookie names to debug
  const token = cookieStore.get("AuthToken")?.value || cookieStore.get("token")?.value;
  console.log("Found token:", token ? "Yes" : "No");

  if (!token) {
    console.log("No token found, returning null");
    return null;
  }

  // Use a server-side only environment variable
  const apiUrl = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL;
  console.log("Using API URL:", apiUrl);
  
  try {
    console.log(`Fetching profile from ${apiUrl}/auth/profile`);
    const res = await fetch(`${apiUrl}/auth/profile`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10000), 
    });

    console.log("Profile response status:", res.status);

    if (!res.ok) {
      console.log("Response not OK:", res.status, res.statusText);
      return null;
    }

    const user = await res.json();
    console.log("User data retrieved successfully:", user);
    return user;
  } catch (error) {
    console.error("Error fetching user data:", error);
    return null;
  }
}