import { User } from "@/@types/user";
import { cookies } from "next/headers";
export async function getUserFromBackend(): Promise<User | null> {
  const cookieStore = await cookies(); //ssr cookies safe

  const token = cookieStore.get("token")?.value;

  if (!token) {
    return null;
  }

  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/profile`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });

  if (!res.ok) {
    return null;
  }

  try {
    const user: User = await res.json();
    return user;
  } catch (error) {
    console.error("Error parsing user data:", error);
    return null;
  }
}
