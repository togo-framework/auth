// togo auth client. Talks to the auth plugin's /api/auth/* endpoints. Session is
// an HttpOnly cookie (set by the server); CSRF uses the double-submit token.
"use client";

const API = process.env.NEXT_PUBLIC_API_ORIGIN ?? "";

async function csrf(): Promise<string> {
  const res = await fetch(`${API}/api/auth/csrf`, { credentials: "include" });
  const data = await res.json().catch(() => ({}));
  return data.csrf_token ?? "";
}

async function post<T = any>(path: string, body?: unknown): Promise<T> {
  const token = await csrf();
  const res = await fetch(`${API}/api/auth/${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.detail || `request failed (${res.status})`);
  return data as T;
}

export const auth = {
  login: (email: string, password: string) => post("login", { email, password }),
  register: (email: string, password: string) => post("register", { email, password }),
  logout: () => post("logout"),
  me: async () => {
    const res = await fetch(`${API}/api/auth/me`, { credentials: "include" });
    if (!res.ok) return null;
    return res.json();
  },
  requestOtp: (email: string, purpose = "reset") => post("otp", { email, purpose }),
  verifyOtp: (email: string, code: string, purpose = "reset") => post("otp/verify", { email, code, purpose }),
  changePassword: (oldPassword: string, newPassword: string) =>
    post("change-password", { old_password: oldPassword, new_password: newPassword }),
  enroll2fa: () => post<{ secret: string; otpauth_url: string }>("2fa/enroll"),
  verify2fa: (code: string) => post("2fa/verify", { code }),
  setPin: (pin: string) => post("pin", { pin }),
  verifyPin: (pin: string) => post("pin/verify", { pin }),
};
