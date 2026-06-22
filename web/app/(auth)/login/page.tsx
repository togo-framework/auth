"use client";

import { useState } from "react";
import { auth } from "@/lib/auth";
import { AuthCard, Field, Submit, ErrorText } from "@/components/auth-card";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await auth.login(email, password);
      window.location.href = "/dashboard";
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Welcome back"
      subtitle="Sign in to your account"
      footer={
        <>
          No account? <a href="/register" className="font-medium text-slate-900 underline dark:text-white">Create one</a>
          <br />
          <a href="/reset" className="text-slate-500 underline">Forgot password?</a>
        </>
      }
    >
      <form onSubmit={submit}>
        <ErrorText>{err}</ErrorText>
        <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <Field label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <Submit disabled={busy}>{busy ? "Signing in…" : "Sign in"}</Submit>
      </form>
    </AuthCard>
  );
}
