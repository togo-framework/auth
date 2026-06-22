"use client";

import { useState } from "react";
import { auth } from "@/lib/auth";
import { AuthCard, Field, Submit, ErrorText } from "@/components/auth-card";

export default function ResetPage() {
  const [step, setStep] = useState<"request" | "verify">("request");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function request(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await auth.requestOtp(email, "reset");
      setMsg("If that email exists, a code is on its way.");
      setStep("verify");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await auth.verifyOtp(email, code, "reset");
      setMsg("Code verified — you can now set a new password from your profile.");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Reset password"
      subtitle={step === "request" ? "We'll email you a one-time code" : "Enter the 6-digit code"}
      footer={<a href="/login" className="text-slate-500 underline">Back to sign in</a>}
    >
      {step === "request" ? (
        <form onSubmit={request}>
          <ErrorText>{err}</ErrorText>
          <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <Submit disabled={busy}>{busy ? "Sending…" : "Send code"}</Submit>
        </form>
      ) : (
        <form onSubmit={verify}>
          <ErrorText>{err}</ErrorText>
          {msg && <p className="mb-4 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:bg-emerald-950/40">{msg}</p>}
          <Field label="Code" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} required />
          <Submit disabled={busy}>{busy ? "Verifying…" : "Verify code"}</Submit>
        </form>
      )}
    </AuthCard>
  );
}
