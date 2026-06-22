"use client";

import { useEffect, useState } from "react";
import { auth } from "@/lib/auth";

// Dashboard home (prism-inspired). Redirects to /login when unauthenticated.
export default function DashboardPage() {
  const [me, setMe] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auth.me().then((u) => {
      if (!u) {
        window.location.href = "/login";
        return;
      }
      setMe(u);
      setLoading(false);
    });
  }, []);

  if (loading) return <div className="p-8 text-slate-500">Loading…</div>;

  const cards = [
    { label: "Account", value: me.email },
    { label: "Roles", value: me.roles?.join(", ") || "user" },
    { label: "Permissions", value: String(me.permissions?.length ?? 0) },
  ];

  return (
    <div className="mx-auto max-w-5xl p-8">
      <header className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-slate-500">Welcome back, {me.email}</p>
        </div>
        <div className="flex gap-3 text-sm">
          <a href="/profile" className="rounded-lg border border-slate-300 px-3 py-1.5 dark:border-slate-700">Profile</a>
          <button
            onClick={async () => { await auth.logout(); window.location.href = "/login"; }}
            className="rounded-lg bg-slate-900 px-3 py-1.5 text-white dark:bg-white dark:text-slate-900"
          >
            Sign out
          </button>
        </div>
      </header>

      <div className="grid gap-4 sm:grid-cols-3">
        {cards.map((c) => (
          <div key={c.label} className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
            <p className="text-sm text-slate-500">{c.label}</p>
            <p className="mt-1 truncate text-lg font-medium">{c.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
