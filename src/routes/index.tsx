import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import CCLogo from "@/assets/cc-mark.png";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Canna-Connec — Launching Soon" },
      {
        name: "description",
        content:
          "Canna-Connec is launching soon. Something amazing is being built — get notified when we go live.",
      },
      { property: "og:title", content: "Canna-Connec — Launching Soon" },
      {
        property: "og:description",
        content:
          "We're building something amazing. Our new platform launches Friday, 2 October. Get notified.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "twitter:title", content: "Canna-Connec — Launching Soon" },
      {
        name: "twitter:description",
        content:
          "We're building something amazing. Our new platform launches Friday, 2 October. Get notified.",
      },
    ],
  }),
  component: Index,
});

const LAUNCH_DATE = new Date("2026-10-02T00:00:00");

function useCountdown(target: Date) {
  const calc = () => {
    const diff = Math.max(0, target.getTime() - Date.now());
    return {
      days: Math.floor(diff / 86_400_000),
      hours: Math.floor((diff / 3_600_000) % 24),
      minutes: Math.floor((diff / 60_000) % 60),
      seconds: Math.floor((diff / 1_000) % 60),
    };
  };

  const [time, setTime] = useState(calc);

  useEffect(() => {
    const id = setInterval(() => setTime(calc()), 1000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return time;
}

function CountdownUnit({ value, label }: { value: number; label: string }) {
  return (
    <div className="countdown-card flex flex-col items-center justify-center rounded-2xl px-3 py-5 sm:px-6 sm:py-7 min-w-[4.5rem] sm:min-w-[7rem]">
      <span className="countdown-value text-foreground">
        {String(value).padStart(2, "0")}
      </span>
      <span className="mt-1.5 text-[0.65rem] sm:text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </span>
    </div>
  );
}

function Index() {
  const { days, hours, minutes, seconds } = useCountdown(LAUNCH_DATE);
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setStatus("error");
      return;
    }
    setStatus("success");
  };

  return (
    <div className="relative min-h-screen overflow-hidden hero-glow">
      <div className="pointer-events-none absolute inset-0 grid-texture" />

      {/* Ambient floating orb */}
      <div className="pointer-events-none absolute left-1/2 top-[38%] -translate-x-1/2 float-slow">
        <div className="h-64 w-64 sm:h-96 sm:w-96 rounded-full bg-primary/10 blur-3xl" />
      </div>

      <div className="relative z-10 flex min-h-screen flex-col">
        {/* Header */}
        <header className="w-full">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-6 sm:py-8">
            <div className="flex items-center gap-2.5">
              <img
                src={CCLogo}
                alt="Canna-Connec logo"
                className="h-8 w-8 rounded-lg"
              />
              <span className="text-display-sm font-semibold text-foreground">
                Canna<span className="text-primary">-</span>Connec
              </span>
            </div>
            <div className="flex items-center gap-2 rounded-full border border-border bg-card/60 px-3.5 py-1.5 backdrop-blur-sm">
              <span className="live-dot h-1.5 w-1.5 rounded-full bg-primary" />
              <span className="text-xs font-medium tracking-wide text-muted-foreground">
                In development
              </span>
            </div>
          </div>
        </header>

        {/* Hero */}
        <main className="flex flex-1 flex-col items-center justify-center px-6 pb-16 pt-4 text-center">
          <span className="animate-fade-in inline-flex items-center rounded-full border border-primary/25 bg-primary/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-primary sm:text-sm">
            Under construction
          </span>

          <h1 className="text-display-xl animate-fade-in mt-6 max-w-3xl font-bold text-foreground">
            We're building something{" "}
            <span className="bg-gradient-to-r from-primary to-glow bg-clip-text text-transparent">
              amazing
            </span>
          </h1>

          <p className="animate-fade-in mt-5 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            Our new platform is launching soon — a smarter way to connect.
            The countdown has started, and we can't wait to show you what's
            next.
          </p>

          {/* Countdown */}
          <div className="animate-fade-in mt-12 flex items-center justify-center gap-2.5 sm:gap-4">
            <CountdownUnit value={days} label="Days" />
            <span className="text-display-lg -mt-8 font-light text-muted-foreground/50">
              :
            </span>
            <CountdownUnit value={hours} label="Hours" />
            <span className="text-display-lg -mt-8 font-light text-muted-foreground/50">
              :
            </span>
            <CountdownUnit value={minutes} label="Minutes" />
            <span className="text-display-lg -mt-8 font-light text-muted-foreground/50">
              :
            </span>
            <CountdownUnit value={seconds} label="Seconds" />
          </div>

          <p className="mt-5 text-sm text-muted-foreground/80">
            Launching Friday, 2 October
          </p>

          {/* Newsletter form */}
          <div className="animate-fade-in mt-12 w-full max-w-md">
            {status === "success" ? (
              <div className="flex items-center justify-center gap-3 rounded-2xl border border-primary/30 bg-primary/10 px-6 py-4">
                <svg
                  className="h-5 w-5 shrink-0 text-primary"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M4.5 12.75l6 6 9-13.5"
                  />
                </svg>
                <p className="text-sm font-medium text-foreground">
                  You're on the list — we'll let you know the moment we launch.
                </p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} noValidate>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:rounded-2xl sm:border sm:border-border sm:bg-card/70 sm:p-2 sm:backdrop-blur-sm">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (status === "error") setStatus("idle");
                    }}
                    placeholder="Enter your email"
                    aria-label="Email address"
                    className="w-full flex-1 rounded-xl border border-border bg-card/70 px-4 py-3.5 text-sm text-foreground placeholder:text-muted-foreground/60 outline-none transition-colors focus:border-primary/50 focus:ring-2 focus:ring-primary/30 sm:border-0 sm:bg-transparent sm:py-2.5"
                  />
                  <button
                    type="submit"
                    className="btn-glow inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-primary px-6 py-3.5 text-sm font-semibold text-primary-foreground sm:py-2.5"
                  >
                    Get Notified
                    <svg
                      className="h-4 w-4"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={2}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M13.5 4.5L21 12l-7.5 7.5M21 12H3"
                      />
                    </svg>
                  </button>
                </div>
                {status === "error" && (
                  <p className="mt-2.5 text-left text-sm text-destructive">
                    Please enter a valid email address.
                  </p>
                )}
                <p className="mt-4 text-xs text-muted-foreground/60">
                  No spam — just one email when we go live.
                </p>
              </form>
            )}
          </div>
        </main>

        {/* Footer */}
        <footer className="w-full pb-8">
          <div className="mx-auto max-w-5xl px-6">
            <div className="flex flex-col items-center gap-2 border-t border-border/60 pt-6 text-center">
              <span className="text-sm font-medium text-foreground/80">
                Canna-Connec
              </span>
              <span className="text-xs text-muted-foreground/60">
                © 2026 Canna-Connec. All rights reserved.
              </span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
