import { createFileRoute } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { fetchSetupStatus, submitFirstRunSetup } from "@/functions/setup.functions";
import { firstRunSetupSchema } from "@/lib/validation";

// First-run setup. Every field starts EMPTY on purpose: the application does not
// decide the business name, time zone, cut-off, commission or notification provider.
// This page is only a convenience - the server re-validates everything and the
// database permanently closes setup after the first success.

export const Route = createFileRoute("/setup")({
  head: () => ({ meta: [{ title: "First-run setup" }, { name: "robots", content: "noindex" }] }),
  loader: () => fetchSetupStatus(),
  component: SetupPage,
});

type Fields = Record<string, string>;
const EMPTY: Fields = {
  setupToken: "",
  adminName: "",
  adminEmail: "",
  adminPassword: "",
  businessName: "",
  timezone: "",
  currency: "",
  cutoff: "",
  cartMinutes: "",
  lowStock: "",
  availabilityMinutes: "",
  hideAfterMinutes: "",
  rateBps: "",
  rounding: "",
  maxFailed: "",
  lockSeconds: "",
  ipAttempts: "",
  ipWindow: "",
  codeAttempts: "",
  codeWindow: "",
  secretMinLength: "",
};

const toInt = (v: string) => (v.trim() === "" ? Number.NaN : Number(v));

function SetupPage() {
  const status = Route.useLoaderData();
  const [f, setF] = useState<Fields>(EMPTY);
  const [hideOos, setHideOos] = useState<"" | "yes" | "no">("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const set = (k: string) => (e: { target: { value: string } }) =>
    setF((p) => ({ ...p, [k]: e.target.value }));

  if (status.setup_completed || done) {
    return (
      <Shell title={done ? "Setup complete" : "Setup already completed"}>
        <p className="text-sm text-muted-foreground">
          {done
            ? "The administrator account and business configuration have been saved. Sign-in screens are delivered in a later phase."
            : "This installation has already been configured. First-run setup cannot be run again."}
        </p>
      </Shell>
    );
  }

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const parsed = firstRunSetupSchema.safeParse({
      setupToken: f["setupToken"],
      admin: { displayName: f["adminName"], email: f["adminEmail"], password: f["adminPassword"] },
      settings: {
        business_name: f["businessName"],
        timezone: f["timezone"],
        currency_code: (f["currency"] ?? "").toUpperCase(),
        business_day_cutoff: f["cutoff"],
        cart_duration_minutes: toInt(f["cartMinutes"] ?? ""),
        low_stock_default_threshold: toInt(f["lowStock"] ?? ""),
        availability_check_minutes: toInt(f["availabilityMinutes"] ?? ""),
        hide_out_of_stock_enabled: hideOos === "yes",
        hide_out_of_stock_after_minutes: toInt(f["hideAfterMinutes"] ?? ""),
        login_max_failed_attempts: toInt(f["maxFailed"] ?? ""),
        login_lock_seconds: toInt(f["lockSeconds"] ?? ""),
        rate_limit_login_ip_attempts: toInt(f["ipAttempts"] ?? ""),
        rate_limit_login_ip_window_seconds: toInt(f["ipWindow"] ?? ""),
        rate_limit_login_code_attempts: toInt(f["codeAttempts"] ?? ""),
        rate_limit_login_code_window_seconds: toInt(f["codeWindow"] ?? ""),
        secret_code_min_length: toInt(f["secretMinLength"] ?? ""),
      },
      commission: { rateBps: toInt(f["rateBps"] ?? ""), rounding: f["rounding"] },
      notificationChannels: [],
    });
    if (!parsed.success || hideOos === "") {
      const first = parsed.success ? undefined : parsed.error.issues[0];
      setError(
        first
          ? `${first.path.join(".")}: ${first.message}`
          : "Choose whether out-of-stock products are hidden.",
      );
      return;
    }
    setBusy(true);
    try {
      await submitFirstRunSetup({ data: parsed.data });
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed.");
    } finally {
      setBusy(false);
    }
  };

  const timeZones =
    typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : [];

  return (
    <Shell title="First-run setup">
      <form onSubmit={onSubmit} className="space-y-6" autoComplete="off" noValidate>
        <Section title="Authorisation">
          <Field label="Setup token (provided by whoever deployed this installation)">
            <Input
              type="password"
              value={f["setupToken"]}
              onChange={set("setupToken")}
              autoComplete="off"
            />
          </Field>
        </Section>
        <Section title="First administrator">
          <Field label="Display name">
            <Input value={f["adminName"]} onChange={set("adminName")} />
          </Field>
          <Field label="Email">
            <Input
              type="email"
              value={f["adminEmail"]}
              onChange={set("adminEmail")}
              autoComplete="off"
            />
          </Field>
          <Field label="Password (must satisfy the password policy of the authentication service)">
            <Input
              type="password"
              value={f["adminPassword"]}
              onChange={set("adminPassword")}
              autoComplete="new-password"
            />
          </Field>
        </Section>
        <Section title="Business">
          <Field label="Business name">
            <Input value={f["businessName"]} onChange={set("businessName")} />
          </Field>
          <Field label="Time zone (IANA name)">
            <Input list="tz-list" value={f["timezone"]} onChange={set("timezone")} />
            <datalist id="tz-list">
              {timeZones.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
          </Field>
          <Field label="Currency code (ISO 4217)">
            <Input value={f["currency"]} onChange={set("currency")} maxLength={3} />
          </Field>
          <Field label="Business-day cut-off time (HH:MM, 24-hour)">
            <Input value={f["cutoff"]} onChange={set("cutoff")} />
          </Field>
        </Section>
        <Section title="Operations">
          <Field label="Cart reservation duration (minutes)">
            <Input inputMode="numeric" value={f["cartMinutes"]} onChange={set("cartMinutes")} />
          </Field>
          <Field label="Default low-stock threshold">
            <Input inputMode="numeric" value={f["lowStock"]} onChange={set("lowStock")} />
          </Field>
          <Field label="Availability check interval (minutes)">
            <Input
              inputMode="numeric"
              value={f["availabilityMinutes"]}
              onChange={set("availabilityMinutes")}
            />
          </Field>
          <Field label="Hide out-of-stock products?">
            <select
              className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
              value={hideOos}
              onChange={(e) => setHideOos(e.target.value as "" | "yes" | "no")}
            >
              <option value="">Choose…</option>
              <option value="yes">Yes</option>
              <option value="no">No</option>
            </select>
          </Field>
          <Field label="Hide after out of stock for (minutes; 0 if not applicable)">
            <Input
              inputMode="numeric"
              value={f["hideAfterMinutes"]}
              onChange={set("hideAfterMinutes")}
            />
          </Field>
        </Section>
        <Section title="Sign-in security policy (owner decision, no defaults)">
          <Field label="Failed Secret Access Code attempts before the account is locked">
            <Input inputMode="numeric" value={f["maxFailed"]} onChange={set("maxFailed")} />
          </Field>
          <Field label="Lock duration (seconds)">
            <Input inputMode="numeric" value={f["lockSeconds"]} onChange={set("lockSeconds")} />
          </Field>
          <Field label="Quick-login attempts allowed per IP address per window">
            <Input inputMode="numeric" value={f["ipAttempts"]} onChange={set("ipAttempts")} />
          </Field>
          <Field label="…window length for the per-IP limit (seconds)">
            <Input inputMode="numeric" value={f["ipWindow"]} onChange={set("ipWindow")} />
          </Field>
          <Field label="Quick-login attempts allowed per Client Code per window">
            <Input inputMode="numeric" value={f["codeAttempts"]} onChange={set("codeAttempts")} />
          </Field>
          <Field label="…window length for the per-Client-Code limit (seconds)">
            <Input inputMode="numeric" value={f["codeWindow"]} onChange={set("codeWindow")} />
          </Field>
          <Field label="Minimum Secret Access Code length (characters)">
            <Input
              inputMode="numeric"
              value={f["secretMinLength"]}
              onChange={set("secretMinLength")}
            />
          </Field>
        </Section>
        <Section title="Commission">
          <Field label="Commission rate in basis points (100 bps = 1%)">
            <Input inputMode="numeric" value={f["rateBps"]} onChange={set("rateBps")} />
          </Field>
          <Field label="Rounding mode">
            <select
              className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
              value={f["rounding"]}
              onChange={set("rounding")}
            >
              <option value="">Choose…</option>
              <option value="half_up">Half up</option>
              <option value="half_even">Half even (banker's)</option>
              <option value="down">Always down</option>
              <option value="up">Always up</option>
            </select>
          </Field>
        </Section>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <Button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Complete setup"}
        </Button>
      </form>
    </Shell>
  );
}

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="mx-auto min-h-screen max-w-xl px-4 py-10">
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">{title}</h1>
      {children}
    </main>
  );
}
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <fieldset className="space-y-3 rounded-lg border p-4">
      <legend className="px-1 text-sm font-medium">{title}</legend>
      {children}
    </fieldset>
  );
}
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
    </div>
  );
}
