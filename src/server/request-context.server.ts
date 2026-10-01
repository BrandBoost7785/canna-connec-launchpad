import { getRequestHeader } from "@tanstack/react-start/server";

/**
 * Client IP for rate limiting. Only a header NAMED BY THE DEPLOYER (CLIENT_IP_HEADER,
 * e.g. `cf-connecting-ip` behind Cloudflare) is trusted, because any other header can
 * be forged by the caller. When unset, all callers share one "unknown" bucket: this is
 * safe (stricter) but can be exhausted by an attacker - configure the header.
 */
export function getClientIp(): string {
  const name = process.env["CLIENT_IP_HEADER"]?.trim().toLowerCase();
  if (!name) return "unknown";
  const raw = getRequestHeader(name);
  const first = raw?.split(",")[0]?.trim();
  if (!first || first.length > 64 || !/^[0-9a-fA-F:.]+$/.test(first)) return "unknown";
  return first;
}
