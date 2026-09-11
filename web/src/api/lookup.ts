import axios from "axios";
import type { LookupResponse } from "../types";

export const LOOKUP_DATA_PATH = "/v0/resource/plugins/cpa-key-policy/lookup/data";

// Public lookup requests intentionally use a short-lived, per-call axios
// request. No management session or browser storage is involved; the secret
// exists only in the Lookup component's React state.
export async function fetchLookupData(secret: string): Promise<LookupResponse> {
  const value = secret.trim();
  const { data } = await axios.get<LookupResponse>(LOOKUP_DATA_PATH, {
    headers: {
      Authorization: `Bearer ${value}`,
      "Content-Type": "application/json",
    },
  });
  return data;
}

export function lookupStatus(error: unknown): number | undefined {
  const response = (error as { response?: { status?: unknown } } | null)?.response;
  return typeof response?.status === "number" ? response.status : undefined;
}
