import axios from "axios";
import type { LookupAuthQuotas, LookupResponse } from "../types";

export const LOOKUP_DATA_PATH = "/v0/resource/plugins/cpa-key-policy/lookup/data";
export const LOOKUP_QUOTA_REFRESH_PATH = "/v0/resource/plugins/cpa-key-policy/lookup/quota-refresh";

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

export async function fetchLookupQuota(secret: string, accountRef: string): Promise<{ auth_quotas: LookupAuthQuotas }> {
  const value = secret.trim();
  const ref = accountRef.trim();
  const { data } = await axios.get<{ auth_quotas: LookupAuthQuotas }>(LOOKUP_QUOTA_REFRESH_PATH, {
    timeout: 30_000,
    headers: {
      Authorization: `Bearer ${value}`,
      "X-Key-Policy-Quota-Refresh": "1",
      "X-Key-Policy-Auth-Ref": ref,
      "Content-Type": "application/json",
    },
  });
  return data;
}
