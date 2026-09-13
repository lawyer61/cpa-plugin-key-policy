export function formatUSD(value: number): string {
  const amount = Number.isFinite(value) ? value : 0;
  if (amount === 0) return "$0.00";

  const absolute = Math.abs(amount);
  const sign = amount < 0 ? "-" : "";
  if (absolute < 0.000001) return `${sign}<$0.000001`;
  if (absolute < 0.01) {
    const precise = absolute.toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
    return `${sign}$${precise}`;
  }
  return `${sign}$${absolute.toFixed(2)}`;
}
