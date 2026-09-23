// Corpus de benchmark SecuScan — code sûr (aucune alerte attendue)

declare function refreshWidget(id: string): void;

export function showBanner(root: HTMLElement): void {
  const params = new URLSearchParams(window.location.search);
  const banner = document.createElement("div");
  banner.className = "banner";
  banner.textContent = params.get("message") ?? "";
  root.appendChild(banner);
}

export function scheduleRefresh(widgetId: string): void {
  setTimeout(() => refreshWidget(widgetId), 1000);
}
