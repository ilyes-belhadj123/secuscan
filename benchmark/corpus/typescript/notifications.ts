// Corpus de benchmark SecuScan — code volontairement vulnérable (ne pas déployer)

export function showBanner(root: HTMLElement): void {
  const params = new URLSearchParams(window.location.search);
  root.innerHTML = `<div class="banner">${params.get("message")}</div>`;
}

export function printReceipt(customer: string): void {
  document.write("<p>Reçu pour " + customer + "</p>");
}

export function scheduleRefresh(widgetId: string): void {
  setTimeout("refreshWidget('" + widgetId + "')", 1000);
}

export function renderComment(el: HTMLElement, html: string): void {
  el.insertAdjacentHTML("beforeend", html);
}
