/** Lien externe affiché tel quel seulement s'il est en https (pas de « javascript: » venu d'une source externe). */
export function safeHref(url: string | undefined | null): string | undefined {
  try {
    return url && new URL(url).protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}

/** Copie dans le presse-papiers, y compris hors HTTPS (adresse IP locale) où navigator.clipboard est absent. */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("Copie impossible : sélectionnez le texte et copiez-le manuellement.");
}
