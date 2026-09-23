// Acme Shop — affichage des avis clients (démonstration volontairement vulnérable)

interface Review {
  author: string;
  rating: number;
  comment: string;
}

export function renderReviews(container: HTMLElement, reviews: Review[]): void {
  container.innerHTML = reviews
    .map((r) => `<div class="review"><strong>${r.author}</strong> (${r.rating}/5)<p>${r.comment}</p></div>`)
    .join("");
}

export function generateResetToken(): string {
  return Math.random().toString(36).substring(2);
}

export function showWelcome(): void {
  const params = new URLSearchParams(window.location.search);
  document.write("<h2>Bienvenue " + params.get("name") + "</h2>");
}
