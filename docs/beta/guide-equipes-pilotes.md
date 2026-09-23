# Bienvenue dans la bêta de SecuScan

Merci de faire partie des équipes pilotes. SecuScan analyse la sécurité de votre code, explique
chaque faille en français et propose un correctif prêt à appliquer. Pendant ces quatre semaines,
votre avis compte plus que tout : il décidera de ce que nous améliorons en priorité.

## Démarrer en 10 minutes

1. **Créez votre organisation** avec le lien d'inscription reçu (votre e-mail professionnel).
2. **Invitez votre équipe** : menu « Équipe » → « Inviter un membre ». Chaque membre reçoit un lien.
3. **Lancez une première analyse**, au choix :
   - un dépôt GitHub / GitLab : bouton « Connecter GitHub », puis choix du dépôt et de la branche ;
   - une archive ZIP de votre code (supprimée juste après l'analyse) ;
   - un extrait de code collé.
4. **Ouvrez une alerte critique** : onglet « Comprendre » pour le risque, onglet « Corriger » pour le
   correctif, bouton « Copier le code corrigé ».

## Ce que nous vous demandons

- **Donner votre avis sur les correctifs** : sous chaque correctif, « Je l'ai appliqué », « Utile »
  ou « Pas utile », avec un commentaire si possible. C'est notre principal indicateur de qualité.
- **Relancer une analyse la semaine suivante**, après vos corrections : le tableau de bord montre
  alors les failles corrigées et l'évolution du score.
- **Répondre au questionnaire** (2 minutes) proposé dans l'application après 14 jours.
- **Ignorer les fausses alertes avec une justification** (« Ignorer cette alerte… ») plutôt que de
  les laisser de côté : cela nous aide à réduire le bruit.

## Confidentialité de votre code

- Le code est analysé sans jamais être exécuté, puis supprimé à la fin de l'analyse.
- Les secrets détectés (clés, mots de passe) ne sont ni stockés ni affichés en clair, ni envoyés à l'IA.
- Seuls des extraits ciblés (la fonction concernée) sont transmis à l'IA pour l'explication et le
  correctif ; ils ne servent pas à entraîner de modèle.
- Vos analyses sont invisibles des autres organisations de la bêta.

## Limites connues de la version bêta

- Langages : Python, JavaScript / TypeScript, PHP, Java.
- Les correctifs sont des **suggestions** : relisez-les et testez-les avant de les intégrer.
- La vérification automatique des correctifs porte sur la syntaxe, pas sur la compilation ni la logique.

## Contact

Une question, un bug, une idée : répondez simplement à l'e-mail d'invitation à la bêta.
