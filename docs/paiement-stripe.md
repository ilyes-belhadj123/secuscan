# Paiement avec Stripe (SS-20)

Sans configuration, SecuScan reste en **mode démo** (changement d'offre immédiat, facture pro
forma). Avec les variables ci-dessous, les offres Pro et Business deviennent de vrais abonnements
mensuels facturés **par membre**.

## Ce qui se passe pour le client

| Action du propriétaire | Effet |
|---|---|
| Free → Pro ou Business | Page de paiement Stripe (carte bancaire). L'offre est activée à la confirmation de Stripe, quelques secondes après. |
| Pro ↔ Business | Changement de tarif immédiat, au prorata, sans repasser par le paiement |
| Retour à Free | Abonnement résilié, offre Free appliquée |
| Ajout ou départ d'un membre | Le nombre de sièges facturés suit, au prorata |
| « Gérer le paiement et les factures » | Portail client Stripe : carte, factures PDF, résiliation |

Les numéros de carte ne passent jamais par SecuScan. Les factures sont émises par Stripe.

## 1. Préparer Stripe (mode test d'abord)

1. Créez un compte sur stripe.com et restez en **mode test** (interrupteur en haut du tableau de bord).
2. **Catalogue de produits** → créez un produit « SecuScan Pro » avec un tarif **récurrent mensuel**,
   **par unité** (29 € HT), puis « SecuScan Business » (79 € HT). Notez les deux identifiants de
   tarif (`price_…`).
3. **Développeurs → Webhooks** → ajoutez le point de terminaison
   `https://VOTRE-DOMAINE/api/billing/stripe/webhook` avec les événements :
   `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`,
   `invoice.payment_failed`. Notez le secret de signature (`whsec_…`).
4. **Paramètres → Portail client** : activez le portail (mise à jour de la carte, factures, résiliation).

## 2. Variables

À placer dans `secuscan.env` (serveur) ou `.env` (poste local), jamais dans le code :

| Variable | Valeur |
|---|---|
| `SECUSCAN_STRIPE_SECRET_KEY` | Clé secrète (`sk_test_…` en test, `sk_live_…` en production) |
| `SECUSCAN_STRIPE_WEBHOOK_SECRET` | Secret de signature du webhook (`whsec_…`) |
| `SECUSCAN_STRIPE_PRICE_PRO` | Identifiant du tarif Pro (`price_…`) |
| `SECUSCAN_STRIPE_PRICE_BUSINESS` | Identifiant du tarif Business (`price_…`) |

`SECUSCAN_PUBLIC_URL` doit être l'adresse réelle du site : Stripe y renvoie le client après paiement.
Gardez `SECUSCAN_PRICE_PRO_EUR` et `SECUSCAN_PRICE_BUSINESS_EUR` alignés sur les tarifs Stripe : ils
servent à l'affichage et à l'estimation mensuelle.

## 3. Tester en local

Avec la [CLI Stripe](https://docs.stripe.com/stripe-cli), qui relaie les webhooks vers le poste :

```bash
stripe listen --forward-to http://127.0.0.1:8001/api/billing/stripe/webhook
# affiche un secret whsec_… à mettre dans SECUSCAN_STRIPE_WEBHOOK_SECRET, puis redémarrer l'API
```

Payez avec la carte de test `4242 4242 4242 4242` (date future, n'importe quel code).

## Sécurité

- Webhook : signature `Stripe-Signature` vérifiée (HMAC-SHA256), événement de plus de 5 minutes
  refusé (rejeu), chaque événement traité une seule fois.
- L'offre n'est jamais activée par le retour du navigateur (`?paiement=ok`, falsifiable), uniquement
  par l'événement signé.
- Si un paiement arrive alors que l'usage ne tient plus dans l'offre (membres ajoutés entre-temps),
  le changement est refusé et tracé dans le journal d'audit pour régularisation.
