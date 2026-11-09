# SUGARMAMI GABON — version de test sécurisée

## Ce que cette version permet
- Créer un compte de test et se connecter.
- Utiliser une session protégée et consulter l'espace membre.
- Se connecter à l'administration et consulter la liste des comptes de test.
- Tester la navigation sur téléphone Android.

## Ce qui est volontairement désactivé
- Tous les paiements Moov Money et Airtel Money.
- Tous les formulaires de justificatifs et téléversements de fichiers.
- Toute approbation ou activation VIP payante.
- Tous les liens d'invitation WhatsApp et Telegram.
- Aucun argent ne doit être envoyé pendant cette phase.

## Configuration locale
Prérequis : Node.js 20 ou plus.

1. Copier `.env.example` vers `.env`.
2. Créer une valeur aléatoire longue pour `SESSION_SECRET` (au moins 32 caractères).
3. Choisir une adresse e-mail administrateur et un mot de passe unique de 16 caractères minimum.
4. Exécuter `npm install`.
5. Exécuter `npm start`.
6. Ouvrir `http://localhost:3000` ; administration : `/admin`.

Ne jamais publier `.env`, `data/`, `private_uploads/` ou une base SQLite sur GitHub.

## Hébergement gratuit
Cette version est uniquement destinée à un test sans vrais clients ni vrais paiements. Les données SQLite locales peuvent disparaître sur un hébergeur gratuit au redémarrage, au redéploiement ou après une période d'inactivité. Ne collectez donc pas de données réelles et n'utilisez pas cette version comme service commercial.

## Avant toute mise en production
Il faudra notamment :
- un hébergement et une base de données persistants, avec sauvegardes vérifiées ;
- un stockage privé durable pour les justificatifs, avec contrôle strict des accès ;
- une politique de confidentialité, des conditions d'utilisation et une durée de conservation ;
- un audit de sécurité indépendant, tests de restauration et protections anti-abus ;
- vérifier la légalité et les conditions des opérateurs de paiement ;
- renouveler les liens d'invitation VIP et ne les exposer qu'après autorisation ;
- valider les règles applicables à l'activité et à la protection des données au Gabon.

Cette version ne constitue pas une certification de sécurité ni un avis juridique.
