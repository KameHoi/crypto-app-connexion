# CRYPTO_APP — connexion et autorisation

La page où l'on se connecte à son espace CRYPTO_APP (adresse e-mail et mot de passe), ou où l'on crée son compte,
puis où l'on autorise Claude à s'y relier par le connecteur de l'app. Supabase Auth, en serveur OAuth 2.1, y envoie
l'utilisateur au moment où il ajoute le connecteur dans Claude. L'adresse sert seulement d'identifiant : aucun e-mail
n'est envoyé. Le mot de passe compte au moins 15 caractères et ne doit pas figurer dans les fuites connues (vérifié
par k-anonymat auprès de Have I Been Pwned : seuls 5 caractères de son empreinte SHA-1 quittent la page).

- Ce dépôt ne contient que cette page : aucun secret, aucune donnée personnelle. `config.js` ne porte que l'adresse
  publique de la base et sa clé publique (« publishable »), faites pour être livrées aux clients ; la base protège les
  données ligne par ligne.
- Il est publié par GitHub Pages. GitHub Pages n'est pas fait pour héberger un SaaS ou un site commercial : CRYPTO_APP
  est une app personnelle et non commerciale.
- Le code source vit dans un dépôt privé ; ce dépôt-ci en est une copie publiée, ne pas le modifier à la main.
