// The consent page of the connector. Supabase Auth (OAuth 2.1 server) sends the user here with
// ?authorization_id=…; the user signs in, or creates an account, with an e-mail address and a password
// (the only way: D25), then approves or denies.
//
// Anyone can register an OAuth client with Supabase Auth (dynamic registration is open, and must be for
// Claude), with any name and any https return address. So this page only lets through requests that
// return to Claude (step 1 review, finding 1, list decided by the brain session): the hosted Claude apps
// and Claude Code on the user's own computer. Every other request is refused, without going there.
(function () {
  "use strict";
  if (!window.CryptoApp) return; // framed: common.js stopped everything
  var app = window.CryptoApp;
  var sb = app.client;
  var $ = app.$;

  // Supabase Auth makes it with SecureAlphanumeric(32): base32, lower case. Checked before it goes into a URL
  // (review, finding 6).
  var AUTHORIZATION_ID = /^[A-Za-z0-9]{32}$/;
  var APPROVE_DELAY_MS = 1500; // the "Autoriser" button wakes up after this, never under a hurried click

  var authorizationId = new URLSearchParams(window.location.search).get("authorization_id");

  /** The return addresses Claude documents: its hosted apps, and Claude Code's loopback on any port. */
  function isClaudeRedirect(uri) {
    var u;
    try {
      u = new URL(uri);
    } catch (e) {
      return false;
    }
    if (u.username || u.password || u.search || u.hash) return false;
    if (u.protocol === "https:" && (u.hostname === "claude.ai" || u.hostname === "claude.com")) {
      return u.port === "" && u.pathname === "/api/mcp/auth_callback";
    }
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
      return u.pathname === "/callback";
    }
    return false;
  }

  function isLoopback(uri) {
    try {
      var host = new URL(uri).hostname;
      return host === "localhost" || host === "127.0.0.1";
    } catch (e) {
      return false;
    }
  }

  var SCOPE_LABELS = {
    openid: "ton identité",
    email: "ton adresse e-mail",
    profile: "ton nom",
    phone: "ton numéro de téléphone",
    offline_access: "rester connecté sans te redemander ton mot de passe",
  };

  function describeScopes(scope) {
    var parts = (scope || "").split(" ").filter(Boolean);
    if (parts.length === 0) return "ton espace " + window.CRYPTO_APP_CONFIG.appName;
    return parts
      .map(function (s) {
        return SCOPE_LABELS[s] || s;
      })
      .join(", ");
  }

  var details = null; // the authorization request being shown

  async function showConsent() {
    var res = await sb.auth.oauth.getAuthorizationDetails(authorizationId);
    if (res.error) {
      app.fail(
        "Cette demande d'autorisation n'est plus valable (" +
          res.error.message +
          "). Retourne dans Claude et relance la connexion du connecteur.",
      );
      return;
    }
    var d = res.data;
    if (!("authorization_id" in d)) {
      // Already approved earlier for these scopes. Supabase sends the user back only to an address it
      // registered; still, never follow one that is not Claude's.
      if (isClaudeRedirect(d.redirect_url.split("?")[0])) {
        window.location.assign(d.redirect_url);
      } else {
        app.fail("Cette demande ne vient pas de Claude : elle est refusée.");
      }
      return;
    }
    if (!isClaudeRedirect(d.redirect_uri)) {
      // Close the request on the server, but never go to the address it gives.
      await sb.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
      app.fail(
        "Cette demande d'accès ne vient pas de Claude : elle est refusée. Si tu n'as rien demandé, ignore-la ; " +
          "ton espace n'a pas été ouvert.",
      );
      return;
    }
    details = d;
    $("client-name").textContent = (d.client && d.client.name) || "Une application";
    $("account").textContent = (d.user && d.user.email) || "?";
    $("redirect-host").textContent = new URL(d.redirect_uri).host;
    $("loopback-warning").hidden = !isLoopback(d.redirect_uri);
    $("scopes").textContent = describeScopes(d.scope);
    app.busy($("approve"), true);
    app.show("consent");
    window.setTimeout(function () {
      app.busy($("approve"), false);
    }, APPROVE_DELAY_MS);
  }

  async function decide(approve) {
    var button = approve ? $("approve") : $("deny");
    app.busy($("approve"), true);
    app.busy($("deny"), true);
    var call = approve ? sb.auth.oauth.approveAuthorization : sb.auth.oauth.denyAuthorization;
    var res = await call.call(sb.auth.oauth, authorizationId, { skipBrowserRedirect: true });
    if (res.error) {
      app.busy($("approve"), false);
      app.busy($("deny"), false);
      app.fail("La réponse n'a pas pu être enregistrée : " + app.explain(res.error));
      return;
    }
    if (!isClaudeRedirect(res.data.redirect_url.split("?")[0])) {
      app.fail("Réponse enregistrée, mais l'adresse de retour n'est pas celle de Claude : retourne dans Claude.");
      return;
    }
    $("done-text").textContent = approve ? "C'est autorisé. Retour vers Claude…" : "Refusé. Retour vers Claude…";
    app.show("done");
    button.blur();
    window.location.assign(res.data.redirect_url);
  }

  function showError(sectionId, message) {
    var box = $(sectionId === "login" ? "login-error" : "sign-up-error");
    box.textContent = message;
    box.hidden = !message;
    app.show(sectionId);
  }

  async function signIn(event) {
    event.preventDefault();
    var button = $("sign-in");
    app.busy(button, true);
    var res = await sb.auth.signInWithPassword({
      email: $("email").value.trim(),
      password: $("password").value,
    });
    app.busy(button, false);
    $("password").value = "";
    if (res.error) {
      showError("login", app.explain(res.error));
      return;
    }
    await showConsent();
  }

  // Sign-ups are open (D22). No e-mail is ever sent (D25): the account is usable at once.
  async function signUp(event) {
    event.preventDefault();
    var button = $("sign-up-button");
    app.busy(button, true);
    var password = $("new-password").value;
    var refused = await app.checkNewPassword(password);
    if (refused) {
      app.busy(button, false);
      showError("sign-up", refused);
      return;
    }
    var res = await sb.auth.signUp({ email: $("new-email").value.trim(), password: password });
    app.busy(button, false);
    if (res.error) {
      showError("sign-up", app.explain(res.error));
      return;
    }
    if (!res.data.session) {
      showError("sign-up", "Le compte n'a pas pu être ouvert tout de suite : réessaie de te connecter.");
      return;
    }
    $("new-password").value = "";
    await showConsent();
  }

  // Supabase ties the request to the account that opened it: with another account, it has to start again
  // from Claude (review, finding 2). So: refuse this one, sign out of this page only, back to Claude.
  async function switchAccount() {
    app.busy($("switch"), true);
    var res = await sb.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
    await app.signOutHere();
    if (!res.error && details && isClaudeRedirect(res.data.redirect_url.split("?")[0])) {
      $("done-text").textContent =
        "Déconnecté. Retour vers Claude : relance la connexion du connecteur et connecte-toi avec le bon compte.";
      app.show("done");
      window.location.assign(res.data.redirect_url);
      return;
    }
    app.fail("Déconnecté. Retourne dans Claude et relance la connexion du connecteur avec le bon compte.");
  }

  async function main() {
    if (!authorizationId || !AUTHORIZATION_ID.test(authorizationId)) {
      app.fail(
        "Rien à autoriser ici. Cette page s'ouvre toute seule quand tu ajoutes le connecteur dans Claude.",
      );
      return;
    }
    var session = (await sb.auth.getSession()).data.session;
    if (!session) {
      showError("login", "");
      return;
    }
    await showConsent();
  }

  $("sign-in-form").addEventListener("submit", signIn);
  $("sign-up-form").addEventListener("submit", signUp);
  $("to-sign-up").addEventListener("click", function () {
    showError("sign-up", "");
    $("new-email").focus();
  });
  $("to-sign-in").addEventListener("click", function () {
    showError("login", "");
    $("email").focus();
  });
  $("approve").addEventListener("click", function () {
    decide(true);
  });
  $("deny").addEventListener("click", function () {
    decide(false);
  });
  $("switch").addEventListener("click", switchAccount);

  main().catch(function (e) {
    app.fail("Erreur inattendue : " + (e && e.message ? e.message : String(e)));
  });
})();
