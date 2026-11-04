// Home of the authorization site: which applications (Claude…) the user has authorized, a way to
// withdraw that access (as Supabase recommends for an OAuth 2.1 server), and changing one's password.
(function () {
  "use strict";
  if (!window.CryptoApp) return;
  var app = window.CryptoApp;
  var sb = app.client;
  var $ = app.$;

  function formatDate(iso) {
    try {
      return new Date(iso).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
    } catch (e) {
      return iso;
    }
  }

  async function revoke(clientId, button) {
    app.busy(button, true);
    var res = await sb.auth.oauth.revokeGrant({ clientId: clientId });
    if (res.error) {
      app.busy(button, false);
      app.fail("Le retrait n'a pas pu se faire : " + app.explain(res.error));
      return;
    }
    await render();
  }

  async function render() {
    var session = (await sb.auth.getSession()).data.session;
    if (!session) {
      app.show("signed-out");
      return;
    }
    $("account").textContent = session.user.email || session.user.id;
    $("password-username").value = session.user.email || ""; // lets password managers save the pair
    var res = await sb.auth.oauth.listGrants();
    if (res.error) {
      app.fail("La liste des accès n'a pas pu être lue : " + app.explain(res.error));
      return;
    }
    var list = $("grants");
    list.textContent = "";
    res.data.forEach(function (grant) {
      var item = document.createElement("li");
      var text = document.createElement("span");
      text.textContent =
        (grant.client.name || "Application sans nom") + " — autorisée le " + formatDate(grant.granted_at);
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = "Retirer l'accès";
      button.addEventListener("click", function () {
        revoke(grant.client.id, button);
      });
      item.appendChild(text);
      item.appendChild(button);
      list.appendChild(item);
    });
    $("grants-empty").hidden = res.data.length > 0;
    app.show("signed-in");
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
    $("login-error").textContent = res.error ? app.explain(res.error) : "";
    $("login-error").hidden = !res.error;
    if (!res.error) await render();
  }

  // Supabase Auth asks for the current password (security_update_password_require_current_password, set on
  // the project: review, finding 1d), and ends every other session of the account, Claude's included.
  async function savePassword(event) {
    event.preventDefault();
    var current = $("current-password");
    var input = $("new-password");
    var status = $("password-status");
    var button = $("save-password");
    app.busy(button, true);
    var refused = await app.checkNewPassword(input.value);
    if (refused) {
      app.busy(button, false);
      status.textContent = refused;
      return;
    }
    var res = await sb.auth.updateUser({ password: input.value, current_password: current.value });
    app.busy(button, false);
    current.value = "";
    input.value = "";
    status.textContent = res.error
      ? "Mot de passe non enregistré : " + app.explain(res.error)
      : "Mot de passe enregistré. Claude est déconnecté : reconnecte le connecteur dans Claude.";
  }

  $("sign-in-form").addEventListener("submit", signIn);
  $("password-form").addEventListener("submit", savePassword);

  $("signout").addEventListener("click", async function () {
    await app.signOutHere();
    app.show("signed-out");
  });

  render().catch(function (e) {
    app.fail("Erreur inattendue : " + (e && e.message ? e.message : String(e)));
  });
})();
