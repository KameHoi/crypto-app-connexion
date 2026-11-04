// Shared by the pages: the Supabase client, frame protection, the password rule, small DOM helpers.
(function () {
  "use strict";

  // Never run inside a frame: a framed consent page could be used to trick a click.
  if (window.top !== window.self) {
    document.documentElement.innerHTML = "";
    window.top.location.href = window.location.href;
    return;
  }

  var cfg = window.CRYPTO_APP_CONFIG;
  var client = window.supabase.createClient(cfg.supabaseUrl, cfg.publishableKey, {
    auth: {
      flowType: "pkce",
      detectSessionInUrl: false, // e-mail and password only (D25): nothing comes back in the address
      // The page's own session lives as long as the tab (step 1 review, finding 1e): it is only needed for the
      // time of an authorization or a password change. Claude keeps its own tokens, not this session.
      storage: window.sessionStorage,
      persistSession: true,
      autoRefreshToken: true,
    },
  });

  function $(id) {
    return document.getElementById(id);
  }

  /** Shows one section of the page and hides the others. */
  function show(id) {
    var sections = document.querySelectorAll("main > section");
    for (var i = 0; i < sections.length; i++) {
      sections[i].hidden = sections[i].id !== id;
    }
  }

  function fail(message) {
    $("error-text").textContent = message;
    show("error");
  }

  function busy(button, isBusy) {
    button.disabled = isBusy;
    button.setAttribute("aria-busy", isBusy ? "true" : "false");
  }

  /** Signs out of this page only. The default ("global") would also end Claude's sessions (review, finding 2). */
  function signOutHere() {
    return client.auth.signOut({ scope: "local" });
  }

  // The password rule (D25), from NIST SP 800-63B-4, 3.1.1.2: a password used alone is at least
  // 15 characters, no composition rule, and is refused if it is a known compromised password.
  // Supabase enforces the length; its leaked-password check needs a paid plan, so that check is made
  // here, by k-anonymity: only the first 5 characters of the password's SHA-1 leave the page.
  var MIN_LENGTH = 15;
  var MAX_BYTES = 72; // Supabase Auth (bcrypt) limit, counted in UTF-8 bytes (review, finding 7)

  // Supabase Auth error codes, in the user's words. Anything else is shown as Supabase wrote it.
  var ERRORS = {
    invalid_credentials: "E-mail ou mot de passe incorrect.",
    user_already_exists: "Un compte existe déjà avec cette adresse : connecte-toi.",
    email_exists: "Un compte existe déjà avec cette adresse : connecte-toi.",
    email_address_invalid: "Cette adresse e-mail n'est pas valide.",
    weak_password: "Mot de passe refusé : au moins " + MIN_LENGTH + " caractères.",
    same_password: "C'est déjà ton mot de passe.",
    current_password_required: "Entre ton mot de passe actuel.",
    current_password_invalid: "Ton mot de passe actuel est incorrect.",
    signup_disabled: "Les inscriptions sont fermées.",
    user_banned: "Ce compte est bloqué.",
    over_request_rate_limit: "Trop d'essais : attends quelques minutes.",
  };
  var TOO_LONG =
    "Mot de passe trop long : " + MAX_BYTES + " octets au plus (une lettre accentuée en compte deux, un emoji quatre).";

  function explain(error) {
    if (!error) return "";
    if (error.code && ERRORS[error.code]) return ERRORS[error.code];
    var message = error.message || "";
    if (/invalid login credentials/i.test(message)) return ERRORS.invalid_credentials;
    if (/already registered/i.test(message)) return ERRORS.user_already_exists;
    if (/password.*longer than/i.test(message)) return TOO_LONG;
    return message || String(error);
  }

  async function isCompromised(password) {
    var digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
    var hex = Array.from(new Uint8Array(digest))
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("")
      .toUpperCase();
    var res = await fetch("https://api.pwnedpasswords.com/range/" + hex.slice(0, 5), {
      headers: { "Add-Padding": "true" },
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    var suffix = hex.slice(5);
    return (await res.text()).split("\n").some(function (line) {
      var parts = line.trim().split(":");
      return parts[0] === suffix && Number(parts[1]) > 0;
    });
  }

  /** Returns why a new password is refused, or "" when it can be used. */
  async function checkNewPassword(password) {
    if (password.length < MIN_LENGTH) {
      return "Au moins " + MIN_LENGTH + " caractères : une phrase de quelques mots convient.";
    }
    if (new TextEncoder().encode(password).length > MAX_BYTES) return TOO_LONG;
    try {
      if (await isCompromised(password)) {
        return "Ce mot de passe figure dans des fuites de données connues : choisis-en un autre.";
      }
    } catch (e) {
      return "La vérification du mot de passe est indisponible : réessaie dans un moment.";
    }
    return "";
  }

  /** "Afficher le mot de passe" boxes: data-shows="<id of the password field>". */
  var toggles = document.querySelectorAll("input[data-shows]");
  for (var t = 0; t < toggles.length; t++) {
    toggles[t].addEventListener("change", function (event) {
      $(event.target.getAttribute("data-shows")).type = event.target.checked ? "text" : "password";
    });
  }

  var names = document.querySelectorAll("[data-app-name]");
  for (var i = 0; i < names.length; i++) names[i].textContent = cfg.appName;

  window.CryptoApp = {
    client: client,
    $: $,
    show: show,
    fail: fail,
    busy: busy,
    explain: explain,
    checkNewPassword: checkNewPassword,
    signOutHere: signOutHere,
  };
})();
