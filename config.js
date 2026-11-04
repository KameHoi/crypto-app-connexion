// Public settings of the authorization page. Only values meant to be shipped to clients:
// the project URL and its publishable key (row level security protects the data, not this key).
// Filled in when the Supabase project exists; the app reads the same two values (P17).
window.CRYPTO_APP_CONFIG = {
  appName: "CRYPTO_APP",
  supabaseUrl: "https://tbgiermxwqlnvdwxrean.supabase.co",
  publishableKey: "sb_publishable_GYelMrUKOZ7xRVVbrWbV2g_wYko2Bs8",
};
