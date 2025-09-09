// CSRF helper: fetch and cache CSRF token, and add to fetch requests
let csrfToken = null;
async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const API_BASE_URL =
    window.location.hostname === "localhost"
      ? "http://localhost:4242"
      : "https://api.grinzine.com";
  const res = await fetch(`${API_BASE_URL}/csrf-token`, { credentials: "include" });
  const data = await res.json();
  csrfToken = data.csrfToken;
  return csrfToken;
}

// Use this function for all POST/PUT/DELETE fetches
async function csrfFetch(url, options = {}) {
  const token = await getCsrfToken();
  options.headers = options.headers || {};
  options.headers["X-CSRF-Token"] = token;
  options.credentials = options.credentials || "include";
  return fetch(url, options);
}
