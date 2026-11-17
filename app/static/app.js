/* Show/hide password buttons. Served from our own origin because the CSP forbids inline scripts. */
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-toggle-password]");
  if (!button) { return; }
  var input = button.parentElement.querySelector("input");
  if (!input) { return; }
  var show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
});