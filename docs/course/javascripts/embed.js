/*
 * Keeps iframe widgets (docs/course/widgets/*.html) in step with the docs
 * site's light/dark toggle. The widget listens for {type: "theme", scheme}.
 */
document$.subscribe(() => {
  const send = () => {
    const scheme = document.body.getAttribute("data-md-color-scheme") === "slate" ? "dark" : "light";
    document.querySelectorAll("iframe.widget-frame").forEach((f) => {
      f.contentWindow && f.contentWindow.postMessage({ type: "theme", scheme }, "*");
    });
  };
  document.querySelectorAll("iframe.widget-frame:not([data-bound])").forEach((f) => {
    f.dataset.bound = "1";
    f.addEventListener("load", send);
  });
  if (!document.body.dataset.themeWatch) {
    document.body.dataset.themeWatch = "1";
    new MutationObserver(send).observe(document.body, { attributes: true, attributeFilter: ["data-md-color-scheme"] });
  }
  send();
});
