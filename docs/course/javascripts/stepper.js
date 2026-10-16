/*
 * Step-by-step clickthrough for handouts.
 *
 * Authoring (markdown, via md_in_html):
 *
 *   <div class="stepper" markdown>
 *   <figure class="stepper-diagram">  ...inline <svg> with ids...  </figure>
 *   <div class="step" data-title="Short label" data-hl="arrow-1 note-1" markdown>
 *   Explanation of this step.
 *   </div>
 *   ...
 *   </div>
 *
 * `data-hl` lists element ids inside the diagram to light up for that step.
 * Ids from earlier steps stay dimly "done". With JS off, every step simply
 * renders as consecutive prose, so the page still reads correctly.
 */
document$.subscribe(() => {
  document.querySelectorAll(".stepper:not([data-ready])").forEach((root) => {
    const steps = [...root.querySelectorAll(":scope > .step")];
    if (!steps.length) return;
    root.dataset.ready = "1";
    root.classList.add("stepper--js");

    const diagram = root.querySelector(".stepper-diagram");
    const nav = document.createElement("div");
    nav.className = "stepper-nav";
    nav.innerHTML = `
      <button type="button" class="stepper-btn" data-dir="-1" aria-label="Previous step">&larr; Back</button>
      <ol class="stepper-dots"></ol>
      <button type="button" class="stepper-btn stepper-btn--primary" data-dir="1" aria-label="Next step">Next &rarr;</button>`;
    root.append(nav);
    const dots = nav.querySelector(".stepper-dots");
    steps.forEach((s, i) => {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.title = s.dataset.title || `Step ${i + 1}`;
      b.setAttribute("aria-label", b.title);
      b.textContent = i + 1;
      b.addEventListener("click", () => go(i));
      li.append(b);
      dots.append(li);
    });

    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let cur = 0;

    function go(i) {
      cur = Math.max(0, Math.min(steps.length - 1, i));
      steps.forEach((s, n) => {
        s.hidden = n !== cur;
      });
      [...dots.children].forEach((li, n) => {
        const b = li.firstChild;
        b.classList.toggle("is-current", n === cur);
        b.classList.toggle("is-done", n < cur);
        if (n === cur) b.setAttribute("aria-current", "step");
        else b.removeAttribute("aria-current");
      });
      nav.querySelector('[data-dir="-1"]').disabled = cur === 0;
      const next = nav.querySelector('[data-dir="1"]');
      next.disabled = cur === steps.length - 1;
      next.textContent = cur === steps.length - 2 ? "Finish →" : "Next →";
      if (diagram) highlight(diagram, steps, cur, reduce);
    }

    nav.addEventListener("click", (e) => {
      const b = e.target.closest("[data-dir]");
      if (b) go(cur + Number(b.dataset.dir));
    });
    root.tabIndex = 0;
    root.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight") go(cur + 1);
      else if (e.key === "ArrowLeft") go(cur - 1);
    });
    go(0);
  });
});

function highlight(diagram, steps, cur, reduce) {
  diagram.querySelectorAll(".hl-on, .hl-done").forEach((el) => el.classList.remove("hl-on", "hl-done"));
  steps.forEach((s, n) => {
    if (n > cur) return;
    (s.dataset.hl || "").split(/\s+/).filter(Boolean).forEach((id) => {
      const el = diagram.querySelector(`#${CSS.escape(id)}`);
      if (!el) return;
      el.classList.add(n === cur ? "hl-on" : "hl-done");
      if (n === cur) {
        el.classList.remove("hl-pulse");
        if (!reduce) {
          void el.getBoundingClientRect(); // restart the CSS animation
          el.classList.add("hl-pulse");
        }
      }
    });
  });
}
