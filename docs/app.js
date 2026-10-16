/* pink-crow site interactions — all motion gated by prefers-reduced-motion. */
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- mobile nav ---- */
  var toggle = document.querySelector(".nav-toggle");
  var links = document.querySelector(".nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    links.addEventListener("click", function (e) {
      if (e.target.tagName === "A") links.classList.remove("open");
    });
  }

  /* ---- copy install ---- */
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy");
      var done = function () {
        var old = btn.textContent;
        btn.textContent = "copied ✓";
        btn.classList.add("copied");
        setTimeout(function () { btn.textContent = old; btn.classList.remove("copied"); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else { done(); }
    });
  });

  /* ---- scroll reveal ---- */
  var reveals = document.querySelectorAll(".reveal");
  if (reduce || !("IntersectionObserver" in window)) {
    reveals.forEach(function (el) { el.classList.add("in"); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
      });
    }, { threshold: 0.14, rootMargin: "0px 0px -8% 0px" });
    reveals.forEach(function (el) { io.observe(el); });
  }

  /* ---- hero risk scope ---- */
  var scope = document.getElementById("scope");
  if (!scope) return;
  var path = scope.querySelector(".score-line");
  var area = scope.querySelector(".score-area");
  var dot = scope.querySelector(".score-dot");
  var numEl = scope.querySelector(".scope-score");
  var statusEl = scope.querySelector(".scope-status");
  var eventsEl = scope.querySelector(".events");
  var W = 440, H = 150, PAD = 8, THRESH = 60;

  // risk trajectory: [score, label] per step — a campaign that builds then is blocked, then decays
  var seq = [
    [4, null], [9, "benign: “what’s my order status?”"],
    [14, null], [28, "delimiter probe: “###”"],
    [33, null], [48, "role-play: “you are now DAN”"],
    [55, null], [73, "override: “ignore all previous…”"],
    [68, "SESSION BLOCKED · cooldown"], [52, null], [38, null], [26, null], [18, null], [13, null]
  ];
  var N = seq.length;
  function x(i) { return PAD + (i / (N - 1)) * (W - PAD * 2); }
  function y(s) { return H - PAD - (s / 100) * (H - PAD * 2); }
  function color(s) { return s >= 85 ? "var(--pink)" : s >= THRESH ? "var(--pink)" : s >= 30 ? "var(--amber)" : "var(--mint)"; }
  function statusText(s) { return s >= THRESH ? "BLOCKED" : s >= 30 ? "ELEVATED" : "OK"; }

  function lineFor(k) {
    var d = ""; for (var i = 0; i <= k; i++) { d += (i ? "L" : "M") + x(i).toFixed(1) + " " + y(seq[i][0]).toFixed(1) + " "; }
    return d.trim();
  }
  function areaFor(k) {
    if (k < 0) return "";
    return "M" + x(0).toFixed(1) + " " + (H - PAD) + " " + lineFor(k).slice(1) + " L" + x(k).toFixed(1) + " " + (H - PAD) + " Z";
  }
  function addEvent(label) {
    if (!label || !eventsEl) return;
    var crit = /BLOCK/.test(label);
    var row = document.createElement("div");
    row.className = "ev";
    row.innerHTML = '<span class="tag">' + (crit ? "●" : "›") + "</span><span>" + label + "</span>";
    eventsEl.appendChild(row);
    while (eventsEl.children.length > 3) eventsEl.removeChild(eventsEl.firstChild);
    requestAnimationFrame(function () { row.style.transition = "opacity .4s ease, transform .4s ease"; row.style.opacity = "1"; row.style.transform = "none"; });
  }

  function render(k, score) {
    path.setAttribute("d", lineFor(k));
    area.setAttribute("d", areaFor(k));
    dot.setAttribute("cx", x(k)); dot.setAttribute("cy", y(score));
    dot.style.fill = color(score);
    numEl.textContent = Math.round(score);
    numEl.style.color = color(score);
    statusEl.textContent = statusText(score);
    statusEl.style.color = color(score);
    statusEl.style.borderColor = score >= 30 ? color(score) : "var(--hairline-strong)";
  }

  if (reduce) {
    // static final state: draw whole curve at the blocked peak, list the key events
    render(7, seq[7][0]); // peak = blocked
    path.setAttribute("d", lineFor(N - 1));
    area.setAttribute("d", areaFor(N - 1));
    dot.setAttribute("cx", x(7)); dot.setAttribute("cy", y(seq[7][0]));
    ["delimiter probe: “###”", "override: “ignore all previous…”", "SESSION BLOCKED · cooldown"].forEach(addEvent);
    return;
  }

  var step = 0, last = 0, cur = 0;
  function tick(ts) {
    if (!last) last = ts;
    var dt = ts - last;
    if (dt > 620) {
      last = ts;
      var target = seq[step][0];
      cur = target;
      render(step, cur);
      if (seq[step][1]) addEvent(seq[step][1]);
      step++;
      if (step >= N) {
        setTimeout(function () { step = 0; last = 0; cur = 0; if (eventsEl) eventsEl.innerHTML = ""; requestAnimationFrame(tick); }, 2600);
        return;
      }
    } else {
      // ease the number between steps for a live feel
      var prev = step === 0 ? 0 : seq[step - 1][0];
      var nxt = seq[step][0];
      var t = Math.min(1, dt / 620);
      var s = prev + (nxt - prev) * (t * t * (3 - 2 * t));
      numEl.textContent = Math.round(s);
      numEl.style.color = color(s);
      dot.setAttribute("cy", y(s));
      dot.style.fill = color(s);
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
