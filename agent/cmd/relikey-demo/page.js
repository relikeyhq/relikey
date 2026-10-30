// SPDX-License-Identifier: EUPL-1.2
"use strict";

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

function items(xs, render) {
  return xs.length ? xs.map(render) : [el("li", "none", "none")];
}

async function poll() {
  let s;
  try {
    s = await (await fetch("/api/story", {cache: "no-store"})).json();
  } catch (e) {
    setTimeout(poll, 1000);
    return;
  }
  document.getElementById("steps").replaceChildren(...s.steps.map(st => {
    const li = el("li", "step");
    li.append(el("span", "at", st.at.slice(11, 19)), el("strong", "", st.title), el("p", "", st.detail));
    return li;
  }));
  const acc = s.bastion.accounts;
  document.getElementById("accounts").replaceChildren(...items(Object.keys(acc).sort(),
    n => el("li", "", n + ": " + (acc[n].join(", ") || "no role"))));
  document.getElementById("sessions").replaceChildren(...items(s.bastion.sessions,
    x => el("li", "", x[0] + " on " + x[1])));
  const state = document.getElementById("state");
  state.textContent = s.error ? "Stopped: " + s.error
    : (s.done ? "Finished. Press Ctrl-C in the terminal to stop the demo." : "Running...");
  state.className = s.error ? "bad" : "";
  if (!s.done) setTimeout(poll, 500);
}

poll();
