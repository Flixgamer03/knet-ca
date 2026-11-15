// Kopieren-Buttons: <button class="copy" data-copy="#id">
document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-copy]");
  if (btn) {
    const el = document.querySelector(btn.dataset.copy);
    const text = el ? (el.value !== undefined ? el.value : el.textContent) : "";
    try {
      await navigator.clipboard.writeText(text.trim());
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text.trim(); document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    const old = btn.textContent; btn.textContent = "Kopiert ✓";
    setTimeout(() => (btn.textContent = old), 1500);
  }
  // Lokale Downloads (Schlüssel verlassen den Browser nicht mehr Richtung Server)
  const dl = ev.target.closest("[data-download]");
  if (dl) {
    const src = document.querySelector(dl.dataset.download);
    let blob;
    if (dl.dataset.b64) {
      const bin = atob(src.value.trim());
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      blob = new Blob([bytes], { type: "application/x-pkcs12" });
    } else {
      blob = new Blob([src.value], { type: "application/x-pem-file" });
    }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = dl.dataset.filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  // Tabs
  const tab = ev.target.closest(".tabs button[data-tab]");
  if (tab) {
    const group = tab.closest("[data-tabgroup]");
    group.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b === tab));
    group.querySelectorAll(".tabpane").forEach((p) => p.classList.toggle("active", p.id === tab.dataset.tab));
  }
});

// Bestätigung für gefährliche Aktionen
document.addEventListener("submit", (ev) => {
  const msg = ev.target.dataset.confirm;
  if (msg && !window.confirm(msg)) ev.preventDefault();
});
