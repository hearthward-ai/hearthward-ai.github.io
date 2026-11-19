/* Side bar menu: opens from the hamburger button, closes with the X button, a click on the backdrop, or Esc.
   Focus moves into the panel, is trapped there while it is open, and returns to the button on close. */
(function () {
  var d = document, root = d.documentElement;
  var btn = d.querySelector('.menubtn'), panel = d.getElementById('sidenav'), back = d.querySelector('.backdrop');
  if (!btn || !panel) return;
  var closeBtn = panel.querySelector('.closebtn');
  var bg = [].slice.call(d.querySelectorAll('.skip,.topbar,header,main,footer'));

  function focusable() {
    return [].slice.call(panel.querySelectorAll('a[href],button:not([disabled])'));
  }
  function setInert(on) {
    bg.forEach(function (e) { if (on) e.setAttribute('inert', ''); else e.removeAttribute('inert'); });
  }
  function open() {
    root.classList.add('nav-open');
    btn.setAttribute('aria-expanded', 'true');
    setInert(true);
    d.addEventListener('keydown', onKey);
    (closeBtn || panel).focus();
  }
  function close(returnFocus) {
    root.classList.remove('nav-open');
    btn.setAttribute('aria-expanded', 'false');
    setInert(false);
    d.removeEventListener('keydown', onKey);
    if (returnFocus !== false) btn.focus();
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key !== 'Tab') return;
    var f = focusable();
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1], a = d.activeElement;
    if (!panel.contains(a)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && a === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && a === last) { e.preventDefault(); first.focus(); }
  }
  btn.addEventListener('click', function () {
    if (root.classList.contains('nav-open')) close(); else open();
  });
  if (closeBtn) closeBtn.addEventListener('click', function () { close(); });
  if (back) back.addEventListener('click', function () { close(); });
  addEventListener('pageshow', function () { if (root.classList.contains('nav-open')) close(false); });
})();
