// public/js/theme.js  – UNIVERSAL THEME CONTROLLER (v2)
// Adds 'dark-mode' to BOTH <html> and <body> so every CSS rule works.
(function () {
  const wantDark = localStorage.getItem('theme') === 'dark';

  /* 1. EARLY paint – html only (body may not exist yet) */
  if (wantDark) document.documentElement.classList.add('dark-mode');

  /* 2. Late bindings – run when DOM is ready */
  document.addEventListener('DOMContentLoaded', () => {
    const btn  = document.getElementById('darkModeToggle');
    const icon = btn?.querySelector('i');

    /* helper */
    const apply = theme => {
      const dark = theme === 'dark';
      [document.documentElement, document.body].forEach(el =>
        el.classList.toggle('dark-mode', dark)
      );
      if (icon) {
        icon.classList.toggle('fa-sun',  dark);
        icon.classList.toggle('fa-moon', !dark);
      }
    };

    /* first render (now that <body> exists) */
    apply(localStorage.getItem('theme') || 'light');

    /* click-toggle */
    btn?.addEventListener('click', () => {
      const next = document.documentElement.classList.contains('dark-mode')
                   ? 'light' : 'dark';
      localStorage.setItem('theme', next);
      apply(next);
    });
  });
})();
