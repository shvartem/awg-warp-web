// If the app module fails to load (e.g. stale cached files), say so instead of a dead page.
setTimeout(function () {
  if (window.__appReady) return;
  var el = document.getElementById('status');
  el.className = 'status err';
  el.textContent = 'Страница загрузилась не полностью. Обновите её; если не поможет, очистите кеш браузера для этого сайта.';
}, 4000);
