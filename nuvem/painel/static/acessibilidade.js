// botoes de texto grande e alto contraste, guarda a escolha no navegador
(function () {
  function alternar(classe) {
    document.body.classList.toggle(classe);
    try { localStorage.setItem(classe, document.body.classList.contains(classe) ? "1" : "0"); } catch (e) {}
  }
  ["texto-grande", "alto-contraste"].forEach(function (c) {
    try { if (localStorage.getItem(c) === "1") document.body.classList.add(c); } catch (e) {}
  });
  var t = document.getElementById("btn-texto");
  var c = document.getElementById("btn-contraste");
  if (t) t.addEventListener("click", function () { alternar("texto-grande"); });
  if (c) c.addEventListener("click", function () { alternar("alto-contraste"); });
})();
