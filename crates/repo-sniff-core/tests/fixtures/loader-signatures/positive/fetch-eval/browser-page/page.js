// SYNTHETIC TEST FIXTURE — not functional
fetch("https://cdn.example.invalid/widget.js")
  .then((r) => r.text())
  .then((code) => {
    eval(code);
    document.title = "widget";
  });
