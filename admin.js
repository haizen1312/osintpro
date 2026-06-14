function showMessage(message, isError = false) {
  const box = document.querySelector("#adminMessage");
  box.textContent = message;
  box.classList.add("visible");
  box.classList.toggle("error", isError);
}

document.querySelector("#adminForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const code = document.querySelector("#adminCode").value;
  button.disabled = true;
  button.textContent = "Verifico...";

  try {
    const response = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Accesso negato");
    showMessage("Accesso Admin attivato. Report e monitor illimitati sbloccati.");
    window.setTimeout(() => {
      window.location.href = "/";
    }, 700);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    document.querySelector("#adminCode").value = "";
    button.disabled = false;
    button.textContent = "Sblocca Admin";
  }
});
