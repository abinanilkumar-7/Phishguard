const fileInput = document.getElementById("email_file");
const dropZone = document.getElementById("dropZone");
const fileTitle = document.getElementById("fileTitle");
const fileSubtitle = document.getElementById("fileSubtitle");
const form = document.getElementById("uploadForm");
const analyzeButton = document.getElementById("analyzeButton");

function showSelectedFile(file) {
  if (!file) return;
  fileTitle.textContent = file.name;
  fileSubtitle.textContent = `${(file.size / 1024).toFixed(1)} KB selected`;
  dropZone.classList.add("dragover");
}
if (fileInput) {
  fileInput.addEventListener("change", () => showSelectedFile(fileInput.files[0]));
}
if (dropZone) {
  ["dragenter", "dragover"].forEach(eventName => dropZone.addEventListener(eventName, event => {
    event.preventDefault(); dropZone.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach(eventName => dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    if (eventName === "drop" && event.dataTransfer.files.length) {
      fileInput.files = event.dataTransfer.files;
      showSelectedFile(fileInput.files[0]);
    } else if (eventName === "dragleave") {
      dropZone.classList.remove("dragover");
    }
  }));
}
if (form) {
  form.addEventListener("submit", event => {
    const file = fileInput.files[0];
    if (!file || !file.name.toLowerCase().endsWith(".eml")) {
      event.preventDefault();
      alert("Please choose a valid .eml email file.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      event.preventDefault();
      alert("The selected file is larger than 5 MB.");
      return;
    }
    analyzeButton.disabled = true;
    analyzeButton.innerHTML = "<span>◌</span> Analyzing email... <b>PLEASE WAIT</b>";
  });
}