const themeButton = document.getElementById('theme');
const status = document.getElementById('status');
let clearStatus;
// The downloaded archive already contains its assets; it cannot contain itself.
if (location.protocol === 'file:') document.getElementById('kit-download').hidden = true;
themeButton.addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  themeButton.setAttribute('aria-pressed', String(dark));
  themeButton.innerHTML = `${dark ? 'Light' : 'Dark'} view <span aria-hidden="true">◐</span>`;
  document.querySelectorAll('.adaptive-logo').forEach(img => { img.src = img.dataset[dark ? 'dark' : 'light']; });
});
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      status.textContent = `Copied ${button.dataset.copy}`;
    } catch {
      status.textContent = `Color: ${button.dataset.copy}`;
    }
    clearTimeout(clearStatus);
    clearStatus = setTimeout(() => { status.textContent = ''; }, 2800);
  });
});
