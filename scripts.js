document.querySelectorAll('.paywall-btn').forEach((button) => {
  button.addEventListener('click', function() {
    const link = this.nextElementSibling; // The link immediately after the button
    this.classList.add('active'); // Change button appearance (optional)
    link.style.display = 'block'; // Show the hidden link
  });
});
