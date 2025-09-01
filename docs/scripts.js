document.querySelectorAll('.deafult-btn').forEach((button) => {
  button.addEventListener('click', function() {
    this.classList.add('active'); // Change button appearance (optional)
  });
});
