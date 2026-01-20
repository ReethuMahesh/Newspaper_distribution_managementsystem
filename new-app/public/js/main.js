// Example for fetch API
fetch('/api/employees')
  .then(response => {
    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }
    return response.json();
  })
  .then(data => {
    // handle data
  });
