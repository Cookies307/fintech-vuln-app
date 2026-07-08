function requireAuth() {
  if (!localStorage.getItem('token')) location.href = 'index.html';
}
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  location.href = 'index.html';
}
function authFetch(url, opts = {}) {
  opts.headers = Object.assign({}, opts.headers, {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  });
  return fetch(url, opts);
}
