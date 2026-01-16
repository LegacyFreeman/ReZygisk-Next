const errorh_panel = document.getElementById('errorh_panel')
let sys_error = localStorage.getItem('/ReZygisk/error')

if (!sys_error) {
  localStorage.setItem('/ReZygisk/error', '')

  sys_error = localStorage.getItem('/ReZygisk/error')
}

if (sys_error.length !== 0) errorh_panel.innerHTML = sys_error