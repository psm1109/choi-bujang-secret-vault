const installButton = document.querySelector('#install-app');
const installStatus = document.querySelector('#install-status');
const connectionStatus = document.querySelector('#connection-status');
const deviceStatus = document.querySelector('#device-status');
const offlineNotice = document.querySelector('#offline-notice');
const standalone = window.matchMedia('(display-mode: standalone)');
let installPrompt = null;

function renderConnection() {
  const offline = navigator.onLine === false;
  connectionStatus.textContent = offline
    ? '연결: 오프라인'
    : '연결: 네트워크 사용 가능 — 서버 접속 성공을 뜻하지 않습니다.';
  offlineNotice.hidden = !offline;
  // 로그인·설치·접속 성공으로 기기 등록이나 승인을 추정하지 않습니다.
  deviceStatus.textContent = offline
    ? '기기 승인: 확인 불가 — 오프라인입니다.'
    : '기기 승인: 확인 불가 — 서버의 승인 상태 연결이 제공되지 않았습니다.';
}

function renderInstallation() {
  if (standalone.matches || navigator.standalone === true) {
    installButton.hidden = true;
    installStatus.textContent = '앱 창으로 열었습니다. 기기 승인은 별도로 확인해야 합니다.';
  }
}

window.addEventListener('online', renderConnection);
window.addEventListener('offline', renderConnection);
standalone.addEventListener('change', renderInstallation);
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  installPrompt = event;
  installButton.hidden = false;
  installStatus.textContent = '이 브라우저에서 자료실 앱을 설치할 수 있습니다. 설치는 기기 승인이 아닙니다.';
  renderInstallation();
});
installButton.addEventListener('click', async () => {
  const prompt = installPrompt;
  if (!prompt) return;
  installPrompt = null;
  installButton.disabled = true;
  try {
    await prompt.prompt();
    const choice = await prompt.userChoice;
    installStatus.textContent = choice.outcome === 'accepted'
      ? '설치 요청을 수락했습니다. 기기 승인 상태는 별도로 확인해야 합니다.'
      : '설치를 취소했습니다. 브라우저에서 계속 자료실을 사용할 수 있습니다.';
  } catch {
    installStatus.textContent = '설치 안내를 열지 못했습니다. 브라우저 메뉴를 이용해 주세요.';
  } finally {
    installButton.disabled = false;
    installButton.hidden = true;
  }
});
window.addEventListener('appinstalled', () => {
  installPrompt = null;
  installButton.hidden = true;
  installStatus.textContent = '자료실 앱이 설치되었습니다. 기기 확인이 완료된 것은 아닙니다.';
});

renderConnection();
renderInstallation();
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' })
    .catch(() => {
      offlineNotice.hidden = false;
      offlineNotice.textContent = '오프라인 안내를 준비하지 못했습니다. 자료실은 네트워크 연결이 필요합니다.';
    });
}
