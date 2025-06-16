// Theme switching
function setTheme(theme) {
  if (theme === 'dark') {
    document.documentElement.style.setProperty('--primary-bg', '#121212');
    document.documentElement.style.setProperty('--accent-color', '#00ffaa');
    document.documentElement.style.setProperty('--text-color', '#fff');
  } else if (theme === 'light') {
    document.documentElement.style.setProperty('--primary-bg', '#f5f5f5');
    document.documentElement.style.setProperty('--accent-color', '#333');
    document.documentElement.style.setProperty('--text-color', '#000');
  } else if (theme === 'purple') {
    document.documentElement.style.setProperty('--primary-bg', '#1e1b2e');
    document.documentElement.style.setProperty('--accent-color', '#bb86fc');
    document.documentElement.style.setProperty('--text-color', '#fff');
  }
}

// Playlist player
let originalPlayer, remixPlayer;
function loadTracks(originalUrl, remixUrl) {
  if (originalPlayer) originalPlayer.destroy();
  if (remixPlayer) remixPlayer.destroy();
  originalPlayer = WaveSurfer.create({
    container: '#waveform-original',
    waveColor: '#888',
    progressColor: '#00ffaa',
    height: 100
  });
  remixPlayer = WaveSurfer.create({
    container: '#waveform-remix',
    waveColor: '#555',
    progressColor: '#00ffaa',
    height: 100
  });
  originalPlayer.load(originalUrl);
  remixPlayer.load(remixUrl);
}

// Main crossfade player
const stripe = Stripe("pk_live_51RW06LJ2Iq1764pCr02p7yLia0VqBgUcRfG7Qm5OWFNAwFZcexIs9iBB3B9s22elcQzQjuAUMBxpeUhwcm8hsDf900NbCbF3Vw");
function checkout(priceId) {
  stripe.redirectToCheckout({
    lineItems: [{ price: priceId, quantity: 1 }],
    mode: 'payment',
    successUrl: window.location.href,
    cancelUrl: window.location.href
  });
}

const formatTime = (seconds) => {
  const minutes = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

const original = WaveSurfer.create({
  container: '#waveform-original',
  waveColor: '#555',
  progressColor: '#00ffaa',
  height: 160,
  responsive: true,
  loop: false,
});

const remix = WaveSurfer.create({
  container: '#waveform-remix',
  waveColor: '#333',
  progressColor: '#00ffaa',
  height: 160,
  responsive: true,
  loop: false,
});

original.load('track-original.mp3');
remix.load('track-remix.mp3');

const crossfade = document.getElementById("crossfade");
const master = document.getElementById("master-volume");
const loopBtn = document.getElementById("loop-btn");
const tsOriginal = document.getElementById("timestamp-original");
const tsRemix = document.getElementById("timestamp-remix");
const playBtn = document.getElementById("play-btn");
const pauseBtn = document.getElementById("pause-btn");

let loopMode = false;

crossfade.addEventListener("input", () => {
  const val = parseFloat(crossfade.value);
  original.setVolume((1 - val) * parseFloat(master.value));
  remix.setVolume(val * parseFloat(master.value));
});

master.addEventListener("input", () => {
  const val = parseFloat(master.value);
  const cross = parseFloat(crossfade.value);
  original.setVolume((1 - cross) * val);
  remix.setVolume(cross * val);
});

loopBtn.addEventListener("click", () => {
  loopMode = !loopMode;
  loopBtn.classList.toggle("active", loopMode);
  loopBtn.textContent = loopMode ? "Loop On" : "Loop Off";
  original.setLoop(loopMode);
  remix.setLoop(loopMode);
});

original.on('audioprocess', () => {
  if (original.isPlaying()) {
    tsOriginal.textContent = formatTime(original.getCurrentTime());
  }
});

remix.on('audioprocess', () => {
  if (remix.isPlaying()) {
    tsRemix.textContent = formatTime(remix.getCurrentTime());
  }
});

playBtn.addEventListener('click', () => {
  original.play();
  remix.play();
});

pauseBtn.addEventListener('click', () => {
  original.pause();
  remix.pause();
});

document.body.addEventListener('keydown', function(e) {
  if (e.code === 'Space') {
    e.preventDefault();
    if (original.isPlaying() || remix.isPlaying()) {
      original.pause();
      remix.pause();
    } else {
      original.play();
      remix.play();
    }
  }
});

// Upload forms
const cleanForm = document.getElementById('cleanForm');
const masterForm = document.getElementById('masterForm');
const cleanStatus = document.getElementById('cleanStatus');
const masterStatus = document.getElementById('masterStatus');

const handleUpload = async (form, url, statusElement, statusText) => {
  statusElement.innerText = statusText;
  const formData = new FormData(form);
  try {
    const res = await fetch(url, { method: 'POST', body: formData });
    const result = await res.json();
    statusElement.innerText = result.message || 'Done! Download your result.';
  } catch (error) {
    statusElement.innerText = '❌ Error: Upload failed.';
  }
};

cleanForm.addEventListener('submit', (e) => {
  e.preventDefault();
  handleUpload(cleanForm, '/api/clean-edit', cleanStatus, 'Processing clean version...');
});

masterForm.addEventListener('submit', (e) => {
  e.preventDefault();
  handleUpload(masterForm, '/api/master-track', masterStatus, 'Mastering your track...');
});

// Unlock Hard Drive (placeholder)
function unlockHardDrive() {
  alert('Unlocking feature coming soon!');
}
