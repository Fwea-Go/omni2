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

<<<<<<< HEAD
// --- DUAL PLAYLIST & PLAYER LOGIC ---

// Fetch playlists from backend (expects /api/playlists endpoint)
async function fetchPlaylists() {
  const res = await fetch('/api/playlists');
  return await res.json();
}

// Populate playlists
function populatePlaylist(listId, tracks, type) {
  const ul = document.getElementById(listId);
  ul.innerHTML = '';
  tracks.forEach((track, idx) => {
    const li = document.createElement('li');
    li.className = 'flex items-center gap-2 p-2 rounded hover:bg-accent/10 cursor-pointer';
    li.tabIndex = 0;
    li.setAttribute('role', 'button');
    li.setAttribute('aria-label', `${type} track: ${track.title}`);
    li.innerHTML = `
      <span class="font-semibold">${track.title}</span>
      ${track.downloadable ? '<span class="ml-2 px-2 py-0.5 bg-accent text-black text-xs rounded">Download</span>' : ''}
    `;
    li.onclick = () => loadDualTrack(track, type);
    li.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') li.onclick(); };
    ul.appendChild(li);
  });
}

// Store playlists in memory
let originals = [], remixes = [], harddrive = [];
let currentOriginal = null, currentRemix = null;

// Load both original and remix into dual player
function loadDualTrack(track, type) {
  if (type === 'original') {
    currentOriginal = track;
    // Try to find matching remix by base name
    currentRemix = remixes.find(r => r.base === track.base) || null;
  } else if (type === 'remix') {
    currentRemix = track;
    currentOriginal = originals.find(o => o.base === track.base) || null;
  } else if (type === 'harddrive') {
    currentOriginal = null;
    currentRemix = track;
  }
  updateDualPlayer();
}

// Update dual player UI and load tracks
function updateDualPlayer() {
  const title = document.getElementById('now-playing-title');
  const albumArt = document.getElementById('album-art');
  if (currentOriginal) {
    originalPlayer.load(currentOriginal.url);
    title.textContent = currentOriginal.title;
    albumArt.src = currentOriginal.art || '/static/img/album-art.png';
    document.getElementById('download-btn').onclick = () => downloadTrack(currentOriginal);
  }
  if (currentRemix) {
    remixPlayer.load(currentRemix.url);
    if (!currentOriginal) {
      title.textContent = currentRemix.title;
      albumArt.src = currentRemix.art || '/static/img/album-art.png';
      document.getElementById('download-btn').onclick = () => downloadTrack(currentRemix);
    }
  }
  // Share button
  document.getElementById('share-btn').onclick = () => shareTrack(currentOriginal || currentRemix);
}

// Download logic
function downloadTrack(track) {
  if (!track.downloadable) {
    showToast('Download not allowed for this track.');
    return;
  }
  const a = document.createElement('a');
  a.href = track.url;
  a.download = track.title + '.mp3';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// Share logic
function shareTrack(track) {
  if (navigator.share) {
    navigator.share({ title: track.title, url: window.location.origin + track.url });
  } else {
    navigator.clipboard.writeText(window.location.origin + track.url);
    showToast('Track link copied!');
  }
}

// Toast utility
function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 2500);
}

// Show/hide Hard Drive playlist after payment
function unlockHardDrivePlaylist() {
  document.getElementById('harddrive-playlist').classList.remove('hidden');
}

// Back to Top button
const backToTop = document.getElementById('back-to-top');
window.addEventListener('scroll', () => {
  if (window.scrollY > 300) backToTop.style.display = 'block';
  else backToTop.style.display = 'none';
});
backToTop.onclick = () => window.scrollTo({ top: 0, behavior: 'smooth' });

// On page load, fetch playlists and populate
window.addEventListener('DOMContentLoaded', async () => {
  const data = await fetchPlaylists();
  originals = data.originals;
  remixes = data.remixes;
  harddrive = data.harddrive;
  populatePlaylist('originals-list', originals, 'original');
  populatePlaylist('remixes-list', remixes, 'remix');
  // Hard drive playlist only if unlocked
  if (data.harddriveUnlocked) {
    unlockHardDrivePlaylist();
    populatePlaylist('harddrive-list', harddrive, 'harddrive');
  }
});

=======
>>>>>>> f20d66079c0ffbf3a4804ccd78579d90a64b01f4
// Unlock Hard Drive (placeholder)
function unlockHardDrive() {
  alert('Unlocking feature coming soon!');
}
