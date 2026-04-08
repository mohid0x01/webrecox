/* ══════════════════════════════════════════
   TeamCyberOps — Premium Sound Effects
   Web Audio API — No external dependencies
══════════════════════════════════════════ */

let ctx: AudioContext | null = null;
function getCtx() { if (!ctx) ctx = new AudioContext(); return ctx; }

function playTone(freq: number, dur: number, type: OscillatorType = 'sine', vol = 0.15) {
  try {
    const c = getCtx();
    const o = c.createOscillator();
    const g = c.createGain();
    o.type = type;
    o.frequency.setValueAtTime(freq, c.currentTime);
    g.gain.setValueAtTime(vol, c.currentTime);
    g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + dur);
    o.connect(g); g.connect(c.destination);
    o.start(); o.stop(c.currentTime + dur);
  } catch { /* audio not supported */ }
}

export function playModuleStart() { playTone(880, 0.08, 'sine', 0.08); }
export function playModuleDone() { playTone(1200, 0.1, 'sine', 0.1); }
export function playModuleError() { playTone(300, 0.15, 'sawtooth', 0.08); }

export function playScanStart() {
  try {
    const c = getCtx();
    [440, 554, 659, 880].forEach((f, i) => {
      const o = c.createOscillator(); const g = c.createGain();
      o.type = 'sine'; o.frequency.value = f;
      g.gain.setValueAtTime(0.1, c.currentTime + i * 0.08);
      g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + i * 0.08 + 0.15);
      o.connect(g); g.connect(c.destination);
      o.start(c.currentTime + i * 0.08); o.stop(c.currentTime + i * 0.08 + 0.15);
    });
  } catch { /* */ }
}

export function playScanComplete() {
  try {
    const c = getCtx();
    [659, 784, 988, 1319, 1568].forEach((f, i) => {
      const o = c.createOscillator(); const g = c.createGain();
      o.type = 'sine'; o.frequency.value = f;
      g.gain.setValueAtTime(0.12, c.currentTime + i * 0.1);
      g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + i * 0.1 + 0.25);
      o.connect(g); g.connect(c.destination);
      o.start(c.currentTime + i * 0.1); o.stop(c.currentTime + i * 0.1 + 0.25);
    });
  } catch { /* */ }
}

export function playAlert() {
  try {
    const c = getCtx();
    [800, 600, 800].forEach((f, i) => {
      const o = c.createOscillator(); const g = c.createGain();
      o.type = 'square'; o.frequency.value = f;
      g.gain.setValueAtTime(0.06, c.currentTime + i * 0.12);
      g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + i * 0.12 + 0.1);
      o.connect(g); g.connect(c.destination);
      o.start(c.currentTime + i * 0.12); o.stop(c.currentTime + i * 0.12 + 0.1);
    });
  } catch { /* */ }
}

export function playFindingCritical() {
  playTone(200, 0.3, 'sawtooth', 0.1);
  setTimeout(() => playTone(180, 0.3, 'sawtooth', 0.08), 150);
}
