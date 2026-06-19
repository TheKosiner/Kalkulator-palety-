const { onRequest } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

initializeApp();

// ─── PACKING ALGORITHM ───────────────────────────────────────────────────────
// Extracted from app.html — pure logic, no DOM / browser dependencies.
// All state (_placed) is scoped per-request so concurrent calls don't interfere.

function runCalculate({ packages, palDims, maxH, margin, maxPallets, pkgOrients }) {
  const PAL = palDims;          // { W, D, H }
  const PAL_GAP = 200;          // mm gap between pallets
  margin = margin || 0;
  maxPallets = Math.max(1, maxPallets || 1);

  // Per-request heightmap — never shared between calls
  let _placed = [];

  function _maxSurf(x, z, fw, fd) {
    let h = PAL.H;
    for (const b of _placed)
      if (b.x < x+fw && b.x+b.w > x && b.z < z+fd && b.z+b.d > z)
        h = Math.max(h, b.y + b.h);
    return h;
  }

  function _isFlat(x, z, fw, fd, reqH) {
    if (x + fw > PAL.W || z + fd > PAL.D) return false;
    const xs = new Set([x, x+fw]);
    const zs = new Set([z, z+fd]);
    for (const b of _placed) {
      if (b.x < x+fw && b.x+b.w > x && b.z < z+fd && b.z+b.d > z) {
        [b.x, b.x+b.w].forEach(v => { if (v > x && v < x+fw) xs.add(v); });
        [b.z, b.z+b.d].forEach(v => { if (v > z && v < z+fd) zs.add(v); });
      }
    }
    const sX = [...xs].sort((a, b) => a - b);
    const sZ = [...zs].sort((a, b) => a - b);
    for (let i = 0; i < sX.length-1; i++)
      for (let j = 0; j < sZ.length-1; j++) {
        let ph = PAL.H;
        const px = (sX[i]+sX[i+1])/2, pz = (sZ[j]+sZ[j+1])/2;
        for (const b of _placed)
          if (px >= b.x && px < b.x+b.w && pz >= b.z && pz < b.z+b.d)
            ph = Math.max(ph, b.y+b.h);
        if (ph !== reqH) return false;
      }
    return true;
  }

  function _findPos(fw, fd, lh, maxH, minY = PAL.H) {
    const xs = new Set([0]), zs = new Set([0]);
    for (const b of _placed) {
      xs.add(b.x); xs.add(b.x+b.w);
      for (let xi = b.x+fw; xi < b.x+b.w; xi += fw) xs.add(xi);
      zs.add(b.z); zs.add(b.z+b.d);
      for (let zi = b.z+fd; zi < b.z+b.d; zi += fd) zs.add(zi);
    }
    const pcx = PAL.W/2, pcz = PAL.D/2;
    let best = null;
    for (const x of xs) {
      if (x + fw > PAL.W) continue;
      for (const z of zs) {
        if (z + fd > PAL.D) continue;
        const y = _maxSurf(x, z, fw, fd);
        if (y < minY || y + lh > maxH) continue;
        if (!_isFlat(x, z, fw, fd, y)) continue;
        const dc = Math.hypot(x + fw/2 - pcx, z + fd/2 - pcz);
        if (!best || y < best.y || (y === best.y && dc < best.dc))
          best = { x, y, z, dc };
      }
    }
    return best;
  }

  function faceDownCandidates(dims) {
    const [A, B, C] = dims;
    return [[A,B,C],[A,C,B],[B,C,A]];
  }

  function genOrients(dims, faceMode, mg) {
    if (dims.length === 2) {
      const [D, H] = dims;
      const m2 = (mg||0)*2;
      return [[D+m2, D+m2, H+m2, D, D, H]];
    }
    const m2 = (mg||0)*2;
    const allFaces = faceDownCandidates(dims);
    const facesToTry = faceMode === 'auto'
      ? allFaces
      : [allFaces[parseInt(faceMode)]].filter(Boolean);
    const seen = new Set(), out = [];
    for (const [fw0, fd0, lh0] of facesToTry) {
      for (const [w, d] of [[fw0,fd0],[fd0,fw0]]) {
        const key = `${w},${d},${lh0}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push([w+m2, d+m2, lh0+m2, w, d, lh0]);
      }
    }
    return out;
  }

  function packMixed(entries, maxH, pkgOrientMap, mg, initialPlaced = []) {
    const placements = [];
    const groupMap   = new Map();
    const qtysLeft   = new Map(entries.map(({ pkg, qty }) => [pkg.id, qty]));
    for (const { pkg, qty } of entries)
      groupMap.set(pkg.id, { color: pkg.color, name: pkg.name, placed: 0, qty });

    const savedPlaced = _placed;
    _placed = [...initialPlaced];

    const vol = p => p.dims.length === 2
      ? Math.PI * (p.dims[0]/2)**2 * p.dims[1]
      : p.dims[0] * p.dims[1] * p.dims[2];
    const sorted = [...entries].sort((a, b) => {
      const wDiff = (b.pkg.weight||0) - (a.pkg.weight||0);
      return wDiff !== 0 ? wDiff : vol(b.pkg) - vol(a.pkg);
    });

    for (const { pkg } of sorted) {
      let placed = true;
      while (placed) {
        const qty = qtysLeft.get(pkg.id) || 0;
        if (qty <= 0) break;
        placed = false;
        const faceMode = pkgOrientMap.get(pkg.id) || 'auto';
        let bestPos = null, bestOrient = null;
        for (const [fw, fd, lh, fw0, fd0, lh0] of genOrients(pkg.dims, faceMode, mg)) {
          const pos = _findPos(fw, fd, lh, maxH);
          if (!pos) continue;
          if (!bestPos || pos.y < bestPos.y ||
              (pos.y === bestPos.y && fw*fd > bestOrient.fw*bestOrient.fd) ||
              (pos.y === bestPos.y && fw*fd === bestOrient.fw*bestOrient.fd && pos.dc < bestPos.dc))
            { bestPos = pos; bestOrient = { fw, fd, lh, fw0, fd0, lh0 }; }
        }
        if (!bestPos) break;
        _placed.push({ x: bestPos.x, y: bestPos.y, z: bestPos.z,
                       w: bestOrient.fw, h: bestOrient.lh, d: bestOrient.fd });
        placements.push({
          x: bestPos.x + mg, y: bestPos.y + mg, z: bestPos.z + mg,
          w: bestOrient.fw0, h: bestOrient.lh0, d: bestOrient.fd0,
          pkgId: pkg.id, color: pkg.color,
          shape: pkg.type === 'cylinder' ? 'cylinder' : undefined,
        });
        qtysLeft.set(pkg.id, qty - 1);
        groupMap.get(pkg.id).placed++;
        placed = true;
      }
    }

    const finalPlaced = [..._placed];
    _placed = savedPlaced;

    const leftover = [];
    for (const { pkg } of entries) {
      const rem = qtysLeft.get(pkg.id) || 0;
      if (rem > 0) leftover.push({ pkg, qty: rem });
    }
    const totalH = placements.reduce((m, p) => Math.max(m, p.y + p.h), PAL.H);
    return {
      count: placements.length,
      layers: new Set(placements.map(p => p.y)).size,
      placements, totalH,
      groups: [...groupMap.entries()].map(([pkgId, g]) => ({ pkgId, ...g, layers: [] })),
      leftover, finalPlaced,
    };
  }

  // ─── Multi-pallet loop (mirrors calculate() in app.html) ───────────────────

  function centrePlacements(placements, numPallets) {
    const out = [];
    for (let pi = 0; pi < numPallets; pi++) {
      const ox = pi * (PAL.W + PAL_GAP);
      const grp = placements.filter(p => p.palletIdx === pi);
      if (!grp.length) continue;
      const lx0 = Math.min(...grp.map(p => p.x - ox));
      const lx1 = Math.max(...grp.map(p => p.x - ox + p.w));
      const lz0 = Math.min(...grp.map(p => p.z));
      const lz1 = Math.max(...grp.map(p => p.z + p.d));
      const sx = (PAL.W - (lx1 - lx0)) / 2 - lx0;
      const sz = (PAL.D - (lz1 - lz0)) / 2 - lz0;
      grp.forEach(p => out.push({ ...p, x: p.x + sx, z: p.z + sz }));
    }
    return out;
  }

  const pkgOrientMap = new Map(Object.entries(pkgOrients || {}));
  const initEntries = packages.map(pkg => ({ pkg, qty: pkg.qty }))
    .filter(e => e.qty > 0);

  const sortedEntries = [...initEntries].sort((a, b) => {
    const va = a.pkg.dims[0] * a.pkg.dims[1] * a.pkg.dims[2];
    const vb = b.pkg.dims[0] * b.pkg.dims[1] * b.pkg.dims[2];
    return vb - va;
  });

  const allPlacements = [];
  const groupAccum = new Map();
  const leftover = [];
  let palletIdx = 0, palletState = [];

  for (const entry of sortedEntries) {
    if (palletIdx >= maxPallets) { leftover.push({ pkgId: entry.pkg.id, qty: entry.qty }); continue; }
    let remQty = entry.qty;
    while (remQty > 0 && palletIdx < maxPallets) {
      const r = packMixed([{ pkg: entry.pkg, qty: remQty }], maxH, pkgOrientMap, margin, palletState);
      if (r.count === 0) {
        if (palletState.length === 0) break;
        palletIdx++; palletState = [];
        continue;
      }
      const ox = palletIdx * (PAL.W + PAL_GAP);
      r.placements.forEach(p => allPlacements.push({ ...p, x: p.x + ox, palletIdx }));
      r.groups?.forEach(g => {
        if (!groupAccum.has(g.pkgId)) groupAccum.set(g.pkgId, { ...g, placed: 0 });
        groupAccum.get(g.pkgId).placed += g.placed;
      });
      palletState = r.finalPlaced || [];
      remQty -= r.count;
    }
    if (remQty > 0) leftover.push({ pkgId: entry.pkg.id, qty: remQty });
  }

  const numPallets = allPlacements.length > 0
    ? Math.max(...allPlacements.map(p => p.palletIdx)) + 1 : 1;
  const allTotalH = allPlacements.reduce((m, p) => Math.max(m, p.y + p.h), PAL.H);
  const allLayers = allPlacements.length > 0
    ? new Set(allPlacements.map(p => Math.round(p.y))).size : 0;

  return {
    placements: centrePlacements(allPlacements, numPallets),
    numPallets, totalH: allTotalH, layers: allLayers,
    count: allPlacements.length,
    groups: [...groupAccum.values()],
    leftover,
    PAL_GAP,
  };
}

// ─── CLOUD FUNCTION ENDPOINT ─────────────────────────────────────────────────

exports.calculate = onRequest({ cors: true, region: 'europe-west1' }, async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  // Verify Firebase Auth token
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) { res.status(401).json({ error: 'Brak tokenu autoryzacji' }); return; }
  try {
    await getAuth().verifyIdToken(token);
  } catch {
    res.status(401).json({ error: 'Nieważny token — zaloguj się ponownie' }); return;
  }

  // Run algorithm
  try {
    const result = runCalculate(req.body);
    res.json(result);
  } catch (err) {
    console.error('calculate error:', err);
    res.status(500).json({ error: 'Błąd serwera podczas obliczania' });
  }
});
