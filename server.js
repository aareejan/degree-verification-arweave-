const express    = require('express');
const multer     = require('multer');
const sharp      = require('sharp');
const QRCode     = require('qrcode');
const { chromium } = require('playwright');
const { exec }   = require('child_process');
const fs         = require('fs');
const path       = require('path');
const util       = require('util');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const Database   = require('better-sqlite3');
const { TurboFactory, ArweaveSigner } = require('@ardrive/turbo-sdk');

const execPromise = util.promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;

const publicDir = path.join(__dirname, 'public');
const tempDir   = path.join(__dirname, 'temp');
const usersFilePath = path.join(__dirname, 'users.json');

if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

const upload = multer({ dest: tempDir });

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'degree-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 8 }
}));

/* =========================================================
   CONSTANTS
   ========================================================= */
const ISSUER_WALLET = "TBJSLEeN74eSi7N3kVTpDRJ53tunl5idAq_BYM4fkDA";
const DEGREE_ARGON2_SALT = "2f8d1e4c7a9b3e6f0d5c8a1b4e7f2d9c";
const DEGREE_APP_TAG = "HIST-Credential";

const ARWEAVE_GRAPHQL_ENDPOINTS = [
  "https://arweave.net/graphql",
  "https://ar-io.net/graphql",
  "https://g8way.io/graphql"
];
const ARWEAVE_HTTP_GATEWAYS = [
  "https://arweave.net",
  "https://ar-io.net",
  "https://g8way.io"
];

/* ---------- user config ---------- */
if (!fs.existsSync(usersFilePath)) {
  console.error('users.json missing'); process.exit(1);
}
function loadUsers() {
  const raw = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
  return Array.isArray(raw.users) ? raw.users : [];
}
let USERS = loadUsers();
const findUserById       = (id) => USERS.find(u => u.id === id);
const findUserByUsername = (u)  => USERS.find(x => x.username === u);
const userWalletPath     = (u)  => path.join(__dirname, u.dir, u.walletFile);
const userAdminHtmlPath  = (u)  => u.adminHtml ? path.join(__dirname, u.dir, u.adminHtml) : null;
function getUserTemplate(u, type) {
  const t = u.templates && u.templates[type];
  if (!t) throw new Error(`Template "${type}" not configured`);
  return { viewerTxId: t.viewerTxId, pdfHtml: t.pdfHtml };
}

/* ---------- auth ---------- */
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.redirect('/login');
  const user = findUserById(req.session.userId);
  if (!user) return req.session.destroy(() => res.redirect('/login'));
  req.user = user; next();
}

app.get('/login', (req, res) => {
  const p = path.join(__dirname, 'login.html');
  if (!fs.existsSync(p)) return res.status(500).send('login.html missing');
  res.sendFile(p);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  USERS = loadUsers();
  const user = findUserByUsername(String(username));
  if (!user || !bcrypt.compareSync(String(password), user.passwordHash))
    return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  res.json({ success: true, redirect: '/admin' });
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get(['/admin', '/admin.html'], requireAuth, (req, res) => {
  const custom = userAdminHtmlPath(req.user);
  if (custom && fs.existsSync(custom)) return res.sendFile(custom);
  res.sendFile(path.join(publicDir, 'admin.html'));
});

app.get('/', (req, res) => res.redirect('/admin'));
app.use(express.static(publicDir, { index: false }));

/* ---------- progress jobs ---------- */
const jobs = new Map();
app.get('/progress/:jobId', requireAuth, (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job || job.userId !== req.user.id) return res.status(404).json({ error: 'Not found' });
  res.json(job);
});

/* =========================================================
   UPLOAD via ardrive CLI (no tags)
   ========================================================= */
async function uploadFileCLI(filePath, contentType, walletPath, parentFolderId, retry = true) {
  const cmd = `ardrive upload-file ` +
    `--wallet-file "${walletPath}" --turbo ` +
    `--gateway https://arweave.net ` +
    `--parent-folder-id ${parentFolderId} ` +
    `--local-path "${filePath}" --content-type "${contentType}"`;
  console.log('>', cmd);
  try {
    const { stdout, stderr } = await execPromise(cmd, { shell: true, maxBuffer: 20 * 1024 * 1024 });
    if (stderr) console.log('stderr:', stderr);
    const clean = stdout.replace(/^.*bigint:.*\n?/gm, '').trim();
    if (!clean) throw new Error('Empty response');
    const result = JSON.parse(clean);
    if (!result.created?.[0]?.dataTxId) throw new Error('No dataTxId');
    const txId = result.created[0].dataTxId;
    console.log('TX:', txId);
    for (let i = 1; i <= 3; i++) {
      try {
        const r = await fetch(`https://arweave.net/${txId}`, { method: 'HEAD' });
        if ([200, 301, 302].includes(r.status)) return txId;
      } catch (_) {}
      if (i < 3) await new Promise(r => setTimeout(r, 2000));
    }
    return txId;
  } catch (err) {
    if (retry) {
      await new Promise(r => setTimeout(r, 5000));
      return uploadFileCLI(filePath, contentType, walletPath, parentFolderId, false);
    }
    throw err;
  }
}

/* =========================================================
   UPLOAD via Turbo SDK — used ONLY for tagged revocation list
   ========================================================= */
async function uploadWithTurboSDK(filePath, contentType, walletPath, tags = []) {
  const jwk    = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
  const signer = new ArweaveSigner(jwk);
  const turbo  = TurboFactory.authenticated({ signer });

  const size = fs.statSync(filePath).size;
  console.log(`> turbo upload: ${path.basename(filePath)} (${size} bytes) + ${tags.length} tags`);

  const result = await turbo.uploadFile({
    fileStreamFactory: () => fs.createReadStream(filePath),
    fileSizeFactory:    () => size,
    dataItemOpts: {
      tags: [{ name: 'Content-Type', value: contentType }, ...(tags || [])]
    }
  });

  console.log('TX (turbo):', result.id);
  return result.id;
}

/* ---------- generate rudraksha PDF (existing flow) ---------- */
async function generateDegreePDF(data, photoPath, qrDataUrl, outputPath, templateHtmlPath) {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1200, height: 1600 } });
    if (!fs.existsSync(templateHtmlPath)) throw new Error(`Template not found: ${templateHtmlPath}`);
    await page.goto(`file://${templateHtmlPath}`, { waitUntil: 'networkidle' });

    const fill = async (sel, val) => {
      const el = await page.$(sel);
      if (el) await page.fill(sel, String(val ?? ''));
    };
    await fill('#studentName', data.studentName);
    await fill('#fatherName',  data.fatherName);
    await fill('#motherName',  data.motherName);
    await fill('#dob',         data.dob);
    await fill('#rollNo',      data.rollNo);
    await fill('#regNo',       data.regNo);
    await fill('#degreeName',  data.degreeName);
    await fill('#major',       data.major);
    await fill('#gpa',         data.gpa);
    await fill('#percentage',  data.percentage);
    await fill('#passYear',    data.passYear);
    await fill('#issueDate',   data.issueDate);
    await fill('#certNo',      data.certNo);

    if (photoPath && fs.existsSync(photoPath)) {
      const b64 = fs.readFileSync(photoPath).toString('base64');
      const dataUrl = `data:image/jpeg;base64,${b64}`;
      await page.evaluate(url => {
        const img = document.getElementById('studentPhoto');
        if (img) img.src = url;
      }, dataUrl);
    }
    await page.evaluate(url => {
      const img = document.getElementById('qrPreview');
      if (img) img.src = url;
    }, qrDataUrl);

    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(500);
    await page.pdf({ path: outputPath, format: 'A4', printBackground: true, margin:{top:'0',right:'0',bottom:'0',left:'0'} });
    if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size === 0) throw new Error('PDF generation failed');
    return outputPath;
  } finally {
    await browser.close();
  }
}

/* =========================================================
   DEGREE CERTIFICATE PDF (new)
   ========================================================= */
async function generateDegreeCertificatePDF(record, degreeJson, manifestUrl, outputPath) {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1200, height: 1600 } });
    const tplPath = path.join(__dirname, 'degree-pdf-template.html');
    if (!fs.existsSync(tplPath)) throw new Error('degree-pdf-template.html missing');
    await page.goto('file://' + tplPath, { waitUntil: 'networkidle' });

    // ---- compute derived values ----
    const gp = degreeJson.gradePoints || {};
    const terms = Array.isArray(degreeJson.terms) ? degreeJson.terms : [];
    let grandCredits = 0, grandQP = 0, semesters = 0, majorCredits = 0, majorQP = 0;
    const termsForPdf = terms.map(t => {
      let tCredits = 0, tQP = 0;
      const courses = (t.courses || []).map(c => {
        const p = (typeof gp[c.grade] === 'number') ? gp[c.grade] : 0;
        const qp = (Number(c.credits) || 0) * p;
        tCredits += Number(c.credits) || 0;
        tQP += qp;
        if (c.major){ majorCredits += Number(c.credits) || 0; majorQP += qp; }
        return { code: c.code, title: c.title, credits: Number(c.credits) || 0, grade: c.grade, qp };
      });
      grandCredits += tCredits; grandQP += tQP; semesters++;
      return { name: t.name, note: t.note || '', courses, credits: tCredits, qp: tQP, gpa: tCredits ? (tQP/tCredits) : 0 };
    });
    const cgpa      = grandCredits ? (grandQP / grandCredits) : 0;
    const majorGpa  = majorCredits ? (majorQP / majorCredits) : 0;

    // ---- QR pointing to the Arweave manifest ----
    const qrDataUrl = await QRCode.toDataURL(manifestUrl, { errorCorrectionLevel: 'H', margin: 1, width: 400 });

    // ---- inject data ----
    await page.evaluate((d) => {
      const $ = id => document.getElementById(id);
      const esc = s => String(s == null ? '' : s);

      $('pdfStudentName').textContent   = esc(d.record.student_name).toUpperCase();
      $('pdfSymbolNo').textContent      = esc(d.record.symbol_no);
      $('pdfDob').textContent           = esc(d.record.dob || '—');
      $('pdfProgramme').textContent     = esc(d.record.programme);
      $('pdfFaculty').textContent       = esc(d.record.faculty);
      $('pdfEnrollStatus').textContent  = esc(d.record.enrollmentStatus || 'Graduated — Degree Awarded');
      $('pdfDateIssued').textContent    = esc(d.record.date_issued);
      $('pdfDateIssued2').textContent   = esc(d.record.date_issued);
      $('pdfStanding').textContent      = esc(d.record.academicStanding || 'Good Standing');
      $('pdfStanding2').textContent     = esc(d.record.academicStanding || 'Good Standing');

      const shortId = 'AR/' + esc(d.record.manifest_tx).slice(0, 20) + '…';
      $('pdfDocId').textContent = shortId;
      $('pdfDocIdShort').textContent = esc(d.record.manifest_tx || '—');

      // Terms
      const wrap = $('pdfTermsWrap');
      wrap.innerHTML = d.terms.map(t => {
        const rows = t.courses.map(c => `
          <tr>
            <td class="c-code">${esc(c.code)}</td>
            <td class="c-title">${esc(c.title)}</td>
            <td class="c-cr">${c.credits.toFixed(2)}</td>
            <td class="c-gr">${esc(c.grade)}</td>
            <td class="c-qp">${c.qp.toFixed(2)}</td>
          </tr>`).join('');
        return `<div class="term">
          <div class="term-head">
            <span class="term-name">${esc(t.name)}</span>
            <span class="term-note">${esc(t.note)}</span>
          </div>
          <table class="courses">
            <thead><tr>
              <th class="c-code">Course</th><th class="c-title">Title</th>
              <th class="c-cr">Credits</th><th class="c-gr">Grade</th>
              <th class="c-qp">Quality Pts</th>
            </tr></thead>
            <tbody>${rows}</tbody>
            <tfoot><tr class="term-total">
              <td colspan="2" class="lbl-cell">Term Totals</td>
              <td class="c-cr">${t.credits.toFixed(2)}</td>
              <td class="c-gr">GPA ${t.gpa.toFixed(2)}</td>
              <td class="c-qp">${t.qp.toFixed(2)}</td>
            </tr></tfoot>
          </table>
        </div>`;
      }).join('');

      $('pdfTotalCredits').textContent  = d.summary.credits.toFixed(2);
      $('pdfTotalCredits2').textContent = d.summary.credits.toFixed(2);
      $('pdfTotalQP').textContent       = d.summary.qp.toFixed(2);
      $('pdfSemesters').textContent     = String(d.summary.semesters);
      $('pdfCgpaText').textContent      = d.summary.cgpa.toFixed(2) + ' / 4.00';
      $('pdfCgpaBig').textContent       = d.summary.cgpa.toFixed(2);
      $('pdfMajorGpa').textContent      = d.summary.majorGpa.toFixed(2);

      $('pdfQr').src = d.qrDataUrl;
    }, {
      record: record,
      terms: termsForPdf,
      summary: { credits: grandCredits, qp: grandQP, semesters, cgpa, majorGpa },
      qrDataUrl
    });

    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(400);

    await page.pdf({
      path: outputPath,
      format: 'Letter',
      printBackground: true,
      margin: { top: '0', right: '0', bottom: '0', left: '0' }
    });

    if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size === 0)
      throw new Error('Degree certificate PDF generation failed');
    return outputPath;
  } finally {
    await browser.close();
  }
}

/* ---------- fetch degree.json from Arweave ---------- */
async function fetchDegreeJsonFromArweave(txId) {
  let lastErr = null;
  for (const gw of ARWEAVE_HTTP_GATEWAYS) {
    try {
      const r = await fetch(`${gw}/${txId}`, { signal: AbortSignal.timeout(20000) });
      if (!r.ok) { lastErr = new Error('HTTP ' + r.status); continue; }
      return await r.json();
    } catch (err) { lastErr = err; }
  }
  throw lastErr || new Error('Could not fetch degree.json from Arweave');
}

/* ---------- per-user databases ---------- */
function getDatabaseForUser(user) {
  const dbPath = path.join(__dirname, user.dir, 'certificates.db');
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      certno TEXT NOT NULL,
      studentName TEXT NOT NULL,
      rollNo TEXT, regNo TEXT, degreeName TEXT, major TEXT,
      gpa TEXT, percentage TEXT, passYear TEXT,
      arweave_url TEXT NOT NULL, pdf_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  return db;
}

function getDegreeDatabaseForUser(user) {
  const dbPath = path.join(__dirname, user.dir, 'degrees.db');
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS degrees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_name TEXT,
      symbol_no TEXT,
      dob TEXT,
      programme TEXT,
      faculty TEXT,
      date_issued TEXT,
      academic_standing TEXT,
      identity_hash TEXT,
      arweave_json_tx TEXT,
      manifest_tx TEXT,
      manifest_url TEXT NOT NULL,
      revoked INTEGER DEFAULT 0,
      revoked_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  // Backwards-compat column additions
  try { db.exec(`ALTER TABLE degrees ADD COLUMN revoked INTEGER DEFAULT 0`); } catch(_){}
  try { db.exec(`ALTER TABLE degrees ADD COLUMN revoked_at DATETIME`); } catch(_){}
  try { db.exec(`ALTER TABLE degrees ADD COLUMN dob TEXT`); } catch(_){}
  try { db.exec(`ALTER TABLE degrees ADD COLUMN academic_standing TEXT`); } catch(_){}
  return db;
}

/* =========================================================
   ARWEAVE HELPERS — revocation list
   ========================================================= */
async function fetchOwnerOfTx(txId) {
  const query = `{ transaction(id: "${txId}") { owner { address } } }`;
  for (const gql of ARWEAVE_GRAPHQL_ENDPOINTS) {
    try {
      const res = await fetch(gql, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
        signal: AbortSignal.timeout(15000)
      });
      if (!res.ok) continue;
      const json = await res.json();
      const addr = json?.data?.transaction?.owner?.address;
      if (addr && typeof addr === 'string' && addr.length) return addr;
    } catch (_) {}
  }
  return "";
}

async function fetchLatestRevocationList() {
  const query = `{
    transactions(
      tags: [
        {name:"App-Name", values:["${DEGREE_APP_TAG}"]},
        {name:"Type",     values:["RevocationList"]}
      ],
      sort: HEIGHT_DESC, first: 1
    ) { edges { node { id } } }
  }`;

  let lastErr = null;
  for (const gql of ARWEAVE_GRAPHQL_ENDPOINTS) {
    try {
      const res = await fetch(gql, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
        signal: AbortSignal.timeout(20000)
      });
      if (!res.ok) { lastErr = new Error('GraphQL HTTP ' + res.status); continue; }
      const json = await res.json();
      const edges = json?.data?.transactions?.edges || [];
      if (!edges.length) return { listTxId: null, revoked: [] };
      const listTxId = edges[0].node.id;

      const signer = await fetchOwnerOfTx(listTxId);
      if (signer !== ISSUER_WALLET) {
        console.warn('Latest revocation list signer mismatch — ignoring');
        return { listTxId: null, revoked: [] };
      }

      for (const gw of ARWEAVE_HTTP_GATEWAYS) {
        try {
          const r = await fetch(gw + '/' + listTxId, { signal: AbortSignal.timeout(20000) });
          if (!r.ok) continue;
          const data = await r.json();
          return { listTxId, revoked: Array.isArray(data.revoked) ? data.revoked : [] };
        } catch (err) { lastErr = err; }
      }
      throw new Error('Revocation body fetch failed');
    } catch (err) { lastErr = err; }
  }
  throw lastErr || new Error('Revocation lookup failed on all gateways');
}

/* =========================================================
   DEGREE JSON BUILDER
   ========================================================= */
function buildDegreeJson(clientPayload) {
  const now = new Date();
  const months = ["January","February","March","April","May","June",
                  "July","August","September","October","November","December"];
  const defaultDateIssued = String(now.getDate()).padStart(2,"0") + " " + months[now.getMonth()] + " " + now.getFullYear();
  const r = clientPayload.record || {};

  return {
    institution: {
      name: "Himalayan Institute of Science & Technology",
      shortName: "HIST",
      tagline: "Office of the Controller of Examinations",
      address: "Kalimati Height, Kathmandu 44600, Nepal",
      phone: "+977 1 555 0142",
      email: "examinations@hist.edu.np",
      est: "1998",
      watermark: "HIMALAYAN INSTITUTE",
      crestText: "HIST"
    },
    issuerWallet: ISSUER_WALLET,
    appTag: DEGREE_APP_TAG,
    credential: {
      title: "Official Academic Transcript",
      subtitle: "Bachelor Level · Verifiable Credential · Anchored on Arweave",
      docIdPrefix: "HIST-TR-"
    },
    argon2: { salt: DEGREE_ARGON2_SALT, type: 2, mem: 65536, time: 3, parallelism: 1, hashLen: 32 },
    identityHash: String(clientPayload.identityHash || "").toLowerCase(),
    record: {
      programme:        r.programme        || "B.Sc. Computer Science (Hons.)",
      faculty:          r.faculty          || "Faculty of Science & Technology",
      enrollmentStatus: r.enrollmentStatus || "Graduated — Degree Awarded",
      dateIssued:       r.dateIssued       || defaultDateIssued,
      academicStanding: r.academicStanding || "Good Standing"
    },
    gradePoints: { "A":4.00,"A-":3.70,"B+":3.30,"B":3.00,"B-":2.70,"C+":2.30,"C":2.00,"D":1.00,"F":0.00 },
    gradeScale: [
      { letter:"A", points:4.00 }, { letter:"A−", points:3.70 },
      { letter:"B+", points:3.30 }, { letter:"B", points:3.00 },
      { letter:"B−", points:2.70 }, { letter:"C+", points:2.30 },
      { letter:"C", points:2.00 }, { letter:"D", points:1.00 },
      { letter:"F", points:0.00 },
      { letter:"W", points:null, label:"Withdrawn" },
      { letter:"I", points:null, label:"Incomplete" },
      { letter:"TR", points:null, label:"Transfer" }
    ],
    legendNote: "Grade point average is computed by dividing total quality points by total credits attempted. Only coursework completed at the Himalayan Institute of Science & Technology is included in the cumulative grade point average. Dean's List recognition requires a term GPA of 3.50 or higher with a minimum of 12 graded credits. This transcript reflects the complete academic record as of the issue date.",
    terms: Array.isArray(clientPayload.terms) ? clientPayload.terms : [],
    footer: {
      notice: "This transcript is confidential and is released only upon the written request of the student or as permitted by law. Alteration or reproduction of this document is a violation of Institute policy and may constitute a criminal offence. Official transcripts are invalid without the raised seal of the Institute.",
      verifyLine: "viewblock.io/arweave"
    },
    revocation: { appTag: DEGREE_APP_TAG, type: "RevocationList" }
  };
}

/* =========================================================
   RUDRAKSHA DEPLOY ENDPOINT
   ========================================================= */
app.post('/deploy', requireAuth, upload.any(), async (req, res) => {
  try {
    const user = req.user;
    const { studentName, fatherName, motherName, dob, rollNo, regNo,
            degreeName, major, gpa, percentage, passYear, issueDate, certNo,
            templateType = 'degree' } = req.body;

    if (!studentName || !certNo || !req.files || req.files.length === 0)
      return res.status(400).json({ error: 'Missing studentName/certNo/photo' });

    const template = getUserTemplate(user, templateType);
    const walletPath = userWalletPath(user);
    const templateHtmlPath = path.join(__dirname, user.dir, template.pdfHtml);

    if (!fs.existsSync(walletPath)) return res.status(500).json({ error: 'Wallet missing' });
    if (!fs.existsSync(templateHtmlPath)) return res.status(500).json({ error: 'Template missing' });

    const jobId = Date.now().toString(36) + Math.random().toString(36).slice(2,7);
    const job = { userId: user.id, current: 0, completed: [], finished: false,
      manifestUrl: null, qrCode: null, pdfUrl: null, pdfFilename: null,
      pdfPath: null, error: null };
    jobs.set(jobId, job);
    res.json({ jobId });

    (async () => {
      const uploadedPaths = {};
      const imageTxIds = {};
      try {
        job.current = 0;
        for (const file of req.files) {
          const out = file.path + '.jpg';
          await sharp(file.path).resize({ width: 800, withoutEnlargement: true }).jpeg({ quality: 75, mozjpeg: true }).toFile(out);
          fs.unlinkSync(file.path);
          uploadedPaths[file.fieldname] = out;
        }
        job.completed.push(0);

        let step = 1;
        for (const [field, filePath] of Object.entries(uploadedPaths)) {
          job.current = step;
          imageTxIds[field] = await uploadFileCLI(filePath, 'image/jpeg', walletPath, user.parentFolderId);
          job.completed.push(step++);
        }

        job.current = step;
        const metadata = { certNo, studentName, fatherName, motherName, dob, rollNo, regNo,
          degreeName, major, gpa, percentage, passYear, issueDate, issuedAt: new Date().toISOString() };
        const metaPath = path.join(tempDir, `metadata-${jobId}.json`);
        fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));
        const jsonTx = await uploadFileCLI(metaPath, 'application/json', walletPath, user.parentFolderId);
        fs.unlinkSync(metaPath);
        job.completed.push(step++);

        job.current = step;
        const manifest = {
          manifest: 'arweave/paths', version: '0.1.0',
          index: { path: 'verification.html' },
          paths: { 'verification.html': { id: template.viewerTxId }, 'metadata.json': { id: jsonTx } }
        };
        for (const [field, txId] of Object.entries(imageTxIds)) {
          const base = field.replace(/Image$/i,'') || field;
          manifest.paths[`${base}.jpg`] = { id: txId };
        }
        const manifestPath = path.join(tempDir, `manifest-${jobId}.json`);
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
        const manifestTx = await uploadFileCLI(manifestPath, 'application/x.arweave-manifest+json', walletPath, user.parentFolderId);
        fs.unlinkSync(manifestPath);
        job.completed.push(step++);

        job.current = step;
        const manifestUrl = `https://arweave.net/${manifestTx}`;
        const qrDataUrl = await QRCode.toDataURL(manifestUrl, { errorCorrectionLevel: 'H', margin: 1, width: 400 });
        job.manifestUrl = manifestUrl; job.qrCode = qrDataUrl;
        job.completed.push(step++);

        job.current = step;
        const safeCert = certNo.replace(/[^a-zA-Z0-9_-]/g,'_');
        const pdfFilename = `Degree_${safeCert}.pdf`;
        const pdfPath = path.join(tempDir, `${jobId}-${pdfFilename}`);
        const photoField = Object.keys(uploadedPaths)[0];
        await generateDegreePDF(metadata, uploadedPaths[photoField], qrDataUrl, pdfPath, templateHtmlPath);
        job.pdfPath = pdfPath; job.pdfUrl = `/download/${jobId}`; job.pdfFilename = pdfFilename;
        job.completed.push(step++);

        for (const p of Object.values(uploadedPaths)) { try { fs.unlinkSync(p); } catch(_){} }

        try {
          const db = getDatabaseForUser(user);
          db.prepare(`INSERT INTO certificates (certno, studentName, rollNo, regNo, degreeName, major, gpa, percentage, passYear, arweave_url, pdf_url)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
            certNo, studentName, rollNo || '', regNo || '', degreeName || '',
            major || '', gpa || '', percentage || '', passYear || '',
            manifestUrl, `/download/${jobId}`);
          db.close();
        } catch (e) { console.error('DB insert failed:', e.message); }

        job.finished = true;
        job.completed.push(step);
      } catch (err) {
        console.error('Deploy failed:', err);
        job.error = err.message || String(err);
        job.finished = true;
        for (const p of Object.values(uploadedPaths)) { try { fs.unlinkSync(p); } catch(_){} }
      }
    })();
  } catch (err) {
    console.error('Sync error:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

/* =========================================================
   DEGREE DEPLOY ENDPOINT
   ========================================================= */
app.post('/deploy-degree', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const clientPayload = req.body || {};

    if (!clientPayload.identityHash || !clientPayload.record || !Array.isArray(clientPayload.terms))
      return res.status(400).json({ error: 'Invalid payload' });
    if (clientPayload.terms.length === 0)
      return res.status(400).json({ error: 'At least one term with a course is required' });

    const template = getUserTemplate(user, 'degree');
    const walletPath = userWalletPath(user);
    if (!fs.existsSync(walletPath)) return res.status(500).json({ error: 'Wallet missing' });
    if (!template.viewerTxId) return res.status(500).json({ error: 'Degree template TxId missing' });

    const jobId = Date.now().toString(36) + Math.random().toString(36).slice(2,7);
    const job = { userId: user.id, current: 0, completed: [], finished: false,
      manifestUrl: null, qrCode: null, error: null };
    jobs.set(jobId, job);
    res.json({ jobId });

    (async () => {
      try {
        job.current = 1;
        const degreeJson = buildDegreeJson(clientPayload);
        const jsonPath = path.join(tempDir, `degree-${jobId}.json`);
        fs.writeFileSync(jsonPath, JSON.stringify(degreeJson, null, 2));
        job.completed.push(0);

        job.current = 2;
        const jsonTx = await uploadFileCLI(jsonPath, 'application/json', walletPath, user.parentFolderId);
        fs.unlinkSync(jsonPath);
        job.completed.push(1);

        job.current = 3;
        const manifest = {
          manifest: 'arweave/paths', version: '0.1.0',
          index: { path: 'verification.html' },
          paths: { 'verification.html': { id: template.viewerTxId }, 'degree.json': { id: jsonTx } }
        };
        const manifestPath = path.join(tempDir, `manifest-degree-${jobId}.json`);
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
        job.completed.push(2);

        job.current = 4;
        const manifestTx = await uploadFileCLI(manifestPath, 'application/x.arweave-manifest+json', walletPath, user.parentFolderId);
        fs.unlinkSync(manifestPath);
        job.completed.push(3);

        job.current = 5;
        const manifestUrl = `https://arweave.net/${manifestTx}`;
        job.qrCode = await QRCode.toDataURL(manifestUrl, { errorCorrectionLevel: 'H', margin: 1, width: 400 });
        job.manifestUrl = manifestUrl;
        job.completed.push(4);

        try {
          const db = getDegreeDatabaseForUser(user);
          db.prepare(`INSERT INTO degrees
            (student_name, symbol_no, dob, programme, faculty, date_issued, academic_standing,
             identity_hash, arweave_json_tx, manifest_tx, manifest_url)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
            clientPayload.studentName || '',
            clientPayload.symbolNo    || '',
            clientPayload.dob         || '',
            degreeJson.record.programme,
            degreeJson.record.faculty,
            degreeJson.record.dateIssued,
            degreeJson.record.academicStanding,
            degreeJson.identityHash,
            jsonTx,
            manifestTx,
            manifestUrl);
          db.close();
          console.log('Degree saved to DB:', clientPayload.symbolNo);
        } catch (e) { console.error('Degree DB insert failed:', e.message); }

        job.finished = true;
        job.completed.push(5);
      } catch (err) {
        console.error('Degree deploy failed:', err);
        job.error = err.message || String(err);
        job.finished = true;
      }
    })();
  } catch (err) {
    console.error('Deploy-degree sync error:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

/* =========================================================
   REVOKE DEGREE ENDPOINT — uses Turbo SDK
   ========================================================= */
app.post('/revoke-degree', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { manifestTx, password } = req.body || {};

    if (!manifestTx || !password)
      return res.status(400).json({ error: 'Missing manifestTx or password' });

    if (!bcrypt.compareSync(String(password), user.passwordHash))
      return res.status(401).json({ error: 'Incorrect password' });

    const db = getDegreeDatabaseForUser(user);
    const row = db.prepare('SELECT * FROM degrees WHERE manifest_tx = ?').get(manifestTx);
    if (!row) { db.close(); return res.status(404).json({ error: 'Degree record not found' }); }
    if (row.revoked) { db.close(); return res.status(400).json({ error: 'Already revoked' }); }

    let existing = { listTxId: null, revoked: [] };
    try { existing = await fetchLatestRevocationList(); }
    catch (err) { console.warn('Could not fetch existing revocation list:', err.message); }

    const revoked = Array.isArray(existing.revoked) ? existing.revoked.slice() : [];
    if (!revoked.includes(manifestTx)) revoked.push(manifestTx);

    const listPayload = {
      appTag: DEGREE_APP_TAG, type: 'RevocationList',
      issuerWallet: ISSUER_WALLET,
      updatedAt: new Date().toISOString(),
      previousListTx: existing.listTxId || null,
      revoked
    };

    const listPath = path.join(tempDir, `revocation-${Date.now()}.json`);
    fs.writeFileSync(listPath, JSON.stringify(listPayload, null, 2));

    const walletPath = userWalletPath(user);
    const tags = [
      { name: 'App-Name', value: DEGREE_APP_TAG },
      { name: 'Type',     value: 'RevocationList' },
      { name: 'Content-Type', value: 'application/json' },
      { name: 'Issuer',   value: ISSUER_WALLET }
    ];

    let listTx;
    try { listTx = await uploadWithTurboSDK(listPath, 'application/json', walletPath, tags); }
    finally { try { fs.unlinkSync(listPath); } catch(_){} }

    db.prepare('UPDATE degrees SET revoked = 1, revoked_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.id);
    db.close();

    console.log('Revoked:', manifestTx, 'via list TX:', listTx);
    res.json({ success: true, manifestTx, revocationListTx: listTx,
      revocationListUrl: `https://arweave.net/${listTx}`, totalRevoked: revoked.length });
  } catch (err) {
    console.error('Revoke failed:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

/* =========================================================
   DOWNLOAD DEGREE CERTIFICATE PDF  (NEW)
   ========================================================= */
app.get('/download-degree/:id', requireAuth, async (req, res) => {
  try {
    const db = getDegreeDatabaseForUser(req.user);
    const row = db.prepare('SELECT * FROM degrees WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'Degree record not found' });

    // Fetch the exact on-chain degree.json (contains terms, gradePoints, legendNote, etc.)
    const degreeJson = await fetchDegreeJsonFromArweave(row.arweave_json_tx);

    const pdfPath = path.join(tempDir, `degree-cert-${row.id}-${Date.now()}.pdf`);
    await generateDegreeCertificatePDF(row, degreeJson, row.manifest_url, pdfPath);

    const safe = String(row.symbol_no || row.id).replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `HIST_Degree_${safe}.pdf`;

    res.download(pdfPath, filename, (err) => {
      try { fs.unlinkSync(pdfPath); } catch (_) {}
    });
  } catch (err) {
    console.error('Degree PDF download failed:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

/* =========================================================
   RECORDS + DOWNLOAD
   ========================================================= */
app.get('/api/records', requireAuth, (req, res) => {
  try {
    const db = getDatabaseForUser(req.user);
    const records = db.prepare('SELECT * FROM certificates ORDER BY created_at DESC').all();
    db.close();
    res.json({ records });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/degree-records', requireAuth, (req, res) => {
  try {
    const db = getDegreeDatabaseForUser(req.user);
    const records = db.prepare('SELECT * FROM degrees ORDER BY created_at DESC').all();
    db.close();
    res.json({ records });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/download/:jobId', requireAuth, (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job || job.userId !== req.user.id || !job.pdfPath || !fs.existsSync(job.pdfPath))
    return res.status(404).json({ error: 'PDF not found' });
  res.download(job.pdfPath, job.pdfFilename);
});

/* ---------- error handler ---------- */
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));