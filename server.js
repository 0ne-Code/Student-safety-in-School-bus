'use strict';

const express      = require('express');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const fs           = require('fs');
const path         = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'school-bus-secret-change-in-prod';
const DATA_DIR   = path.join(__dirname, 'data');

// ─── Data helpers ─────────────────────────────────────────────────────────────
function dataPath(name) { return path.join(DATA_DIR, `${name}.json`); }

function read(name) {
  try { return JSON.parse(fs.readFileSync(dataPath(name), 'utf8')); }
  catch { return []; }
}

function readObj(name) {
  try { return JSON.parse(fs.readFileSync(dataPath(name), 'utf8')); }
  catch { return {}; }
}

function write(name, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(dataPath(name), JSON.stringify(data, null, 2));
}

// ─── App setup ────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function requireRole(...roles) {
  return [requireAuth, (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: 'Forbidden' });
    next();
  }];
}

// ─── POST /api/login ─────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const users = read('users');
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000   // 8 hours
  });

  res.json({ username: user.username, role: user.role });
});

// ─── GET /api/me ──────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ─── POST /api/logout ─────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// STUDENTS
// ═════════════════════════════════════════════════════════════════════════════

// GET /api/students  — admin + staff see all; parent sees only theirs
app.get('/api/students', requireAuth, (req, res) => {
  const students = read('students');
  if (req.user.role === 'parent') {
    return res.json(students.filter(s => s.parent_username === req.user.username));
  }
  res.json(students);
});

// GET /api/students/mine — convenience for parent dashboard
app.get('/api/students/mine', requireRole('parent'), (req, res) => {
  const students = read('students');
  const mine = students.find(s => s.parent_username === req.user.username);
  if (!mine) return res.status(404).json({ error: 'No student linked to this account' });
  res.json(mine);
});

// POST /api/students — admin only
app.post('/api/students', requireRole('admin'), async (req, res) => {
  const { name, class: cls, location, bus_id, parent_name, parent_phone } = req.body || {};
  if (!name || !location || !bus_id)
    return res.status(400).json({ error: 'name, location and bus_id are required' });

  const students = read('students');
  const users    = read('users');

  // Auto-generate student ID
  const nums = students
    .map(s => parseInt((s.student_id || '').replace(/\D/g, ''), 10))
    .filter(n => !isNaN(n));
  const nextNum = (nums.length ? Math.max(...nums) : 0) + 1;
  const student_id = 'STU' + String(nextNum).padStart(3, '0');

  // Auto-generate parent username: first-word-of-name + zero-padded-number
  const firstName      = name.trim().split(/\s+/)[0].toLowerCase();
  const parent_username = `${firstName}${String(nextNum).padStart(3, '0')}`;

  // Create parent account (password = username)
  const passwordHash = await bcrypt.hash(parent_username, 10);
  users.push({ username: parent_username, passwordHash, role: 'parent' });
  write('users', users);

  const student = {
    student_id,
    name,
    class:           cls    || '',
    location:        location,
    parent_name:     parent_name  || 'N/A',
    parent_phone:    parent_phone || 'N/A',
    bus_id,
    qr_code:         student_id,
    parent_username
  };

  students.push(student);
  write('students', students);

  res.status(201).json({ student, parent_username });
});

// DELETE /api/students/:id — admin only
app.delete('/api/students/:id', requireRole('admin'), (req, res) => {
  const { id } = req.params;
  let students = read('students');
  const student = students.find(s => s.student_id === id);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  // Remove student
  students = students.filter(s => s.student_id !== id);
  write('students', students);

  // Remove linked parent account
  let users = read('users');
  users = users.filter(u => u.username !== student.parent_username);
  write('users', users);

  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// BUSES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/api/buses', requireAuth, (req, res) => {
  res.json(read('buses'));
});

app.post('/api/buses', requireRole('admin'), (req, res) => {
  const { bus_id, name, route } = req.body || {};
  if (!bus_id || !name || !route)
    return res.status(400).json({ error: 'bus_id, name, and route are required' });

  const buses = read('buses');
  if (buses.find(b => b.bus_id === bus_id))
    return res.status(409).json({ error: 'Bus ID already exists' });

  const bus = { bus_id, name, route };
  buses.push(bus);
  write('buses', buses);
  res.status(201).json(bus);
});

app.delete('/api/buses/:id', requireRole('admin'), (req, res) => {
  let buses = read('buses');
  if (!buses.find(b => b.bus_id === req.params.id))
    return res.status(404).json({ error: 'Bus not found' });
  buses = buses.filter(b => b.bus_id !== req.params.id);
  write('buses', buses);
  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// BUS STATE  (live location)
// ═════════════════════════════════════════════════════════════════════════════

// GET /api/bus-state — returns an object keyed by bus_id
app.get('/api/bus-state', requireAuth, (req, res) => {
  res.json(readObj('bus-state'));
});

// GET /api/bus-state/:busId — single bus
app.get('/api/bus-state/:busId', requireAuth, (req, res) => {
  const state = readObj('bus-state');
  res.json(state[req.params.busId] || null);
});

// POST /api/bus-state — update location (staff / admin)
app.post('/api/bus-state', requireRole('admin', 'staff'), (req, res) => {
  const { bus_id, currentLocation, updateReason } = req.body || {};
  if (!bus_id || !currentLocation)
    return res.status(400).json({ error: 'bus_id and currentLocation required' });

  const state = readObj('bus-state');
  state[bus_id] = { currentLocation, lastUpdated: new Date().toISOString(), updateReason: updateReason || '' };
  write('bus-state', state);
  res.json(state[bus_id]);
});

// DELETE /api/bus-state/:busId — reset a bus location (admin)
app.delete('/api/bus-state/:busId', requireRole('admin'), (req, res) => {
  const state = readObj('bus-state');
  delete state[req.params.busId];
  write('bus-state', state);
  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// ATTENDANCE
// ═════════════════════════════════════════════════════════════════════════════

// GET /api/attendance  — admin/staff see all; parent filters to their child
app.get('/api/attendance', requireAuth, (req, res) => {
  const records = read('attendance');
  if (req.user.role === 'parent') {
    const students = read('students');
    const mine = students.find(s => s.parent_username === req.user.username);
    if (!mine) return res.json([]);
    return res.json(records.filter(r => r.student_id === mine.student_id));
  }
  res.json(records);
});

// POST /api/attendance — staff / admin  (QR scan or manual mark)
app.post('/api/attendance', requireRole('admin', 'staff'), (req, res) => {
  const { student_id, bus_id, status } = req.body || {};
  if (!student_id || !bus_id || !status)
    return res.status(400).json({ error: 'student_id, bus_id, and status are required' });

  const students = read('students');
  const student  = students.find(s => s.student_id === student_id);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  const now  = new Date();
  const date = now.toISOString().split('T')[0];

  const records = read('attendance');

  // Check for duplicate within the same day + same status
  const dup = records.find(r =>
    r.student_id === student_id &&
    r.date === date &&
    r.status === status
  );
  if (dup) return res.status(409).json({ error: 'duplicate', message: `Already marked ${status} today`, student });

  const record = {
    id:         `ATT-${Date.now()}`,
    student_id,
    bus_id,
    status,                          // 'IN' | 'OUT' | 'ABSENT'
    date,
    timestamp: now.toISOString()
  };

  records.push(record);
  write('attendance', records);

  // Auto-update bus location when a student boards (IN scan)
  if (status === 'IN' || status === 'ABSENT') {
    const state = readObj('bus-state');
    state[bus_id] = {
      currentLocation: student.location,
      lastUpdated:     now.toISOString(),
      updateReason:    `${status === 'IN' ? '📥 Boarded' : '❌ Absent'}: ${student.name}`
    };
    write('bus-state', state);
  }

  res.status(201).json({ record, student });
});

// DELETE /api/attendance/:id — admin only (undo a scan)
app.delete('/api/attendance/:id', requireRole('admin'), (req, res) => {
  let records = read('attendance');
  const before = records.length;
  records = records.filter(r => r.id !== req.params.id);
  if (records.length === before) return res.status(404).json({ error: 'Record not found' });
  write('attendance', records);
  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// USER ACCOUNTS
// ═════════════════════════════════════════════════════════════════════════════

// GET /api/users — admin only; strips password hashes
app.get('/api/users', requireRole('admin'), (req, res) => {
  const users = read('users').map(({ username, role }) => ({ username, role }));
  res.json(users);
});

// POST /api/users — admin only; create any account
app.post('/api/users', requireRole('admin'), async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || !role)
    return res.status(400).json({ error: 'username, password, and role are required' });

  const users = read('users');
  if (users.find(u => u.username === username))
    return res.status(409).json({ error: 'Username already taken' });

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash, role });
  write('users', users);

  res.status(201).json({ username, role });
});

// DELETE /api/users/:username — admin only
app.delete('/api/users/:username', requireRole('admin'), (req, res) => {
  const { username } = req.params;
  if (username === 'admin')
    return res.status(403).json({ error: 'Cannot delete the admin account' });

  let users = read('users');
  if (!users.find(u => u.username === username))
    return res.status(404).json({ error: 'User not found' });

  users = users.filter(u => u.username !== username);
  write('users', users);
  res.json({ ok: true });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚌  School Bus System running on http://localhost:${PORT}`);
});
