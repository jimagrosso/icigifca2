const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const Datastore  = require('nedb');
const path       = require('path');
const cors       = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

const db = new Datastore({ filename: path.join(__dirname, 'campus.db'), autoload: true });
db.ensureIndex({ fieldName: 'correo', unique: true });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));
app.use(session({
  secret: 'icigifca-campus-2025-secret', resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 7*24*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, '..')));

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'No autenticado' });
}

function safeUser(u) {
  return { id: u._id, nombre_completo: u.nombre_completo, correo: u.correo,
           perfil_profesional: u.perfil_profesional, pais: u.pais,
           telefono: u.telefono, cedula: u.cedula, paid: u.paid };
}

app.post('/api/register', async (req, res) => {
  const { nombre_completo, cedula, pais, telefono, correo, password, perfil_profesional } = req.body;
  if (!nombre_completo||!cedula||!pais||!telefono||!correo||!password||!perfil_profesional)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  if (password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener mínimo 6 caracteres' });
  try {
    const password_hash = await bcrypt.hash(password, 12);
    db.insert({ nombre_completo, cedula, pais, telefono, correo: correo.toLowerCase().trim(),
      password_hash, perfil_profesional, paid: false, created_at: new Date().toISOString() },
      (err, doc) => {
        if (err) return res.status(err.errorType==='uniqueViolated'?409:500).json({ error: err.errorType==='uniqueViolated'?'Este correo ya está registrado':'Error al guardar' });
        req.session.userId = doc._id; req.session.user = safeUser(doc);
        res.json({ ok: true, redirect: '/panel.html' });
      });
  } catch(e) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/api/login', (req, res) => {
  const { correo, password } = req.body;
  if (!correo||!password) return res.status(400).json({ error: 'Correo y contraseña requeridos' });
  db.findOne({ correo: correo.toLowerCase().trim() }, async (err, user) => {
    if (err||!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
    req.session.userId = user._id; req.session.user = safeUser(user);
    res.json({ ok: true, redirect: '/panel.html' });
  });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ ok: true, user: req.session.user }));

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.listen(PORT, () => {
  console.log(`\n✅  ICIGIFCA Campus → http://localhost:${PORT}`);
  console.log(`    registro : http://localhost:${PORT}/registro.html`);
  console.log(`    login    : http://localhost:${PORT}/login.html`);
  console.log(`    panel    : http://localhost:${PORT}/panel.html\n`);
});
