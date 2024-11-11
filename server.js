const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const SECRET_KEY = 'ahademy_secret'; // Ganti dengan kunci rahasia Anda

server.use(bodyParser.json());
server.use(cookieParser());
server.use(middlewares);

// Fungsi untuk membuat token
const createToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: '1h',
  });
};

// Login endpoint
server.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = router.db;
  const user = db.get('users').find({ email, password }).value();

  if (user) {
    const token = createToken(user);
    res.cookie('token', token, { httpOnly: true }); // Set cookie JWT
    res.status(200).json({ message: 'Login successful', user });
  } else {
    res.status(401).json({ error: 'Invalid email or password' });
  }
});

// Signup endpoint
server.post('/signup', (req, res) => {
  const { name, email, password, phone } = req.body;
  const db = router.db;
  const existingUser = db.get('users').find({ email }).value();

  if (existingUser) {
    res.status(400).json({ error: 'Email already exists' });
  } else {
    const newUser = {
      id: db.get('users').size().value() + 1,
      name,
      email,
      password,
      phone,
    };
    db.get('users').push(newUser).write();
    const token = createToken(newUser);
    res.cookie('token', token, { httpOnly: true }); // Set cookie JWT
    res.status(201).json({ message: 'Signup successful', user: newUser });
  }
});

// Logout endpoint
server.post('/logout', (req, res) => {
  res.clearCookie('token'); // Hapus cookie JWT
  res.status(200).json({ message: 'Logout successful' });
});

// Middleware untuk memverifikasi token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Endpoint untuk mendapatkan data pengguna setelah login/signup
server.get('/me', verifyToken, (req, res) => {
  const db = router.db;
  const user = db.get('users').find({ id: req.userId }).value();
  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404).json({ error: 'User  not found' });
  }
});

// Use default router
server.use(router);

// Start the server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`JSON Server is running on http://localhost:${PORT}`);
});
