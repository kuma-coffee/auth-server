const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const setupSwagger = require('./swagger');
const verifyToken = require('./middlewares/authMiddleware');

const SECRET_KEY = 'ahademy_secret';

setupSwagger(server);

server.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);
server.use(bodyParser.json());
server.use(cookieParser());
server.use(middlewares);

const createToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: '1h',
  });
};

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management
 */

/**
 * @swagger
 * /login:
 *   post:
 *     tags: [Users]
 *     description: Login user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid email or password
 */

/**
 * @swagger
 * /signup:
 *   post:
 *     tags: [Users]
 *     description: Signup user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               phone:
 *                 type: string
 *     responses:
 *       201:
 *         description: Signup successful
 *       400:
 *         description: Email already exists
 */

/**
 * @swagger
 * /logout:
 *   post:
 *     tags: [Users]
 *     description: Logout user
 *     responses:
 *       200:
 *         description: Logout successful
 */

/**
 * @swagger
 * /me:
 *   get:
 *     tags: [Users]
 *     description: Get current user
 *     responses:
 *       200:
 *         description: User data
 *       403:
 *         description: No token provided
 *       401:
 *         description: Unauthorized
 */

server.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = router.db;
  const user = db.get('users').find({ email, password }).value();

  if (user) {
    const token = createToken(user);
    res.cookie('token', token, { httpOnly: true });
    res.status(200).json({ message: 'Login successful', user });
  } else {
    res.status(401).json({ error: 'Invalid email or password' });
  }
});

server.post('/signup', (req, res) => {
  const { name, email, password, phoneNumber } = req.body;
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
      phoneNumber,
    };
    db.get('users').push(newUser).write();
    const token = createToken(newUser);
    res.cookie('token', token, { httpOnly: true });
    res.status(201).json({ message: 'Signup successful', user: newUser });
  }
});

server.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'Logout successful' });
});

server.get('/me', verifyToken, (req, res) => {
  const db = router.db;
  const user = db.get('users').find({ id: req.userId }).value();
  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404).json({ error: 'User  not found' });
  }
});

server.use(router);

const PORT = 8080;
server.listen(PORT, () => {
  console.log(`JSON Server is running on http://localhost:${PORT}`);
  console.log(`Swagger docs available at http://localhost:${PORT}/api-docs`);
});
