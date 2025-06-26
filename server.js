const express = require('express');
<<<<<<< HEAD
=======
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
<<<<<<< HEAD
const jwt = require('jsonwebtoken');
=======
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
const logger = require('./logger');
const db = require('./config/db');
const validate = require('./middleware/validate');

const app = express();
const server = http.createServer(app);

const allowedOrigins = [
<<<<<<< HEAD
  'http://localhost:5173',
  'http://192.168.43.22:5173',
  /^http:\/\/192\.168\.1\.\d{1,3}:5173$/
=======
  process.env.FRONTEND_URL || 'https://coffe-front.vercel.app',
  'https://coffe-front.vercel.app', // Explicitly allow Vercel URL
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
];

const corsOptions = {
  origin: (origin, callback) => {
<<<<<<< HEAD
    if (!origin) return callback(null, true);
    if (allowedOrigins.some(allowed => typeof allowed === 'string' ? allowed === origin : allowed.test(origin))) {
=======
    logger.info('CORS check', { origin, allowedOrigins });
    if (!origin || allowedOrigins.includes(origin)) {
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
      callback(null, true);
    } else {
      logger.warn('CORS blocked', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
<<<<<<< HEAD
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id'],
  credentials: true
=======
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id'],
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
};

app.use(cors(corsOptions));

<<<<<<< HEAD
const io = new Server(server, {
  cors: {
    ...corsOptions,
    credentials: true
  },
  path: '/socket.io/'
});
=======
const io = new Server(server, { cors: corsOptions });

const sessionStore = new MySQLStore({
  host: process.env.MYSQL_HOST || 'mysql-36f70339-nadderikarim-1747.f.aivencloud.com',
  port: parseInt(process.env.MYSQL_PORT) || 10419,
  user: process.env.MYSQL_USER || 'avnadmin',
  password: process.env.MYSQL_PASSWORD || 'AVNS_SonSd1S5r3eXqZyL6bi',
  database: process.env.MYSQL_DATABASE || 'defaultdb',
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 86400000,
  createDatabaseTable: true,
}, db);
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

<<<<<<< HEAD
// JWT Middleware
app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (!token || token === 'null' || token === 'undefined' || !token.trim()) {
      logger.warn('Empty or invalid token received', { token: token || 'none' });
      return next();
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
      req.user = decoded;
      logger.debug('JWT verified', { userId: decoded.id, email: decoded.email });
    } catch (error) {
      logger.warn('Invalid JWT', { error: error.message, token: token.substring(0, 10) + '...' });
    }
  } else {
    logger.debug('No token provided in request', { path: req.url });
  }
  logger.info('Incoming request', {
    method: req.method,
    url: req.url,
    user: req.user ? req.user.id : 'anonymous',
=======
app.use(
  session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET || 'your_secure_secret_key',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    },
  })
);

app.use((req, res, next) => {
  logger.info('Incoming request', {
    method: req.method,
    url: req.url,
    user: req.session?.user?.id || 'anonymous',
    sessionID: req.sessionID || 'no-session',
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
    origin: req.headers.origin,
  });
  next();
});

// Routes
const authRoutes = require('./routes/authRoutes');
const menuRoutes = require('./routes/menuRoutes');
const orderRoutes = require('./routes/orderRoutes')(io);
const reservationRoutes = require('./routes/reservationRoutes')(io);
const promotionRoutes = require('./routes/promotionRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const bannerRoutes = require('./routes/bannerRoutes');
const breakfastRoutes = require('./routes/breakfastRoutes');

app.use('/api', authRoutes);
app.use('/api', menuRoutes);
app.use('/api', orderRoutes);
app.use('/api', reservationRoutes);
app.use('/api', promotionRoutes);
app.use('/api', analyticsRoutes);
app.use('/api', notificationRoutes);
app.use('/api', bannerRoutes);
app.use('/api', breakfastRoutes);

// Apply validations middleware
app.use('/api', (req, res, next) => {
  if (
    req.method === 'POST' ||
    req.method === 'PUT' ||
    req.method === 'DELETE' ||
    (req.method === 'GET' && (
      req.path.includes('/menu-items') ||
      req.path.includes('/categories') ||
      req.path.includes('/ratings') ||
      req.path.includes('/tables') ||
      req.path.includes('/notifications') ||
      req.path.includes('/banners') ||
      req.path.includes('/breakfasts')
    ))
  ) {
    if (req.path.includes('/menu-items') || req.path.includes('/categories') || req.path.includes('/banners') || req.path.includes('/breakfasts')) {
      if (req.headers['content-type']?.includes('multipart/form-data')) {
        return next();
      }
    }
    return validate(req, res, next);
  }
  next();
});

function logRoutes() {
  app._router?.stack?.forEach((layer) => {
    if (layer.route) {
      logger.info('Registered route', {
        method: layer.route.stack[0].method.toUpperCase(),
        path: layer.route.path,
      });
    } else if (layer.name === 'router' && layer.handle.stack) {
      const prefix = layer.regexp.source
        .replace(/\\\//g, '/')
        .replace(/^\/\^/, '')
        .replace(/\/\?\(\?=\/\|\$\)/, '');
      layer.handle.stack.forEach((handler) => {
        if (handler.route) {
          logger.info('Registered route', {
            method: handler.route.stack[0].method.toUpperCase(),
            path: prefix + handler.route.path,
          });
        }
      });
    }
  });
}

logRoutes();

app.use((err, req, res, next) => {
<<<<<<< HEAD
  if (err.code === 'ECONNABORTED') {
    logger.error('Request aborted', {
      method: req.method,
      url: req.url,
      user: req.user ? req.user.id : 'anonymous',
      origin: req.headers.origin,
    });
  }
=======
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
  logger.error('Server error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
<<<<<<< HEAD
    user: req.user ? req.user.id : 'anonymous',
=======
    user: req.session?.user?.id || 'anonymous',
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
    origin: req.headers.origin,
  });
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  logger.warn('Route not found', {
    method: req.method,
    url: req.url,
<<<<<<< HEAD
    user: req.user ? req.user.id : 'anonymous',
=======
    user: req.session?.user?.id || 'anonymous',
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
    origin: req.headers.origin,
  });
  res.status(404).json({ error: 'Not found' });
});

io.on('connection', (socket) => {
  logger.info('New socket connection', { id: socket.id });

<<<<<<< HEAD
  socket.on('join-session', async (data) => {
    const { token, sessionId } = data;
    if (!token && !sessionId) {
      logger.warn('No token or sessionId provided for socket session', { socketId: socket.id });
      socket.emit('auth-error', { message: 'No token or session ID provided' });
      return;
    }
    if (token) {
      if (typeof token !== 'string' || !token.trim()) {
        logger.warn('Invalid token provided for socket session', { socketId: socket.id });
        socket.emit('auth-error', { message: 'Invalid or empty token' });
        return;
      }
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
        const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [decoded.id]);
        if (rows.length > 0 && ['admin', 'server'].includes(rows[0].role)) {
          socket.join('staff-notifications');
          logger.info('Socket joined staff-notifications room', { socketId: socket.id, userId: decoded.id, role: rows[0].role });
        } else {
          logger.warn('Unauthorized socket join attempt', { socketId: socket.id, userId: decoded.id });
          socket.emit('auth-error', { message: 'Unauthorized access' });
        }
      } catch (error) {
        logger.warn('Invalid JWT for socket session', { error: error.message, socketId: socket.id });
        socket.emit('auth-error', { message: 'Invalid or expired token' });
      }
    } else if (sessionId && typeof sessionId === 'string' && sessionId.trim()) {
      socket.join(`guest-${sessionId}`);
      logger.info('Guest socket joined', { socketId: socket.id, sessionId });
    } else {
      logger.warn('Invalid sessionId for socket session', { socketId: socket.id });
      socket.emit('auth-error', { message: 'Invalid session ID' });
=======
  socket.on('join-session', async (sessionId) => {
    socket.join(sessionId);
    logger.info('Socket joined session room', { socketId: socket.id, sessionId });

    try {
      const [sessionData] = await db.query('SELECT data FROM sessions WHERE session_id = ?', [sessionId]);
      if (sessionData.length > 0) {
        const session = JSON.parse(sessionData[0].data);
        if (session.user && ['admin', 'server'].includes(session.user.role)) {
          socket.join('staff-notifications');
          logger.info('Socket joined staff-notifications room', { socketId: socket.id, sessionId, role: session.user.role });
        }
      }
    } catch (error) {
      logger.error('Error checking session for staff role', { error: error.message, sessionId });
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
    }
  });

  socket.on('disconnect', () => {
    logger.info('Socket disconnected', { socketId: socket.id });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', async () => {
  try {
    await db.getConnection();
    logger.info(`Server running on port ${PORT}`);
  } catch (error) {
    logger.error('Failed to connect to database', { error: error.message });
    process.exit(1);
  }
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason.message || reason, promise });
<<<<<<< HEAD
});
=======
});
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
