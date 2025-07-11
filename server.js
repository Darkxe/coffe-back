const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const logger = require('./logger');
const db = require('./config/db');
const validate = require('./middleware/validate');
const themeValidate = require('./middleware/themeValidate');
const fs = require('fs').promises;
const multer = require('multer');

const app = express();
const server = http.createServer(app);

// Ensure upload directory is writable
const uploadDir = '/app/public/uploads';
fs.mkdir(uploadDir, { recursive: true })
  .then(async () => {
    try {
      const testFile = path.join(uploadDir, '.test-write');
      await fs.writeFile(testFile, 'test');
      await fs.unlink(testFile);
      logger.info('Upload directory created and writable', { path: uploadDir });
    } catch (err) {
      logger.error('Upload directory not writable', { error: err.message, path: uploadDir });
    }
  })
  .catch(err => {
    logger.error('Failed to create uploads directory', { error: err.message });
  });

// Configure multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|ico/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only .jpg, .jpeg, .png, and .ico files are allowed'));
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

app.set('upload', upload);

// CORS configuration
const corsOptions = {
  origin: ['https://coffe-front.vercel.app', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id'],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

// Log all incoming requests
app.use((req, res, next) => {
  logger.info('Received request', {
    method: req.method,
    url: req.url,
    headers: req.headers,
    origin: req.headers.origin,
  });
  res.on('finish', () => {
    logger.info('Response sent', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
    });
  });
  next();
});

const io = new Server(server, {
  cors: corsOptions,
  path: '/socket.io/',
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

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
      logger.warn('Invalid JWT', { error: error.message });
    }
  } else {
    logger.debug('No token provided', { path: req.url });
  }
  next();
});

// Health check
app.get('/health', (req, res) => {
  logger.info('Health check requested');
  res.status(200).json({ status: 'OK', environment: process.env.NODE_ENV || 'production' });
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
const themeRoutes = require('./routes/themeRoutes');

app.use('/api', authRoutes);
app.use('/api', menuRoutes);
app.use('/api', orderRoutes);
app.use('/api', reservationRoutes);
app.use('/api', promotionRoutes);
app.use('/api', analyticsRoutes);
app.use('/api', notificationRoutes);
app.use('/api', bannerRoutes);
app.use('/api', breakfastRoutes);
app.use('/api', themeRoutes);

// Validations middleware
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
  } else if (req.path.includes('/theme')) {
    return themeValidate(req, res, next);
  }
  next();
});

// Debug uploads
app.get('/api/debug/uploads', async (req, res) => {
  try {
    const files = await fs.readdir(uploadDir);
    logger.info('Listing uploads', { files });
    res.json({ files });
  } catch (error) {
    logger.error('Error listing uploads', { error: error.message });
    res.status(500).json({ error: 'Failed to list uploads' });
  }
});

// Log registered routes
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
  logger.error('Server error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
  });
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  logger.warn('Route not found', { method: req.method, url: req.url });
  res.status(404).json({ error: 'Not found' });
});

io.on('connection', (socket) => {
  logger.info('New socket connection', { id: socket.id });
  socket.on('join-session', async (data) => {
    const { token, sessionId } = data;
    if (!token && !sessionId) {
      logger.warn('No token or sessionId for socket', { socketId: socket.id });
      socket.emit('auth-error', { message: 'No token or session ID' });
      return;
    }
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
        const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [decoded.id]);
        if (rows.length > 0 && ['admin', 'server'].includes(rows[0].role)) {
          socket.join('staff-notifications');
          logger.info('Socket joined staff-notifications', { socketId: socket.id, userId: decoded.id });
        } else {
          logger.warn('Unauthorized socket join', { socketId: socket.id });
          socket.emit('auth-error', { message: 'Unauthorized' });
        }
      } catch (error) {
        logger.warn('Invalid JWT for socket', { error: error.message });
        socket.emit('auth-error', { message: 'Invalid token' });
      }
    } else if (sessionId && typeof sessionId === 'string' && sessionId.trim()) {
      socket.join(`guest-${sessionId}`);
      logger.info('Guest socket joined', { socketId: socket.id, sessionId });
    } else {
      logger.warn('Invalid sessionId', { socketId: socket.id });
      socket.emit('auth-error', { message: 'Invalid session ID' });
    }
  });

  socket.on('disconnect', () => {
    logger.info('Socket disconnected', { socketId: socket.id });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', async () => {
  try {
    logger.info('Attempting database connection', {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      database: process.env.DB_NAME,
    });
    const [rows] = await db.query('SELECT 1');
    logger.info('Database connection successful', { result: rows });
    logger.info(`Server running on http://0.0.0.0:${PORT} in ${process.env.NODE_ENV || 'production'}`);
  } catch (error) {
    logger.error('Failed to connect to database', { error: error.message, stack: error.stack });
    process.exit(1);
  }
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason.message || reason, promise });
  process.exit(1);
});
