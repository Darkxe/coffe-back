const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../logger');

let pool;

try {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'mysql.railway.internal',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'EGBnnTbtJEpUmdIpKjtFaEsvEERWwcyB',
    database: process.env.DB_NAME || 'railway',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 10000, // Added timeout for connection
  });

  pool.getConnection()
    .then((conn) => {
      logger.info('Database connected successfully', {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
      });
      conn.release();
    })
    .catch((err) => {
      logger.error('Database connection failed', {
        error: err.message,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        database: process.env.DB_NAME,
      });
      throw err;
    });
} catch (err) {
  logger.error('Error initializing database pool', {
    error: err.message,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
  });
  throw err;
}

module.exports = pool;
