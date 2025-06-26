const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../logger');

<<<<<<< HEAD
=======
// Aiven CA certificate (replace with actual CA certificate content from Aiven)
const caCert = `-----BEGIN CERTIFICATE-----
MIIETTCCArWgAwIBAgIUee0UZan+ruOAfVHUAkACa9wcLKgwDQYJKoZIhvcNAQEM
BQAwQDE+MDwGA1UEAww1MGUwY2YzOWUtOThmYS00YTAyLTgyNDktZTU2OTc2OWVk
OTE4IEdFTiAxIFByb2plY3QgQ0EwHhcNMjUwNDIzMjEzNDM3WhcNMzUwNDIxMjEz
NDM3WjBAMT4wPAYDVQQDDDUwZTBjZjM5ZS05OGZhLTRhMDItODI0OS1lNTY5NzY5
ZWQ5MTggR0VOIDEgUHJvamVjdCBDQTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
AYoCggGBANb5FFF+gfyA+gnuMHNwu5i47G8ekXzP01E/3aEgjUyhtG+PQmO17HWs
AHhHZwWZ2z/5qnhygaWOUOLma8N14PI6YUzoua1BzriY5XB9Yx7sTJ0yzRjLhkPr
C5Ht+pMzIs7m7fHOTNTb2DT15oE60xeYYZsnAOYPef4DxTACdZeQyXVbJ9rAUQ5T
fTQx8UyKQiIyaKqo8pR0IeVm3zuJADMt6ttDPJGx3+VOSD4ktnLamk1xiYS+M95I
LbpQGveWSJPbA7G2ZeMQqmtwZfxcuVUM4YgYFM/EbXAW+PzhxUGYxzByiFZ0vmp3
OODR23VorwwTrWF9STKBmgit8UQorJi8A/S+708iktQGQVtUhOybAKgKTd1N/b9F
ykWpv5AlEKdqqlix7gKBV36h3lDXupjXh27ARmBgYvtQkjg0ULJ+WPyg+2HLvvqO
wgx0i16/3bIuqIyhzNUvj7y2Aj2bEAr/F3yLkhuqqPQv6fRloBO8AvEu6cjJuPw1
QrQYztMhRQIDAQABoz8wPTAdBgNVHQ4EFgQU/eCV06cklsa0cm8VP79sLabTpigw
DwYDVR0TBAgwBgEB/wIBADALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQEMBQADggGB
AH1T4FT5IUaQoT7DQNJE/oyJqBHaC1JrY4kjkMM4S7ctifLolqlCh2nUREzO/lrl
n1ATPu9T84xyzoQpPXmcJvGG80gWVdTxZHK5F0CGv0/0J3cwvhRbQ9WofLJFm5jl
yhr3mNzMj8CFScT08GGx1DxP3XQUEI+6Ua7SuphnweRahhLXKTm/QHp9H6gI9Wf9
jQ37AVDWzYykzzlj4dJg5jxU3cDvNzauSVr5cA+eP0aw3XfFDRws16gm3qVCSctX
UxGPLQgs6d74GA/1pMiJ/hNFC2GYz47ofenKadq45WoonUX/OAh0W4ZyI3KQgX1z
syXvxcnTo6SZTc3YHNGs4MxoGUbNCeV8rkUCbIhWsr8pWyvbc62gf2tGC3c1BTyU
SFhnNge+IezKTVLBW2l+zsp+67naq5XwLRJTso7++BxbcVe/5d8faFc9xSGfSbkK
E4tuw5T0n7RSodCZAci1bBwJ+fs4ht43sHIr+JQ9+FXPtvLbRMlPhVDpX8GKHC5t
vw==
-----END CERTIFICATE-----`;

>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
let pool;

try {
  pool = mysql.createPool({
<<<<<<< HEAD
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
=======
    host: process.env.MYSQL_HOST || 'mysql-36f70339-nadderikarim-1747.f.aivencloud.com',
    port: parseInt(process.env.MYSQL_PORT) || 10419,
    user: process.env.MYSQL_USER || 'avnadmin',
    password: process.env.MYSQL_PASSWORD || 'AVNS_SonSd1S5r3eXqZyL6bi',
    database: process.env.MYSQL_DATABASE || 'defaultdb',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: process.env.MYSQL_SSL === 'true' ? { ca: caCert } : false,
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
  });

  pool.getConnection()
    .then(() => logger.info('Database connected successfully'))
    .catch((err) => {
      logger.error('Database connection failed', {
        error: err.message,
<<<<<<< HEAD
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        database: process.env.DB_NAME,
=======
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        database: process.env.MYSQL_DATABASE,
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
      });
      throw err;
    });
} catch (err) {
  logger.error('Error initializing database pool', {
    error: err.message,
<<<<<<< HEAD
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
=======
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    database: process.env.MYSQL_DATABASE,
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
  });
  throw err;
}

<<<<<<< HEAD
module.exports = pool;
=======
module.exports = pool;
>>>>>>> da8dab252f709a019c06b973c34d591887ccad2e
