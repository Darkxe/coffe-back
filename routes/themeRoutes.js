const express = require('express');
const router = express.Router();
const db = require('../config/db');
const jwt = require('jsonwebtoken');
const themeValidate = require('../middleware/themeValidate');
const path = require('path');

// Middleware to verify admin role
const validateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Get current theme
router.get('/theme', async (req, res) => {
  try {
    const [theme] = await db.query('SELECT * FROM themes ORDER BY updated_at DESC LIMIT 1');
    if (!theme.length) {
      // Insert default theme if none exists
      const defaultTheme = {
        primary_color: '#ff6b35',
        secondary_color: '#ff8c42',
        background_color: '#faf8f5',
        text_color: '#1f2937',
        site_title: 'Café Local',
      };
      await db.query(
        'INSERT INTO themes (primary_color, secondary_color, background_color, text_color, site_title, admin_id) VALUES (?, ?, ?, ?, ?, NULL)',
        [defaultTheme.primary_color, defaultTheme.secondary_color, defaultTheme.background_color, defaultTheme.text_color, defaultTheme.site_title]
      );
      return res.json(defaultTheme);
    }
    res.json(theme[0]);
  } catch (error) {
    console.error('Error fetching theme:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update theme colors (admin only)
router.put('/theme', validateAdmin, themeValidate, async (req, res) => {
  const { primary_color, secondary_color, background_color, text_color, site_title } = req.body;
  try {
    const [existingTheme] = await db.query('SELECT id FROM themes ORDER BY updated_at DESC LIMIT 1');
    if (!existingTheme.length) {
      // Insert new theme if none exists
      await db.query(
        'INSERT INTO themes (primary_color, secondary_color, background_color, text_color, site_title, admin_id) VALUES (?, ?, ?, ?, ?, ?)',
        [primary_color || '#ff6b35', secondary_color || '#ff8c42', background_color || '#faf8f5', text_color || '#1f2937', site_title || 'Café Local', req.user.id]
      );
    } else {
      // Update existing theme
      const [result] = await db.query(
        'UPDATE themes SET primary_color = ?, secondary_color = ?, background_color = ?, text_color = ?, site_title = ?, admin_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [
          primary_color || '#ff6b35',
          secondary_color || '#ff8c42',
          background_color || '#faf8f5',
          text_color || '#1f2937',
          site_title || 'Café Local',
          req.user.id,
          existingTheme[0].id,
        ]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'No theme found' });
      }
    }
    res.json({ message: 'Theme updated successfully' });
  } catch (error) {
    console.error('Error updating theme:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update theme branding (logo, favicon, site title) - admin only
router.put('/theme/branding', validateAdmin, themeValidate, (req, res, next) => {
  const upload = req.app.get('upload');
  upload.fields([{ name: 'logo', maxCount: 1 }, { name: 'favicon', maxCount: 1 }])(req, res, async (err) => {
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({ error: err.message || 'File upload error' });
    }
    try {
      const { site_title } = req.body;
      const files = req.files || {};
      const [existingTheme] = await db.query('SELECT id, logo_url, favicon_url FROM themes ORDER BY updated_at DESC LIMIT 1');
      let logo_url = existingTheme.length ? existingTheme[0].logo_url : null;
      let favicon_url = existingTheme.length ? existingTheme[0].favicon_url : null;

      // Handle logo upload
      if (files.logo && files.logo[0]) {
        logo_url = `/uploads/${files.logo[0].filename}`;
      }

      // Handle favicon upload
      if (files.favicon && files.favicon[0]) {
        favicon_url = `/uploads/${files.favicon[0].filename}`;
      }

      if (!existingTheme.length) {
        // Insert new theme if none exists
        await db.query(
          'INSERT INTO themes (logo_url, favicon_url, site_title, primary_color, secondary_color, background_color, text_color, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [
            logo_url,
            favicon_url,
            site_title || 'Café Local',
            '#ff6b35',
            '#ff8c42',
            '#faf8f5',
            '#1f2937',
            req.user.id,
          ]
        );
      } else {
        // Update existing theme
        const [result] = await db.query(
          'UPDATE themes SET logo_url = ?, favicon_url = ?, site_title = ?, admin_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          [
            logo_url,
            favicon_url,
            site_title || existingTheme[0].site_title || 'Café Local',
            req.user.id,
            existingTheme[0].id,
          ]
        );
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'No theme found' });
        }
      }
      res.json({ message: 'Branding updated successfully', logo_url, favicon_url, site_title: site_title || existingTheme[0].site_title || 'Café Local' });
    } catch (error) {
      console.error('Error updating branding:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });
});

module.exports = router;
