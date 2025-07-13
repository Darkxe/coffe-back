const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const breakfastValidation = require('../middleware/breakfastValidation');

// Ensure upload directory exists
const uploadDir = '/app/public/uploads';
fs.mkdir(uploadDir, { recursive: true }).catch(err => {
  logger.error('Failed to create uploads directory', { error: err.message });
});

// Configure multer for file uploads
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Image must be JPEG or PNG'), false);
    }
  },
}).single('image');

// Middleware to check admin role
const checkAdmin = async (userId) => {
  if (!userId) return false;
  const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
  return rows.length > 0 && rows[0].role === 'admin';
};

// Middleware to log raw FormData
const logFormData = (req, res, next) => {
  if (req.headers['content-type']?.includes('multipart/form-data')) {
    const formData = req.body ? { ...req.body } : {};
    logger.info('Raw FormData request', {
      headers: req.headers,
      method: req.method,
      url: req.url,
      formData,
      file: req.file ? { name: req.file.filename, path: req.file.path } : null,
    });
  }
  next();
};

// Create breakfast
router.post('/breakfasts', breakfastValidation, upload, logFormData, async (req, res) => {
  const { user_id, name, description, price, availability, category_id } = req.body;
  const image = req.file;
  logger.info('Parsed breakfast creation request', {
    body: { user_id, name, description, price, availability, category_id },
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add breakfast', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const finalName = name && name.trim() ? name.trim() : 'Unnamed Breakfast';
    const finalPrice = price && !isNaN(parseFloat(price)) && parseFloat(price) >= 0.01 ? parseFloat(price) : 0.01;
    const parsedAvailability = availability === 'true' || availability === true;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const [result] = await db.query(
      'INSERT INTO breakfasts (name, description, price, image_url, availability, category_id) VALUES (?, ?, ?, ?, ?, ?)',
      [finalName, description || null, finalPrice, image_url, parsedAvailability, parsedCategoryId]
    );
    logger.info('Breakfast created', { id: result.insertId, name: finalName, image_url, category_id: parsedCategoryId });
    res.status(201).json({ message: 'Breakfast created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating breakfast', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to create breakfast', details: error.message });
  }
});

// Update breakfast
router.put('/breakfasts/:id', breakfastValidation, upload, logFormData, async (req, res) => {
  const { user_id, name, description, price, availability, category_id } = req.body;
  const image = req.file;
  const { id } = req.params;
  logger.info('Parsed breakfast update request', {
    params: { id },
    body: { user_id, name, description, price, availability, category_id },
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update breakfast', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const finalName = name && name.trim() ? name.trim() : 'Unnamed Breakfast';
    const finalPrice = price && !isNaN(parseFloat(price)) && parseFloat(price) >= 0.01 ? parseFloat(price) : 0.01;
    const parsedAvailability = availability === 'true' || availability === true;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    // Check for existing breakfast and its image
    const [existing] = await db.query('SELECT image_url FROM breakfasts WHERE id = ?', [breakfastId]);
    if (existing.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    // Delete old image if new image is uploaded
    const image_url = image ? `/Uploads/${image.filename}` : existing[0].image_url;
    if (image && existing[0].image_url) {
      const oldImagePath = path.join('/app/public/uploads', path.basename(existing[0].image_url));
      try {
        await fs.unlink(oldImagePath);
      } catch (err) {
        if (err.code !== 'ENOENT') {
          logger.error('Error deleting old breakfast image', { error: err.message, path: oldImagePath });
        }
      }
    }
    // Update breakfast
    const updateFields = [finalName, description || null, finalPrice, parsedAvailability, parsedCategoryId];
    let query = 'UPDATE breakfasts SET name = ?, description = ?, price = ?, availability = ?, category_id = ?';
    if (image_url) {
      query += ', image_url = ?';
      updateFields.push(image_url);
    }
    updateFields.push(breakfastId);
    const [result] = await db.query(query + ' WHERE id = ?', updateFields);
    if (result.affectedRows === 0) {
      logger.warn('Breakfast not found for update', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    logger.info('Breakfast updated', { id: breakfastId, name: finalName, image_url, category_id: parsedCategoryId });
    res.json({ message: 'Breakfast updated' });
  } catch (error) {
    logger.error('Error updating breakfast', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to update breakfast', details: error.message });
  }
});

// Delete breakfast
router.delete('/breakfasts/:id', breakfastValidation, async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete breakfast', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    // Delete associated image
    const [existing] = await db.query('SELECT image_url FROM breakfasts WHERE id = ?', [breakfastId]);
    if (existing.length && existing[0].image_url) {
      const imagePath = path.join('/app/public/uploads', path.basename(existing[0].image_url));
      try {
        await fs.unlink(imagePath);
      } catch (err) {
        if (err.code !== 'ENOENT') {
          logger.error('Error deleting breakfast image', { error: err.message, path: imagePath });
        }
      }
    }
    const [result] = await db.query('DELETE FROM breakfasts WHERE id = ?', [breakfastId]);
    if (result.affectedRows === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    logger.info('Breakfast deleted', { id: breakfastId });
    res.json({ message: 'Breakfast deleted' });
  } catch (error) {
    logger.error('Error deleting breakfast', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete breakfast', details: error.message });
  }
});

// Fetch all breakfasts
router.get('/breakfasts', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT b.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM breakfasts b
       LEFT JOIN categories c ON b.category_id = c.id
       LEFT JOIN breakfast_ratings r ON b.id = r.breakfast_id
       GROUP BY b.id`
    );
    const sanitizedRows = rows.map(item => ({
      ...item,
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    res.json(sanitizedRows);
  } catch (error) {
    logger.error('Error fetching breakfasts', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch breakfasts', details: error.message });
  }
});

// Fetch single breakfast
router.get('/breakfasts/:id', breakfastValidation, async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [rows] = await db.query(
      `SELECT b.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM breakfasts b
       LEFT JOIN categories c ON b.category_id = c.id
       LEFT JOIN breakfast_ratings r ON b.id = r.breakfast_id
       WHERE b.id = ?
       GROUP BY b.id`,
      [breakfastId]
    );
    if (rows.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const breakfast = rows[0];
    breakfast.average_rating = parseFloat(breakfast.average_rating).toFixed(1);
    breakfast.review_count = parseInt(breakfast.review_count);
    res.json(breakfast);
  } catch (error) {
    logger.error('Error fetching breakfast', { error: error.message, id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch breakfast', details: error.message });
  }
});

// Fetch related breakfasts and menu items
router.get('/breakfasts/:id/related', async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [breakfast] = await db.query(
      'SELECT category_id FROM breakfasts WHERE id = ?',
      [breakfastId]
    );
    if (!breakfast.length) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [breakfastRows] = await db.query(
      `SELECT b.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM breakfasts b
       LEFT JOIN categories c ON b.category_id = c.id
       LEFT JOIN breakfast_ratings r ON b.id = r.breakfast_id
       WHERE b.category_id = ? AND b.id != ?
       GROUP BY b.id
       LIMIT 2`,
      [breakfast[0].category_id, breakfastId]
    );
    const [menuItemRows] = await db.query(
      `SELECT mi.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM menu_items mi
       LEFT JOIN categories c ON mi.category_id = c.id
       LEFT JOIN ratings r ON mi.id = r.item_id
       WHERE mi.category_id = ?
       GROUP BY mi.id
       LIMIT 2`,
      [breakfast[0].category_id]
    );
    const sanitizedBreakfasts = breakfastRows.map(item => ({
      ...item,
      type: 'breakfast',
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    const sanitizedMenuItems = menuItemRows.map(item => ({
      ...item,
      type: 'menuItem',
      dietary_tags: item.dietary_tags && typeof item.dietary_tags === 'string' && item.dietary_tags.match(/^\[.*\]$/)
        ? item.dietary_tags
        : '[]',
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    const combinedItems = [...sanitizedBreakfasts, ...sanitizedMenuItems].slice(0, 4);
    res.json(combinedItems);
  } catch (error) {
    logger.error('Error fetching related products', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch related products', details: error.message });
  }
});

// Create option group
router.post('/breakfasts/:id/option-groups', breakfastValidation, async (req, res) => {
  const { user_id, title, is_required, max_selections } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add option group', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (!title || !title.trim()) {
      logger.warn('Missing title', { user_id });
      return res.status(400).json({ error: 'Title is required' });
    }
    const parsedIsRequired = is_required === 'true' || is_required === true;
    const parsedMaxSelections = parseInt(max_selections) || 1;
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [existingGroup] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ? AND title = ?', [breakfastId, title.trim()]);
    if (existingGroup.length > 0) {
      logger.warn('Duplicate option group title', { title, breakfast_id: breakfastId });
      return res.status(400).json({ error: 'Option group title already exists for this breakfast' });
    }
    const [result] = await db.query(
      'INSERT INTO breakfast_option_groups (breakfast_id, title, is_required, max_selections) VALUES (?, ?, ?, ?)',
      [breakfastId, title.trim(), parsedIsRequired, parsedMaxSelections]
    );
    logger.info('Option group created', { id: result.insertId, breakfast_id: breakfastId, title, is_required: parsedIsRequired, max_selections: parsedMaxSelections });
    res.status(201).json({ message: 'Option group created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating option group', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to create option group', details: error.message });
  }
});

// Update option group
router.put('/breakfasts/:breakfastId/option-groups/:groupId', breakfastValidation, async (req, res) => {
  const { user_id, title, is_required, max_selections } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update option group', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const groupId = parseInt(req.params.groupId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(groupId) || groupId <= 0) {
      logger.warn('Invalid group ID', { id: req.params.groupId });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!title || !title.trim()) {
      logger.warn('Missing title', { user_id });
      return res.status(400).json({ error: 'Title is required' });
    }
    const parsedIsRequired = is_required === 'true' || is_required === true;
    const parsedMaxSelections = parseInt(max_selections) || 1;
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [groupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: groupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [existingGroup] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ? AND title = ? AND id != ?', [breakfastId, title.trim(), groupId]);
    if (existingGroup.length > 0) {
      logger.warn('Duplicate option group title', { title, breakfast_id: breakfastId });
      return res.status(400).json({ error: 'Option group title already exists for this breakfast' });
    }
    const [result] = await db.query(
      'UPDATE breakfast_option_groups SET title = ?, is_required = ?, max_selections = ? WHERE id = ?',
      [title.trim(), parsedIsRequired, parsedMaxSelections, groupId]
    );
    logger.info('Option group updated', { id: groupId, breakfast_id: breakfastId, title, is_required: parsedIsRequired, max_selections: parsedMaxSelections });
    res.json({ message: 'Option group updated' });
  } catch (error) {
    logger.error('Error updating option group', { error: error.message, breakfast_id: req.params.breakfastId, group_id: req.params.groupId });
    res.status(500).json({ error: 'Failed to update option group', details: error.message });
  }
});

// Delete option group
router.delete('/breakfasts/:breakfastId/option-groups/:groupId', breakfastValidation, async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete option group', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const groupId = parseInt(req.params.groupId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(groupId) || groupId <= 0) {
      logger.warn('Invalid group ID', { id: req.params.groupId });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [result] = await db.query(
      'DELETE FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?',
      [groupId, breakfastId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Option group not found', { id: groupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    logger.info('Option group deleted', { id: groupId, breakfast_id: breakfastId });
    res.json({ message: 'Option group deleted' });
  } catch (error) {
    logger.error('Error deleting option group', { error: error.message, breakfast_id: req.params.breakfastId, group_id: req.params.groupId });
    res.status(500).json({ error: 'Failed to delete option group', details: error.message });
  }
});

// Fetch option groups
router.get('/breakfasts/:id/option-groups', breakfastValidation, async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [rows] = await db.query(
      'SELECT id, title, is_required, max_selections FROM breakfast_option_groups WHERE breakfast_id = ?',
      [breakfastId]
    );
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching option groups', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch option groups', details: error.message });
  }
});

// Create breakfast option
router.post('/breakfasts/:id/options', breakfastValidation, async (req, res) => {
  const { user_id, group_id, option_type, option_name, additional_price } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add breakfast option', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.id);
    const parsedGroupId = parseInt(group_id);
    const parsedAdditionalPrice = additional_price ? parseFloat(additional_price) : 0;
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(parsedGroupId) || parsedGroupId <= 0) {
      logger.warn('Invalid group ID', { group_id });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!option_type || !option_name) {
      logger.warn('Missing required fields', { fields: { option_type, option_name } });
      return res.status(400).json({ error: 'Option type and name are required' });
    }
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [parsedGroupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: parsedGroupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [result] = await db.query(
      'INSERT INTO breakfast_options (breakfast_id, group_id, option_type, option_name, additional_price) VALUES (?, ?, ?, ?, ?)',
      [breakfastId, parsedGroupId, option_type, option_name, parsedAdditionalPrice]
    );
    logger.info('Breakfast option created', { id: result.insertId, breakfast_id: breakfastId, group_id: parsedGroupId });
    res.status(201).json({ message: 'Breakfast option created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating breakfast option', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to create breakfast option', details: error.message });
  }
});

// Update breakfast option
router.put('/breakfasts/:breakfastId/options/:optionId', breakfastValidation, async (req, res) => {
  const { user_id, group_id, option_type, option_name, additional_price } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update breakfast option', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const optionId = parseInt(req.params.optionId);
    const parsedGroupId = parseInt(group_id);
    const parsedAdditionalPrice = additional_price ? parseFloat(additional_price) : 0;
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(optionId) || optionId <= 0) {
      logger.warn('Invalid option ID', { id: req.params.optionId });
      return res.status(400).json({ error: 'Valid option ID is required' });
    }
    if (isNaN(parsedGroupId) || parsedGroupId <= 0) {
      logger.warn('Invalid group ID', { group_id });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!option_type || !option_name) {
      logger.warn('Missing required fields', { fields: { option_type, option_name } });
      return res.status(400).json({ error: 'Option type and name are required' });
    }
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [parsedGroupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: parsedGroupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [option] = await db.query('SELECT id FROM breakfast_options WHERE id = ? AND breakfast_id = ?', [optionId, breakfastId]);
    if (option.length === 0) {
      logger.warn('Breakfast option not found', { id: optionId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Breakfast option not found' });
    }
    const [result] = await db.query(
      'UPDATE breakfast_options SET group_id = ?, option_type = ?, option_name = ?, additional_price = ? WHERE id = ?',
      [parsedGroupId, option_type, option_name, parsedAdditionalPrice, optionId]
    );
    logger.info('Breakfast option updated', { id: optionId, breakfast_id: breakfastId, group_id: parsedGroupId });
    res.json({ message: 'Breakfast option updated' });
  } catch (error) {
    logger.error('Error updating breakfast option', { error: error.message, breakfast_id: req.params.breakfastId, option_id: req.params.optionId });
    res.status(500).json({ error: 'Failed to update breakfast option', details: error.message });
  }
});

// Delete breakfast option
router.delete('/breakfasts/:breakfastId/options/:optionId', breakfastValidation, async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.user || req.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete breakfast option', { user_id, authenticatedUser: req.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const optionId = parseInt(req.params.optionId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(optionId) || optionId <= 0) {
      logger.warn('Invalid option ID', { id: req.params.optionId });
      return res.status(400).json({ error: 'Valid option ID is required' });
    }
    const [result] = await db.query(
      'DELETE FROM breakfast_options WHERE id = ? AND breakfast_id = ?',
      [optionId, breakfastId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Breakfast option not found', { id: optionId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Breakfast option not found' });
    }
    logger.info('Breakfast option deleted', { id: optionId, breakfast_id: breakfastId });
    res.json({ message: 'Breakfast option deleted' });
  } catch (error) {
    logger.error('Error deleting breakfast option', { error: error.message, breakfast_id: req.params.breakfastId, option_id: req.params.optionId });
    res.status(500).json({ error: 'Failed to delete breakfast option', details: error.message });
  }
});

// Fetch breakfast options
router.get('/breakfasts/:id/options', breakfastValidation, async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [rows] = await db.query(
      'SELECT bo.id, bo.group_id, bo.option_type, bo.option_name, bo.additional_price, bog.title as group_title, bog.is_required, bog.max_selections ' +
      'FROM breakfast_options bo ' +
      'JOIN breakfast_option_groups bog ON bo.group_id = bog.id ' +
      'WHERE bo.breakfast_id = ?',
      [breakfastId]
    );
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching breakfast options', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch breakfast options', details: error.message });
  }
});

// Submit breakfast rating
router.post('/breakfast-ratings', [
  require('express-validator').body('breakfast_id').isInt({ min: 1 }).withMessage('Valid breakfast ID is required'),
  require('express-validator').body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
], async (req, res) => {
  const errors = require('express-validator').validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation errors for breakfast rating', { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }
  const { breakfast_id, rating } = req.body;
  const sessionId = req.sessionID || null; // Allow null session ID
  try {
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfast_id]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found for rating', { breakfast_id });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    // Only check for existing rating if sessionId is not null
    if (sessionId) {
      const [existingRating] = await db.query(
        'SELECT id FROM breakfast_ratings WHERE breakfast_id = ? AND session_id = ?',
        [breakfast_id, sessionId]
      );
      if (existingRating.length > 0) {
        logger.warn('Rating already exists for this breakfast in session', { breakfast_id, sessionId });
        return res.status(400).json({ error: 'You have already rated this breakfast' });
      }
    }
    const [result] = await db.query(
      'INSERT INTO breakfast_ratings (breakfast_id, rating, session_id, created_at) VALUES (?, ?, ?, NOW())',
      [breakfast_id, rating, sessionId]
    );
    await db.query(
      `UPDATE breakfasts
       SET average_rating = (SELECT AVG(rating) FROM breakfast_ratings WHERE breakfast_id = ?),
           review_count = (SELECT COUNT(*) FROM breakfast_ratings WHERE breakfast_id = ?)
       WHERE id = ?`,
      [breakfast_id, breakfast_id, breakfast_id]
    );
    logger.info('Breakfast rating submitted', { id: result.insertId, breakfast_id, rating, sessionId });
    res.status(201).json({ message: 'Breakfast rating submitted', id: result.insertId });
  } catch (error) {
    logger.error('Error submitting breakfast rating', { error: error.message, breakfast_id, rating, sessionId });
    res.status(500).json({ error: 'Failed to submit breakfast rating', details: error.message });
  }
});

// Fetch ratings by breakfast
router.get('/breakfast-ratings', [
  require('express-validator').query('breakfast_id').isInt({ min: 1 }).withMessage('Valid breakfast ID is required'),
], async (req, res) => {
  const errors = require('express-validator').validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation errors for fetching breakfast ratings', { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }
  const { breakfast_id } = req.query;
  const sessionId = req.sessionID || null; // Allow null session ID
  try {
    const query = sessionId
      ? 'SELECT id, breakfast_id, rating, created_at FROM breakfast_ratings WHERE breakfast_id = ? AND session_id = ?'
      : 'SELECT id, breakfast_id, rating, created_at FROM breakfast_ratings WHERE breakfast_id = ? AND session_id IS NULL';
    const params = sessionId ? [breakfast_id, sessionId] : [breakfast_id];
    const [rows] = await db.query(query, params);
    logger.info('Breakfast ratings fetched successfully', { breakfast_id, sessionId, count: rows.length });
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching breakfast ratings', { error: error.message, breakfast_id, sessionId });
    res.status(500).json({ error: 'Failed to fetch breakfast ratings', details: error.message });
  }
});

module.exports = router;
