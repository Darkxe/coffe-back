// breakfastValidation.js
const { body, validationResult, param } = require('express-validator');
const logger = require('../logger');

const breakfastValidation = (req, res, next) => {
  const validations = [];

  logger.debug('Breakfast validation middleware called', {
    method: req.method,
    path: req.path,
    params: req.params,
    body: req.body,
    headers: { 'x-session-id': req.headers['x-session-id'] },
  });

  if (req.method === 'POST' || req.method === 'PUT') {
    if (req.path.includes('/breakfasts') && req.path.includes('/option-groups')) {
      validations.push(
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required'),
        body('title')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Title is required'),
        body('is_required')
          .optional()
          .customSanitizer(value => value === 'true' || value === true)
          .isBoolean()
          .withMessage('is_required must be a boolean'),
        body('max_selections')
          .customSanitizer(value => Number(value))
          .isInt({ min: 0 })
          .withMessage('max_selections must be a non-negative integer'),
        param('id')
          .optional()
          .customSanitizer(value => value ? Number(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
      if (req.method === 'PUT' && req.path.match(/^\/breakfasts\/\d+\/option-groups\/\d+$/)) {
        validations.push(
          param('breakfastId')
            .customSanitizer(value => Number(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required'),
          param('groupId')
            .customSanitizer(value => Number(value))
            .isInt({ min: 1 })
            .withMessage('Valid group ID is required')
        );
      }
    } else if (req.path.includes('/breakfasts') && req.path.includes('/options')) {
      validations.push(
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required'),
        body('group_id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid group ID is required'),
        body('option_type')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Option type is required'),
        body('option_name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Option name is required'),
        body('additional_price')
          .customSanitizer(value => value !== undefined ? Number(value) : 0)
          .isFloat({ min: 0 })
          .withMessage('Additional price must be a non-negative number'),
        param('id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
      if (req.method === 'PUT' && req.path.match(/^\/breakfasts\/\d+\/options\/\d+$/)) {
        validations.push(
          param('breakfastId')
            .customSanitizer(value => Number(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required'),
          param('optionId')
            .customSanitizer(value => Number(value))
            .isInt({ min: 1 })
            .withMessage('Valid option ID is required')
        );
      }
    } else if (req.path.includes('/breakfasts') && !req.path.includes('/options') && !req.path.includes('/option-groups')) {
      validations.push(
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required'),
        body('name')
          .optional()
          .isString()
          .trim()
          .withMessage('Name must be a string'),
        body('price')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isFloat({ min: 0.01 })
          .withMessage('Price must be a positive number'),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string'),
        body('availability')
          .optional()
          .customSanitizer(value => value === 'true' || value === true)
          .isBoolean()
          .withMessage('Availability must be a boolean'),
        body('category_id')
          .optional()
          .customSanitizer(value => value ? Number(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Invalid category ID')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .customSanitizer(value => Number(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required')
        );
      }
    }
  }

  if (req.method === 'GET') {
    if (req.path.match(/^\/breakfasts\/\d+$/)) {
      validations.push(
        param('id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/options$/)) {
      validations.push(
        param('id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/option-groups$/)) {
      validations.push(
        param('id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
  }

  if (req.method === 'DELETE') {
    if (req.path.match(/^\/breakfasts\/\d+$/)) {
      validations.push(
        param('id')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required'),
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/option-groups\/\d+$/)) {
      validations.push(
        param('breakfastId')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required'),
        param('groupId')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid group ID is required'),
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/options\/\d+$/)) {
      validations.push(
        param('breakfastId')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required'),
        param('optionId')
          .customSanitizer(value => Number(value))
          .isInt({ min: 1 })
          .withMessage('Valid option ID is required'),
        body('user_id')
          .optional()
          .customSanitizer(value => value !== undefined ? Number(value) : undefined)
          .isInt({ min: 1 })
          .custom((value, { req }) => {
            if (value && (!req.user || req.user.id !== value)) {
              throw new Error('User ID does not match authenticated user');
            }
            return true;
          })
          .withMessage('Valid user ID matching authenticated user is required')
      );
    }
  }

  Promise.all(validations.map(validation => validation.run(req))).then(() => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Breakfast validation errors', {
        errors: errors.array(),
        method: req.method,
        path: req.path,
        body: req.body,
        params: req.params,
        query: req.query,
        headers: { 'x-session-id': req.headers['x-session-id'] },
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }).catch(err => {
    logger.error('Breakfast validation middleware error', {
      error: err.message,
      method: req.method,
      path: req.path,
    });
    res.status(500).json({ error: 'Internal breakfast validation error' });
  });
};

module.exports = breakfastValidation;
