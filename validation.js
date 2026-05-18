/**
 * ZynChat Validation Middleware
 * Production-hardened input sanitization and schema verification
 */

const path = require('path');

/**
 * Custom ValidationError class
 */
class ValidationError extends Error {
  constructor(message, details = null) {
    super(message);
    this.name = 'ValidationError';
    this.status = 400;
    this.details = details;
    this.code = 'VALIDATION_ERROR';
  }
}

/**
 * Validation Schemas
 */
const SCHEMAS = {
  username: {
    pattern: /^[a-zA-Z0-9_]{2,30}$/,
    message: 'Username must be 2-30 characters and only contain letters, numbers, and underscores.'
  },
  password: {
    min: 4,
    max: 128,
    message: 'Password must be between 4 and 128 characters.'
  },
  roomName: {
    pattern: /^[a-zA-Z0-9 ]{1,50}$/,
    message: 'Room name must be 1-50 characters and alphanumeric.'
  },
  filename: {
    // Prevent path traversal by rejecting ".." sequences and slashes
    pattern: /^(?!.*\.\.)[\w.\- ]+$/,
    message: 'Invalid filename. Path traversal characters are not allowed.'
  }
};

/**
 * Validation Middleware Creator
 */
const validate = (schemaMap) => {
  return (req, res, next) => {
    const errors = {};
    const data = { ...req.body, ...req.query, ...req.params };

    for (const [field, schemaType] of Object.entries(schemaMap)) {
      const value = data[field];
      const schema = SCHEMAS[schemaType];

      if (!schema) continue;

      if (value === undefined || value === null || value === '') {
        errors[field] = `${field} is required.`;
        continue;
      }

      if (schema.pattern && !schema.pattern.test(value)) {
        errors[field] = schema.message;
      }

      if (schema.min && value.length < schema.min) {
        errors[field] = schema.message;
      }

      if (schema.max && value.length > schema.max) {
        errors[field] = schema.message;
      }
    }

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({
        ok: false,
        error: 'Validation failed.',
        code: 'VALIDATION_ERROR',
        details: errors
      });
    }

    next();
  };
};

/**
 * Sanitize Database Errors
 * Prevents leaking DB structure to the client
 */
const sanitizeError = (err) => {
  console.error('[Database Error]', err); // Log full error internally
  
  if (err.message && err.message.includes('UNIQUE constraint failed')) {
    return 'This record already exists.';
  }
  
  // Default generic message for production
  return 'A database error occurred. Please try again later.';
};

module.exports = {
  validate,
  sanitizeError,
  ValidationError
};
