const rateLimit = require('express-rate-limit');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// ============================================
// 1. HTTP Rate Limiters (express-rate-limit)
// ============================================

// 🔐 Authentication Endpoints - Very Strict
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many authentication attempts. Please try again later.',
    retryAfter: 15 * 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many authentication attempts from this IP',
      retryAfter: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000),
      type: 'auth_limit'
    });
  }
});

// 📊 Dashboard/Read Endpoints - Liberal
const readLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: {
    error: 'Too many requests. Please slow down.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/api/health';
  },
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP',
      retryAfter: 60,
      type: 'read_limit'
    });
  }
});

// ✍️ Write Endpoints - Medium Strict
const writeLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: {
    error: 'Too many write operations. Please slow down.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many write operations from this IP',
      retryAfter: 60,
      type: 'write_limit'
    });
  }
});

// 🔥 Threat Intelligence Endpoints - Medium
const threatIntelLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: {
    error: 'Too many threat intelligence requests.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many threat intelligence requests from this IP',
      retryAfter: 60,
      type: 'threat_intel_limit'
    });
  }
});

// ============================================
// 2. WebSocket Rate Limiter
// ============================================

const wsRateLimiter = new RateLimiterMemory({
  points: 100, // Number of messages
  duration: 60, // Per 60 seconds
});

const wsConnectionLimiter = new RateLimiterMemory({
  points: 5, // Max 5 connections
  duration: 60, // Per 60 seconds
});

const wsReconnectLimiter = new RateLimiterMemory({
  points: 3, // Max 3 reconnection attempts
  duration: 60, // Per 60 seconds
});

// ============================================
// 3. Helper Functions
// ============================================

// Get client IP (handles proxies)
const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         req.ip;
};

// WebSocket rate limit check
const checkWsRateLimit = async (identifier, limiter, action = 'message') => {
  try {
    await limiter.consume(identifier);
    return { allowed: true };
  } catch (error) {
    return {
      allowed: false,
      retryAfter: Math.ceil(error.msBeforeNext / 1000),
      action
    };
  }
};

// ============================================
// 4. Export
// ============================================

module.exports = {
  // HTTP Limiters
  authLimiter,
  readLimiter,
  writeLimiter,
  threatIntelLimiter,
  
  // WebSocket Limiters
  wsRateLimiter,
  wsConnectionLimiter,
  wsReconnectLimiter,
  
  // Helpers
  getClientIp,
  checkWsRateLimit
};