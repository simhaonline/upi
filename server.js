// server.js - UPI Payment Gateway Backend Server
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Import utilities
const { PaymentUtils, PaymentStatus, PaymentType } = require('./utils/payment');
const { DatabaseService } = require('./utils/database');
const { ValidationMiddleware } = require('./middleware/validation');
const { ErrorHandler } = require('./middleware/errorHandler');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
    mchId: process.env.MCH_ID || '1000',
    key: process.env.API_KEY || 'eb6080dbc8dc429ab86a1cd1c337975d',
    apiHost: process.env.API_HOST || 'https://sandbox.wpay.one',
    callbackIP: process.env.CALLBACK_IP || '27.124.45.41',
    domain: process.env.DOMAIN || 'https://pay.mehulbhatt.net',
    environment: process.env.NODE_ENV || 'development'
};

// Logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'upi-payment' },
    transports: [
        new winston.transports.File({ 
            filename: '/var/log/upi-payment/error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: '/var/log/upi-payment/combined.log' 
        })
    ]
});

// Add console transport in development
if (config.environment !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Initialize database service
const db = new DatabaseService(logger);

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
        },
    },
}));

app.use(cors({
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'https://pay.mehulbhatt.net',
            config.domain
        ];
        
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Rate limiting
const createOrderLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
    message: 'Too many payment requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later'
});

// Apply rate limiting
app.use('/api/create-order', createOrderLimiter);
app.use('/api/', generalLimiter);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Request ID middleware
app.use((req, res, next) => {
    req.id = crypto.randomBytes(16).toString('hex');
    res.setHeader('X-Request-ID', req.id);
    next();
});

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
    const health = {
        status: 'UP',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.environment,
        version: process.env.npm_package_version || '1.0.0'
    };
    
    res.json(health);
});

// Create payment order
app.post('/api/create-order', ValidationMiddleware.validateCreateOrder, async (req, res, next) => {
    const requestId = req.id;
    
    try {
        const { amount, payType = PaymentType.UPI, returnUrl, extraData = {} } = req.body;
        
        logger.info(`Creating order: ${JSON.stringify({ amount, payType, requestId })}`);
        
        // Generate unique order number
        const mchOrderNo = PaymentUtils.generateOrderNo('PAY');
        
        // Prepare order data
        const orderData = {
            mchId: config.mchId,
            mchOrderNo: mchOrderNo,
            amount: PaymentUtils.formatAmount(amount),
            currency: 'INR',
            payType: payType,
            notifyUrl: `${config.domain}/api/notify`,
            returnUrl: returnUrl || `${config.domain}/payment-status?order=${mchOrderNo}`,
            subject: extraData.subject || 'Payment',
            body: extraData.body || `Payment for order ${mchOrderNo}`,
            signType: 'MD5',
            reqTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
            clientIp: req.ip || req.connection.remoteAddress,
            device: req.headers['user-agent'] || 'Unknown'
        };

        // Add extra parameters if provided
        if (extraData.customerName) orderData.customerName = extraData.customerName;
        if (extraData.customerEmail) orderData.customerEmail = extraData.customerEmail;
        if (extraData.customerPhone) orderData.customerPhone = extraData.customerPhone;

        // Generate signature
        orderData.sign = PaymentUtils.generateSign(orderData, config.key);

        // Make API request to create order
        const response = await axios.post(
            `${config.apiHost}/api/pay/create`,
            orderData,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Request-ID': requestId
                },
                timeout: 30000 // 30 second timeout
            }
        );

        logger.info(`Payment gateway response: ${JSON.stringify(response.data)}`);

        if (response.data.code === 0 || response.data.code === '0') {
            // Save order to database
            const orderRecord = {
                mchOrderNo,
                platformOrderNo: response.data.data.platformOrderNo,
                amount: orderData.amount,
                currency: orderData.currency,
                payType: orderData.payType,
                status: PaymentStatus.PENDING,
                payUrl: response.data.data.payUrl,
                qrCode: response.data.data.qrCode || response.data.data.payUrl,
                requestId,
                clientIp: orderData.clientIp,
                device: orderData.device,
                extraData,
                createdAt: new Date()
            };

            await db.saveOrder(orderRecord);

            res.json({
                success: true,
                orderId: mchOrderNo,
                platformOrderNo: response.data.data.platformOrderNo,
                payUrl: response.data.data.payUrl,
                qrCode: response.data.data.qrCode || response.data.data.payUrl,
                amount: amount,
                expiresIn: 600 // 10 minutes
            });
        } else {
            throw new Error(response.data.msg || 'Failed to create order');
        }
    } catch (error) {
        logger.error(`Create order error: ${error.message}`, { 
            error: error.stack, 
            requestId 
        });
        next(error);
    }
});

// Query order status
app.get('/api/order-status/:orderId', ValidationMiddleware.validateOrderId, async (req, res, next) => {
    try {
        const { orderId } = req.params;
        
        // Check cache first
        const cachedOrder = await db.getOrder(orderId);
        
        if (cachedOrder && cachedOrder.status === PaymentStatus.SUCCESS) {
            return res.json({
                success: true,
                status: cachedOrder.status,
                amount: cachedOrder.amount,
                actualAmount: cachedOrder.actualAmount,
                completeTime: cachedOrder.completeTime,
                cached: true
            });
        }

        // Query from payment gateway
        const queryData = {
            mchId: config.mchId,
            mchOrderNo: orderId,
            signType: 'MD5',
            reqTime: new Date().toISOString().replace('T', ' ').substring(0, 19)
        };
        
        queryData.sign = PaymentUtils.generateSign(queryData, config.key);

        const response = await axios.post(
            `${config.apiHost}/api/pay/query`,
            queryData,
            {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            }
        );

        if (response.data.code === 0 || response.data.code === '0') {
            const statusData = response.data.data;
            
            // Update order in database
            await db.updateOrderStatus(orderId, {
                status: statusData.status,
                platformOrderNo: statusData.platformOrderNo,
                actualAmount: statusData.actualAmount,
                completeTime: statusData.completeTime
            });

            res.json({
                success: true,
                status: statusData.status,
                statusText: PaymentUtils.parseStatus(statusData.status).message,
                amount: statusData.amount,
                actualAmount: statusData.actualAmount,
                completeTime: statusData.completeTime,
                orderId: orderId,
                platformOrderNo: statusData.platformOrderNo
            });
        } else {
            throw new Error(response.data.msg || 'Failed to query order');
        }
    } catch (error) {
        logger.error(`Query order error: ${error.message}`, { 
            orderId: req.params.orderId,
            error: error.stack 
        });
        next(error);
    }
});

// Payment notification callback
app.post('/api/notify', async (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const cleanIP = clientIP.replace(/^::ffff:/, '');
    
    try {
        logger.info(`Received callback from IP: ${cleanIP}`, { body: req.body });
        
        // Verify IP in production
        if (config.environment === 'production' && cleanIP !== config.callbackIP) {
            logger.warn(`Unauthorized callback attempt from IP: ${cleanIP}`);
            return res.status(403).send('Forbidden');
        }

        // Verify signature
        if (!PaymentUtils.verifySign(req.body, config.key)) {
            logger.error('Invalid signature in callback', { body: req.body });
            return res.status(400).send('Invalid signature');
        }

        // Validate timestamp to prevent replay attacks
        if (req.body.reqTime && !PaymentUtils.validateWebhookTimestamp(req.body.reqTime, 300)) {
            logger.warn('Webhook timestamp too old', { timestamp: req.body.reqTime });
            return res.status(400).send('Request too old');
        }

        const {
            mchOrderNo,
            platformOrderNo,
            amount,
            actualAmount,
            status,
            completeTime,
            payType,
            successTime
        } = req.body;

        // Update order status
        const updateData = {
            status: parseInt(status),
            platformOrderNo,
            actualAmount,
            completeTime: completeTime || successTime,
            callbackData: req.body
        };

        await db.updateOrderStatus(mchOrderNo, updateData);

        // Log payment event
        PaymentUtils.logPaymentEvent('payment_callback', {
            orderId: mchOrderNo,
            status: status,
            amount: actualAmount
        });

        // Send success response
        res.send('SUCCESS');

        // Trigger any webhooks or notifications
        if (parseInt(status) === PaymentStatus.SUCCESS) {
            // You can add webhook notifications to your system here
            logger.info(`Payment successful for order: ${mchOrderNo}`);
        } else if (parseInt(status) === PaymentStatus.FAILED) {
            logger.info(`Payment failed for order: ${mchOrderNo}`);
        }

    } catch (error) {
        logger.error(`Callback processing error: ${error.message}`, { 
            error: error.stack,
            body: req.body 
        });
        res.status(500).send('ERROR');
    }
});

// Submit UTR reference
app.post('/api/submit-utr', ValidationMiddleware.validateUTR, async (req, res, next) => {
    try {
        const { orderId, utr } = req.body;
        
        // Get order
        const order = await db.getOrder(orderId);
        if (!order) {
            return res.status(404).json({
                success: false,
                message: 'Order not found'
            });
        }

        // Save UTR
        await db.saveUTR(orderId, utr, {
            submittedAt: new Date(),
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        });

        logger.info(`UTR submitted for order: ${orderId}`, { utr });

        res.json({
            success: true,
            message: 'UTR submitted successfully',
            orderId,
            utr
        });

        // In production, you might want to notify the payment processor
        // or trigger a manual verification process

    } catch (error) {
        logger.error(`Submit UTR error: ${error.message}`, { 
            error: error.stack,
            orderId: req.body.orderId 
        });
        next(error);
    }
});

// Get payment methods
app.get('/api/payment-methods', (req, res) => {
    const methods = [
        {
            id: 'upi',
            name: 'UPI',
            code: PaymentType.UPI,
            icon: 'upi',
            enabled: true
        },
        {
            id: 'paytm',
            name: 'Paytm',
            code: PaymentType.PAYTM,
            icon: 'paytm',
            enabled: true
        },
        {
            id: 'phonepe',
            name: 'PhonePe',
            code: PaymentType.PHONEPE,
            icon: 'phonepe',
            enabled: true
        },
        {
            id: 'gpay',
            name: 'Google Pay',
            code: PaymentType.GPAY,
            icon: 'gpay',
            enabled: true
        }
    ];

    res.json({
        success: true,
        methods
    });
});

// Admin endpoints (protected)
app.get('/api/admin/orders', ValidationMiddleware.validateAdminAuth, async (req, res, next) => {
    try {
        const { page = 1, limit = 20, status, from, to } = req.query;
        
        const orders = await db.getOrders({
            page: parseInt(page),
            limit: parseInt(limit),
            status,
            from,
            to
        });

        res.json({
            success: true,
            ...orders
        });
    } catch (error) {
        next(error);
    }
});

// Test endpoints (only in development/sandbox)
if (config.environment !== 'production') {
    app.post('/api/test/simulate-callback/:orderId/:status', async (req, res, next) => {
        try {
            const { orderId, status } = req.params;
            
            const callbackData = {
                mchId: config.mchId,
                mchOrderNo: orderId,
                platformOrderNo: `TEST${Date.now()}`,
                amount: '500',
                actualAmount: '500',
                status: status,
                payType: PaymentType.UPI,
                successTime: new Date().toISOString().replace('T', ' ').substring(0, 19),
                signType: 'MD5'
            };
            
            callbackData.sign = PaymentUtils.generateSign(callbackData, config.key);
            
            // Make internal callback
            const response = await axios.post(
                `http://localhost:${PORT}/api/notify`,
                callbackData,
                {
                    headers: {
                        'X-Forwarded-For': config.callbackIP
                    }
                }
            );

            res.json({ 
                success: true, 
                message: 'Test callback sent',
                response: response.data
            });
        } catch (error) {
            next(error);
        }
    });
}

// Error handling middleware
app.use(ErrorHandler);

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Resource not found',
        path: req.path
    });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received. Starting graceful shutdown...`);
    
    // Stop accepting new connections
    server.close(() => {
        logger.info('HTTP server closed');
    });

    // Close database connections
    await db.close();

    // Wait for ongoing requests to complete (max 30 seconds)
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 30000);
};

// Start server
const server = app.listen(PORT, () => {
    logger.info(`UPI Payment Server running on port ${PORT}`);
    logger.info(`Environment: ${config.environment}`);
    logger.info(`API Host: ${config.apiHost}`);
});

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;
