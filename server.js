const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const useragent = require('useragent');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'your-secret-key';

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use(limiter);

// In-memory storage (use database in production)
const users = new Map();
const loginHistory = new Map();
const otpStore = new Map();

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your-email@gmail.com',
    pass: 'your-app-password'
  }
});

// Helper functions
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function getDeviceInfo(userAgent, ip) {
  const agent = useragent.parse(userAgent);
  return {
    browser: agent.toAgent(),
    os: agent.os.toString(),
    device: agent.device.toString() || 'Desktop',
    ip: ip,
    timestamp: new Date().toISOString()
  };
}

function isMobileTimeAllowed() {
  const now = new Date();
  const hours = now.getHours();
  return hours >= 10 && hours < 13; // 10:00 AM to 1:00 PM
}

function isMobileDevice(userAgent) {
  const agent = useragent.parse(userAgent);
  return /mobile|android|iphone|ipad|tablet/i.test(userAgent) || 
         agent.device.family !== 'Other';
}

function isChromeBasedBrowser(userAgent) {
  return /chrome|chromium/i.test(userAgent) && !/edge|edg/i.test(userAgent);
}

function isMicrosoftBrowser(userAgent) {
  return /edge|edg|msie|trident/i.test(userAgent);
}

// Routes
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  
  if (users.has(email)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  users.set(email, { email, password: hashedPassword });
  loginHistory.set(email, []);
  
  res.json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const userAgent = req.headers['user-agent'];
  const ip = req.ip || req.connection.remoteAddress;
  
  const user = users.get(email);
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const deviceInfo = getDeviceInfo(userAgent, ip);
  
  // Mobile time restriction
  if (isMobileDevice(userAgent) && !isMobileTimeAllowed()) {
    return res.status(403).json({ 
      error: 'Mobile access is only allowed between 10:00 AM and 1:00 PM' 
    });
  }
  
  // Chrome browser - requires OTP
  if (isChromeBasedBrowser(userAgent)) {
    const otp = generateOTP();
    otpStore.set(email, { otp, expires: Date.now() + 300000 }); // 5 minutes
    
    try {
      await transporter.sendMail({
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Login OTP Verification',
        text: `Your OTP for login is: ${otp}. Valid for 5 minutes.`
      });
      
      return res.json({ 
        requiresOTP: true, 
        message: 'OTP sent to your email',
        deviceInfo 
      });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to send OTP' });
    }
  }
  
  // Microsoft browser or other browsers - direct access
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
  
  // Store login history
  const history = loginHistory.get(email) || [];
  history.push(deviceInfo);
  loginHistory.set(email, history);
  
  res.json({ 
    token, 
    message: 'Login successful',
    deviceInfo 
  });
});

app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const userAgent = req.headers['user-agent'];
  const ip = req.ip || req.connection.remoteAddress;
  
  const storedOTP = otpStore.get(email);
  if (!storedOTP || storedOTP.expires < Date.now()) {
    return res.status(400).json({ error: 'OTP expired or invalid' });
  }
  
  if (storedOTP.otp !== otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  
  otpStore.delete(email);
  
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
  const deviceInfo = getDeviceInfo(userAgent, ip);
  
  // Store login history
  const history = loginHistory.get(email) || [];
  history.push(deviceInfo);
  loginHistory.set(email, history);
  
  res.json({ 
    token, 
    message: 'Login successful',
    deviceInfo 
  });
});

app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const history = loginHistory.get(decoded.email) || [];
    
    res.json({
      email: decoded.email,
      loginHistory: history.slice(-10) // Last 10 logins
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});