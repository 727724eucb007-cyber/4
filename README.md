# Login Tracking System

A comprehensive authentication system that tracks user login information with conditional authentication based on browser type and time restrictions for mobile devices.

## Features

- **Detailed Login Tracking**: Records browser type, OS, device type, IP address, and timestamp
- **Conditional Authentication**:
  - Chrome browsers: Requires OTP verification via email
  - Microsoft browsers: Direct access without additional authentication
  - Other browsers: Direct access
- **Mobile Time Restrictions**: Mobile access only allowed between 10:00 AM - 1:00 PM
- **Login History**: Displays last 10 login sessions in user profile
- **Security Features**: Rate limiting, helmet security headers, CORS protection

## Setup Instructions

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Configure Email (Optional for OTP)**:
   - Update email credentials in `server.js`:
   ```javascript
   const transporter = nodemailer.createTransporter({
     service: 'gmail',
     auth: {
       user: 'your-email@gmail.com',
       pass: 'your-app-password'
     }
   });
   ```

3. **Start the Server**:
   ```bash
   npm start
   ```
   Or for development:
   ```bash
   npm run dev
   ```

4. **Access the Application**:
   Open `http://localhost:3000` in your browser

## Testing the System

### Test Scenarios:

1. **Chrome Browser Login**:
   - Register a user
   - Login using Chrome - should require OTP
   - Check email for OTP code
   - Verify OTP to complete login

2. **Microsoft Edge Login**:
   - Login using Edge browser - should allow direct access
   - No OTP required

3. **Mobile Time Restriction**:
   - Access from mobile device outside 10 AM - 1 PM
   - Should deny access with time restriction message

4. **Login History**:
   - Login from different browsers/devices
   - Check profile to see detailed login history

### API Endpoints:

- `POST /api/register` - User registration
- `POST /api/login` - User login with conditional authentication
- `POST /api/verify-otp` - OTP verification for Chrome users
- `GET /api/profile` - Get user profile with login history

## Browser Detection Logic

- **Chrome**: Detects Chrome/Chromium browsers (excludes Edge)
- **Microsoft**: Detects Edge, Internet Explorer, and other Microsoft browsers
- **Mobile**: Detects mobile devices based on user agent

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Rate limiting (100 requests per 15 minutes)
- Helmet security headers
- CORS protection
- OTP expiration (5 minutes)

## Production Considerations

- Replace in-memory storage with a proper database
- Use environment variables for sensitive configuration
- Implement proper email service configuration
- Add input validation and sanitization
- Implement proper error logging
- Add HTTPS in production