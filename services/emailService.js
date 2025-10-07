// backend/services/emailService.js - Simple SMTP Version
const nodemailer = require('nodemailer');
const path = require('path');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

console.log('📧 Initializing Email Service...');
console.log('Email User:', process.env.EMAIL_USER || 'NOT CONFIGURED');

// Email Templates (simplified)
const emailTemplates = {
  userCreated: (userData, tempPassword) => ({
    subject: '🎉 Welcome to PT. Medianusa Permana',
    text: `
Hello ${userData.full_name || userData.username}!

Your account has been created successfully.

LOGIN CREDENTIALS:
- Username: ${userData.username}
- Temporary Password: ${tempPassword}
- Role: ${userData.role.toUpperCase()}

Login here: ${process.env.APP_URL || 'http://localhost:5173'}/login

IMPORTANT: Please change your password after first login.

Best regards,
PT. Medianusa Permana Team
    `,
    html: `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 20px auto; background: #fff; padding: 30px; border-radius: 10px; }
    .header { background: linear-gradient(135deg, #14b8a6 0%, #0891b2 100%); color: white; padding: 20px; border-radius: 5px; }
    .credentials { background: #f0fdfa; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #14b8a6; }
    .button { display: inline-block; padding: 12px 30px; background: #14b8a6; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎉 Welcome to PT. Medianusa Permana</h1>
    </div>
    <h2>Hello, ${userData.full_name || userData.username}!</h2>
    <p>Your account has been successfully created.</p>
    
    <div class="credentials">
      <h3>🔐 Your Login Credentials</h3>
      <p><strong>Username:</strong> ${userData.username}</p>
      <p><strong>Password:</strong> ${tempPassword}</p>
      <p><strong>Role:</strong> ${userData.role.toUpperCase()}</p>
    </div>
    
    <center>
      <a href="${process.env.APP_URL || 'http://localhost:5173'}/login" class="button">
        Login to System
      </a>
    </center>
    
    <p><strong>⚠️ Important:</strong> Please change your password after first login.</p>
    
    <p>Best regards,<br><strong>PT. Medianusa Permana Team</strong></p>
  </div>
</body>
</html>
    `
  }),

  adminNotification: (userData, createdBy) => ({
    subject: '👤 New User Created',
    text: `
New user has been added to the system.

User Details:
- Username: ${userData.username}
- Role: ${userData.role.toUpperCase()}
- Created By: ${createdBy}
- Email: ${userData.email || 'N/A'}

Date: ${new Date().toLocaleString()}
    `,
    html: `
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
  <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd;">
    <h2>👤 New User Created</h2>
    <p>A new user has been added to the system.</p>
    <div style="background: #f3f4f6; padding: 15px; border-radius: 5px;">
      <strong>User Details:</strong><br>
      - Username: ${userData.username}<br>
      - Role: ${userData.role.toUpperCase()}<br>
      - Created By: ${createdBy}<br>
      - Email: ${userData.email || 'N/A'}<br>
      - Date: ${new Date().toLocaleString()}
    </div>
  </div>
</body>
</html>
    `
  })
};

// Email service
const emailService = {
  transporter: null,

  // Initialize transporter
  init() {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.warn('⚠️ Email credentials not configured.');
      return false;
    }

    try {
      // Create transporter using createTransport (not createTransporter!)
      this.transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: false,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      console.log('✅ Email transporter configured');
      return true;
    } catch (error) {
      console.error('❌ Error creating transporter:', error.message);
      return false;
    }
  },

  // Send email
  async sendEmail(to, subject, html, text) {
    if (!this.transporter) {
      if (!this.init()) {
        console.log('📧 Email disabled. Would have sent to:', to);
        return { success: false, message: 'Email transporter not configured' };
      }
    }

    if (process.env.ENABLE_EMAIL_NOTIFICATIONS !== 'true') {
      console.log('📧 Email disabled. Would have sent:', { to, subject });
      return { success: false, message: 'Email notifications disabled' };
    }

    try {
      const mailOptions = {
        from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
        to,
        subject,
        text,
        html
      };

      const info = await this.transporter.sendMail(mailOptions);
      console.log('✅ Email sent:', info.messageId);
      return { success: true, messageId: info.messageId };
    } catch (error) {
      console.error('❌ Email error:', error.message);
      return { success: false, error: error.message };
    }
  },

  // Send welcome email
  async sendUserCreatedEmail(userData, tempPassword) {
    if (!userData.email) {
      return { success: false, message: 'No email provided' };
    }

    const template = emailTemplates.userCreated(userData, tempPassword);
    return await this.sendEmail(
      userData.email,
      template.subject,
      template.html,
      template.text
    );
  },

  // Send admin notification
  async sendAdminNotification(userData, createdBy) {
    const adminEmail = process.env.ADMIN_EMAIL;
    if (!adminEmail) {
      return { success: false, message: 'Admin email not configured' };
    }

    const template = emailTemplates.adminNotification(userData, createdBy);
    return await this.sendEmail(
      adminEmail,
      template.subject,
      template.html,
      template.text
    );
  },

  // Test connection
  async testConnection() {
    if (!this.transporter) {
      if (!this.init()) {
        return { success: false, message: 'Email transporter not configured' };
      }
    }

    try {
      await this.transporter.verify();
      console.log('✅ Email connection verified');
      return { success: true, message: 'Email connection successful' };
    } catch (error) {
      console.error('❌ Connection failed:', error.message);
      return { success: false, error: error.message };
    }
  }
};

// Initialize on load if enabled
if (process.env.ENABLE_EMAIL_NOTIFICATIONS === 'true') {
  emailService.init();
}

module.exports = emailService;