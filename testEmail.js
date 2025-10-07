// backend/testEmail.js
require('dotenv').config();

console.log('📧 Email Configuration:');
console.log('EMAIL_USER:', process.env.EMAIL_USER || 'NOT SET');
console.log('EMAIL_SERVICE:', process.env.EMAIL_SERVICE || 'NOT SET');
console.log('ENABLE_EMAIL_NOTIFICATIONS:', process.env.ENABLE_EMAIL_NOTIFICATIONS || 'NOT SET');
console.log('');

// Test nodemailer import
console.log('Testing nodemailer import...');
try {
  const nodemailer = require('nodemailer');
  console.log('✅ nodemailer imported successfully');
  console.log('Type:', typeof nodemailer.createTransporter);
  console.log('');
} catch (error) {
  console.error('❌ Failed to import nodemailer:', error.message);
  process.exit(1);
}

// Now test email service
const emailService = require('./services/emailService');

async function testEmail() {
  console.log('🧪 Testing Email Service...\n');

  // Test 1: Connection
  console.log('1️⃣ Testing connection...');
  const connectionTest = await emailService.testConnection();
  console.log('Result:', connectionTest);
  console.log('');

  if (!connectionTest.success) {
    console.log('❌ Email connection failed. Please check your configuration.');
    return;
  }

  // Test 2: Send test email
  console.log('2️⃣ Sending test user created email...');
  const testUser = {
    username: 'testuser',
    role: 'staff',
    full_name: 'Test User',
    email: process.env.EMAIL_USER
  };

  const userEmailResult = await emailService.sendUserCreatedEmail(testUser, 'TestPassword123');
  console.log('Result:', userEmailResult);
  console.log('');

  console.log('✅ Email tests completed!');
}

testEmail()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('❌ Test failed:', error);
    process.exit(1);
  });