require('dotenv').config();

async function testEmailService() {
  console.log('Enhanced Email Service Test\n');
  
  const emailService = require('./services/emailService');
  
  // Test 1: Configuration Check
  console.log('1. Checking Configuration...');
  console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✅ SET' : '❌ MISSING');
  console.log('EMAIL_PASSWORD:', process.env.EMAIL_PASSWORD ? '✅ SET' : '❌ MISSING');
  console.log('ENABLE_EMAIL_NOTIFICATIONS:', process.env.ENABLE_EMAIL_NOTIFICATIONS);
  console.log('');
  
  // Test 2: Connection Test
  console.log('2. Testing Connection...');
  const connectionResult = await emailService.testConnection();
  console.log('Connection:', connectionResult.success ? '✅ SUCCESS' : '❌ FAILED');
  if (!connectionResult.success) {
    console.log('Error:', connectionResult.error);
    console.log('Tips: Check your Gmail App Password and ensure 2FA is enabled');
    return;
  }
  console.log('');
  
  // Test 3: Send Test Email
  console.log('3. Sending Test Email...');
  const testUser = {
    username: 'testuser',
    role: 'staff',
    full_name: 'Test User',
    email: process.env.EMAIL_USER 
  };
  
  const emailResult = await emailService.sendUserCreatedEmail(testUser, 'TestPassword123');
  console.log('Email Send:', emailResult.success ? '✅ SUCCESS' : '❌ FAILED');
  if (emailResult.success) {
    console.log('Message ID:', emailResult.messageId);
  } else {
    console.log('Error:', emailResult.error);
  }
}

testEmailService().catch(console.error);