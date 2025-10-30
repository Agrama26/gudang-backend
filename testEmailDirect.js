// backend/testEmailDirect.js
require('dotenv').config();
const emailService = require('./services/emailService');

async function testEmailDirectly() {
    console.log('🧪 TESTING EMAIL SERVICE DIRECTLY...\n');
    
    // Test 1: Check environment
    console.log('1. 📋 Checking environment...');
    console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✅ SET' : '❌ MISSING');
    console.log('EMAIL_PASSWORD:', process.env.EMAIL_PASSWORD ? '✅ SET' : '❌ MISSING');
    console.log('ENABLE_EMAIL_NOTIFICATIONS:', process.env.ENABLE_EMAIL_NOTIFICATIONS);
    console.log('');
    
    // Test 2: Test connection
    console.log('2. 🔗 Testing email connection...');
    try {
        const connection = await emailService.testConnection();
        console.log('Connection result:', connection);
        if (!connection.success) {
            console.log('❌ Email connection failed, stopping test');
            return;
        }
    } catch (error) {
        console.log('❌ Connection test error:', error.message);
        return;
    }
    console.log('');
    
    // Test 3: Send actual email
    console.log('3. ✉️ Sending test email...');
    const testUser = {
        username: 'testuser',
        role: 'staff',
        full_name: 'Test User',
        email: 'sironeko2611@gmail.com' // Email yang sama dengan test sebelumnya
    };
    
    try {
        const result = await emailService.sendUserCreatedEmail(testUser, 'TestPassword123');
        console.log('Email send result:', result);
        
        if (result.success) {
            console.log('✅ EMAIL SENT SUCCESSFULLY!');
            console.log('Message ID:', result.messageId);
        } else {
            console.log('❌ EMAIL FAILED:');
            console.log('Error:', result.error);
            console.log('Message:', result.message);
        }
    } catch (error) {
        console.log('💥 Email sending exception:', error);
    }
}

testEmailDirectly().catch(console.error);