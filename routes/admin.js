// backend/routes/admin.js
router.post('/users', authMiddleware, adminMiddleware, adminController.createUser);
router.get('/test-email', authMiddleware, adminMiddleware, adminController.testEmailConnection);