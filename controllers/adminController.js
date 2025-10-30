// backend/controllers/adminController.js
const adminController = {
  createUser: async (req, res) => {
    try {
      const {
        username,
        password,
        role,
        full_name,
        email,
        is_active = true,
        send_welcome_email = false, // Parameter untuk email
      } = req.body;

      console.log("📧 Email setting:", { send_welcome_email, email });

      // 1. Validasi required fields
      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message: "Username and password are required",
        });
      }

      // 2. Check if user already exists
      const existingUser = await User.findOne({ where: { username } });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "Username already exists",
        });
      }

      // 3. Create user
      const newUser = await User.create({
        username,
        password: await bcrypt.hash(password, 12),
        role,
        full_name,
        email,
        is_active,
      });

      let emailResult = { success: false, message: "Email not sent" };

      // 4. Send welcome email if requested
      if (send_welcome_email && email) {
        try {
          emailResult = await emailService.sendUserCreatedEmail(
            { username, role, full_name, email },
            password
          );

          console.log("📧 Email send result:", emailResult);
        } catch (emailError) {
          console.error("❌ Email error:", emailError);
          emailResult = {
            success: false,
            error: emailError.message,
            message: "Failed to send welcome email",
          };
        }
      }

      // 5. Send admin notification
      let adminNotificationResult = { success: false };
      try {
        adminNotificationResult = await emailService.sendAdminNotification(
          newUser,
          req.user.username
        );
      } catch (adminEmailError) {
        console.error("Admin notification failed:", adminEmailError);
      }

      // 6. Response
      res.status(201).json({
        success: true,
        message: "User created successfully",
        data: {
          user: {
            id: newUser.id,
            username: newUser.username,
            email: newUser.email,
            role: newUser.role,
            full_name: newUser.full_name,
            is_active: newUser.is_active,
          },
          emailSent: emailResult.success,
          adminNotified: adminNotificationResult.success,
          emailDetails: {
            welcome: emailResult,
            admin: adminNotificationResult,
          },
        },
      });
    } catch (error) {
      console.error("Create user error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to create user",
        error: error.message,
      });
    }
  },

  testEmailConnection: async (req, res) => {
    try {
      const result = await emailService.testConnection();
      res.json(result);
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Email test failed",
        error: error.message,
      });
    }
  },
};
