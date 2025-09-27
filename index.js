import express from "express";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://your-frontend.vercel.app" // ganti dengan domain vercel kamu
  ],
  credentials: true
}));

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "Backend is healthy 🚀" });
});

// Contoh route barang
app.get("/api/barang", (req, res) => {
  res.json([{ id: 1, nama: "Barang A" }, { id: 2, nama: "Barang B" }]);
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
