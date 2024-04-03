import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import User from "../models/userModel.js";
import { checkAccessToken } from "../middleware/authMiddleware.js";
import cors from "cors";

const userRouter = express.Router();
userRouter.use(cors());

userRouter.post("/register", async (req, res) => {
  const { fullname, email, password, phone } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(201).json({ message: "Email đã tồn tại." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ fullname, password: hashedPassword, phone, email });
    await user.save();
    const userData = await User.findOne({ email }).select("-password -__v");
    res.status(201).json({
      success: true,
      message: "Tài khoản được đăng ký thành công.",
      status_code: 201,
      data: userData,
    });
  } catch (error) {
    res.status(500).json({ error: "Xin vui lòng hãy thử lại sau." });
  }
});
userRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Tài khoản không tìm thấy." });
    }
    const userData = await User.findOne({ email }).select("-password -__v");

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      const tokenUser = jwt.sign({ id: user._id }, "VinalinkGroup!2020");
      res.status(200).json({
        success: true,
        message: "Tài khoản đăng nhập thành công.",
        status_code: 200,
        data: {
          token: tokenUser,
          _id: userData._id,
          fullname: userData.fullname,
          phone: userData.phone,
          email: userData.email,
        },
      });
    } else {
      res.status(401).json({ message: "Sai mật khẩu hoặc số điện thoại." });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

userRouter.put("/change-password", checkAccessToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    const userId = req.user.id;
    const user = await User.findById(userId);

    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Mật khẩu hiện tại không đúng." });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Mật khẩu đã được thay đổi thành công." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
});

userRouter.get("/get-profile", checkAccessToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select("-password");
    res.status(200).json({ user: user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
});
export default userRouter;
