const router=require("express").Router();
const AuthController=require("./auth.controller");

router.post("/send-otp",AuthController.sendOtp);
router.post("/verify-otp",AuthController.verifyOTP);
router.post("/logout",AuthController.logout);
router.post("/refresh",AuthController.refreshToken);


module.exports = router;
