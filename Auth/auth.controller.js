const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const UserModel = require("../models/user-model");
const RefreshModel = require("../models/refreshToken-model");

exports.sendOtp = async (req, res) => {
	const { phone } = req.body;
	if (!phone) {
		return res.status(400).send("Phone is required");
	}
	const generateOTP = () => {
		const otp = crypto.randomInt(1000, 9999);
		return otp;
	};
	const hashOTP = (data) => {
		// crypto.randomBytes(64).toString("hex") //generate secret
		const SECRET =
			"d490fe473ffe630679b077e64a070bf993518bf01ac089a7237793f601326f14fd7dd74f5519d475ee0a18e0566f119e6e50f039faa215c54593811a2c797065";
		return crypto.createHmac("sha256", SECRET).update(data).digest("hex");
	};
	const otp = generateOTP();

	const ttl = 1000 * 60 * 2;
	const expires = Date.now() + ttl;
	const data = `${phone}.${otp}.${expires}`;
	const hash = hashOTP(data);

	res.status(200).json({ phone, hash: `${hash}.${expires}`, otp });
};

exports.logout = async (req, res) => {
	const { refreshToken } = req.cookies;
	// delete refresh token from db
	const removeToken = async (refreshToken) => {
		return await RefreshModel.deleteOne({ token: refreshToken });
	};
	await removeToken(refreshToken);
	// delete cookies
	res.clearCookie("refreshToken");
	res.clearCookie("accessToken");
	res.json({ user: null });
};

exports.verifyOTP = async (req, res) => {
	try {
		const { phone, otp, hash } = req.body;
		if (!phone || !otp || !hash) {
			return res.status(400).json({ error: "All fields required" });
		}
		const [hashedOTP, expires] = hash.split(".");

		if (Date.now() > expires) {
			return res.status(422).json({ error: "Otp expired" });
		}
		const hashOTP = (data) => {
			// crypto.randomBytes(64).toString("hex") //generate secret
			const SECRET =
				"d490fe473ffe630679b077e64a070bf993518bf01ac089a7237793f601326f14fd7dd74f5519d475ee0a18e0566f119e6e50f039faa215c54593811a2c797065";
			return crypto
				.createHmac("sha256", SECRET)
				.update(data)
				.digest("hex");
		};
		const verifyOTP = (hashedOTP, data) => {
			let computedHash = hashOTP(data);
			return computedHash === hashedOTP;
		};
		const data = `${phone}.${otp}.${expires}`;
		const isValid = verifyOTP(hashedOTP, data);

		if (!isValid) {
			return res.status(422).json({ error: "Invalid otp" });
		}

		let user;

		user = await UserModel.findOne({ phone });
		if (!user) {
			user = await UserModel.create({ phone });
		}
		const generateToken = (payload) => {
			const accessToken = jwt.sign(payload, "access-token-secret", {
				expiresIn: "1h",
			});
			const refreshToken = jwt.sign(payload, "refresh-token-secret", {
				expiresIn: "1y",
			});

			return { accessToken, refreshToken };
		};
		const { accessToken, refreshToken } = generateToken({ _id: user._id });

		await RefreshModel.create({
			token: refreshToken,
			userId: user._id,
		});
		res.cookie("refreshToken", refreshToken, {
			maxAge: 1000 * 60 * 60 * 24 * 30,
			httpOnly: true,
		});

		res.cookie("accessToken", accessToken, {
			maxAge: 1000 * 60 * 60 * 24 * 30,
			httpOnly: true,
		});

		res.status(200).json({ user });
	} catch (error) {
		console.log(error);
		res.status(500).json({ error: "Internal server error" });
	}
};
exports.refreshToken = async (req, res) => {
	// get refresh token from cookie
	const { refreshToken: refreshTokenFromCookie } = req.cookies;
	// check if token is valid
	let userData;
	const verifyRefreshToken = async (refreshToken) => {
		return jwt.verify(refreshToken, "refresh-token-secret");
	};
	try {
		userData = await verifyRefreshToken(refreshTokenFromCookie);
	} catch (err) {
		return res.status(401).json({ message: "Invalid Token" });
	}
	const findRefreshToken = async (userId, refreshToken) => {
		return await RefreshModel.findOne({
			userId: userId,
			token: refreshToken,
		});
	};
	try {
		const token = await findRefreshToken(
			userData._id,
			refreshTokenFromCookie
		);
		if (!token) {
			return res.status(401).json({ message: "Invalid token" });
		}
	} catch (err) {
		return res.status(500).json({ message: "Internal error" });
	}
	// check if valid user

	const user = await UserModel.findOne({ _id: userData._id });
	if (!user) {
		return res.status(404).json({ message: "No user" });
	}
	const generateToken = (payload) => {
		const accessToken = jwt.sign(payload, "access-token-secret", {
			expiresIn: "1h",
		});
		const refreshToken = jwt.sign(payload, "refresh-token-secret", {
			expiresIn: "1y",
		});

		return { accessToken, refreshToken };
	};
	// Generate new tokens
	const { refreshToken, accessToken } = generateToken({
		_id: userData._id,
	});

	// Update refresh token
	const updateRefreshToken = async (userId, refreshToken) => {
		return await RefreshModel.updateOne(
			{ userId: userId },
			{ token: refreshToken }
		);
	};
	try {
		await updateRefreshToken(userData._id, refreshToken);
	} catch (err) {
		return res.status(500).json({ message: "Internal error" });
	}
	// put in cookie
	res.cookie("refreshToken", refreshToken, {
		maxAge: 1000 * 60 * 60 * 24 * 30,
		httpOnly: true,
	});

	res.cookie("accessToken", accessToken, {
		maxAge: 1000 * 60 * 60 * 24 * 30,
		httpOnly: true,
	});
	// response
	res.json({ user });
};
