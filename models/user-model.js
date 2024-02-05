const { Schema, Types, model } = require("mongoose");

const userSchema = new Schema(
	{
		phone: {
			type: String,
			required: true,
		},
	},
	{
		timestamps: true,
		collection: "users",
	}
);

module.exports = model("users", userSchema);
