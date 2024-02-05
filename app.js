const express = require("express");
const app = express();
const mongoose=require("mongoose");
const AuthRoute = require("./Auth/auth.route");

mongoose.connect("mongodb://localhost:27017/sample");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/", AuthRoute);

app.listen(8000, () => {
	console.log("Server is running on port 8000");
});
