import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import passport from "passport";
import { responseHandler } from "./utils/response/responseHandler.js";

//  All Routes
// ------------- USER Routes--------------------
import userRouter from "./routes/USERAPP/user.routes.js";
import commonRoute from "./routes/common.js";

// Strategy Passport
import { userappPassportStrategy } from "../src/config/userappPassportStrategy.js";
import { googlePassportStrategy } from "../src/config/googlePassportStrategy.js";
import { facebookPassportStrategy } from "../src/config/facebookPassportStrategy.js";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credential: true,
  })
);
app.use(responseHandler);

app.use(passport.initialize());
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

userappPassportStrategy(passport);
googlePassportStrategy(passport);
facebookPassportStrategy(passport);

//  User Routes
app.use("/api/v1/userapp/auth", userRouter);
app.use(commonRoute);

export { app };
